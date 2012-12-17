// Group 9

package app.client;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SignedObject;
import java.util.Arrays;

import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

import protocols.Message;
import protocols.exchange.EOOm;
import protocols.exchange.EORk;
import protocols.exchange.EORm;
import protocols.exchange.Hello;
import protocols.exchange.K;
import protocols.exchange.Text;
import protocols.ttp.ABt;
import protocols.ttp.Et;
import util.CryptoWrapper;
import util.KeyIDPair;
import util.Misc;
import app.Configurations;

public class Main {
	
	private static class TimeoutThread extends Thread {

		private volatile boolean timeout;
		private long millis;
		
		public TimeoutThread(long millis) {
			this.millis = millis;
			this.timeout = false;
		}
		
		public boolean getTimeout() {
			return timeout;
		}
		
		@Override
		public void run() {
			try {
				sleep(millis);
			} catch (InterruptedException e) {	}
			timeout = true;
		}
		
	}
	
	private static void errorA(final int state, final SignedObject eorm, final SignedObject abt) {
		Message msg = null;
		switch (state) {
		case 1:
			msg = abort(abt);
			if (msg instanceof ABt) {
				System.out.println("Session aborted.");
			} else if (msg instanceof Et) {
				System.out.println("Session was already resolved by the other party. "
						+ "Unable to abort this session.");
			} else {
				System.out.println("An error occured while trying to deal with an error. "
						+ "Life ain't fair!");
			}
			break;
		case 2:
			msg = resolve(eorm);
			if (msg instanceof ABt) {
				System.out.println("Session was already aborted by the other party. "
						+ "Unable to resolve this session.");
			} else if (msg instanceof Et) {
				System.out.println("Session resolved.");
			} else {
				System.out.println("An error occured while trying to deal with an error. "
						+ "Life ain't fair!");
			}
			break;	
		}
		System.out.println("Quitting.");
		System.exit(0);
	}

	private static void exchangeA(Socket socket) {
		// exchange protocol -- A side

		/*
		 * Step 1: Send Hello, Mk, EOOm
		 * Step 2: Get EORm, send K
		 * Step 3: Get EORk
		 */

		int state = 0;
		
		InputStreamReader isr = new InputStreamReader(System.in);
		BufferedReader br = new BufferedReader(isr);
		
		SecretKey secretKey = CryptoWrapper.generateSecretKey();
		Text text = new Text(Configurations.MESSAGE);
		SealedObject sealedObject = CryptoWrapper.symmetricCipher(text, secretKey);
		byte[] digest = null;
		try {
			digest = Misc.convertObjectToByteArray(sealedObject);
		} catch (IOException e1) {
			e1.printStackTrace();
			System.exit(-1);
		}
		KeyIDPair keyIDPair = new KeyIDPair(secretKey, Configurations.A_IDENTITY);
		EOOm eoom = new EOOm(Configurations.A_IDENTITY, Configurations.B_IDENTITY,
				Configurations.TTP_IDENTITY, digest, keyIDPair,
				CryptoWrapper.loadPublicKey(Configurations.TTP_IDENTITY));
		SignedObject signedObject = CryptoWrapper.sign(eoom, Configurations.USER_KEYPAIR.getPrivate());

		// to abort or resolve the following are needed
		SignedObject signedEORm = null;
		SignedObject signedABt = CryptoWrapper.sign(new ABt(Configurations.A_IDENTITY,
				Configurations.B_IDENTITY, digest, keyIDPair,
				CryptoWrapper.loadPublicKey(Configurations.TTP_IDENTITY)),
				Configurations.USER_KEYPAIR.getPrivate());
		
		try {
			BufferedInputStream bis = new BufferedInputStream(socket.getInputStream());
			BufferedOutputStream bos = new BufferedOutputStream(socket.getOutputStream());
			ObjectOutputStream oos = new ObjectOutputStream(bos);
			oos.flush();
			ObjectInputStream ois = new ObjectInputStream(bis);

			// state 0: send Hello, send MK, EOOm
			System.err.println("Starting step 0.");
			
			Hello hello = new Hello(Configurations.A_IDENTITY);
			oos.writeObject(hello);
			oos.writeObject(sealedObject);
			oos.writeObject(signedObject);
			oos.flush();
			state = 1;
			
			System.err.println("Ended step 0.");
			// end of step 1
			
			if (Configurations.DEBUG) {
				System.out.println("To abort now type 'a'. To continue type anything else.");
				String s = br.readLine();
				if (s.equals("a")) {
					abort(signedABt);
					System.exit(0);
				}
			}

			PublicKey bPublicKey = CryptoWrapper.loadPublicKey(Configurations.B_IDENTITY);
			K k = null;

			boolean running = true;
			while (running) {
				Object obj = null;
				System.err.println("Waiting for an object.");
				TimeoutThread timeoutThread = new TimeoutThread(Configurations.TIMEOUT);
				timeoutThread.start();
				while (bis.available() == 0 && !timeoutThread.getTimeout());
				if (bis.available() > 0) {
					obj = ois.readObject();
					System.err.println("Received object of type " + obj.getClass().getCanonicalName());
				} else {
					System.err.println("Connection timed-out.");
					socket.close();
					errorA(state, signedEORm, signedABt);
				}

				switch (state) {
				case 1: // get EORm, send K
					System.err.println("Starting step 1 - want a SignedObject.");
					if (obj instanceof SignedObject) {
						signedObject = (SignedObject) obj;
						if (signedObject.getObject() instanceof EORm) {
							EORm eorm = (EORm) signedObject.getObject();
							
							System.err.println("EOOm matches? " + eoom.equals(eorm.getEOOm().getObject()));
							System.err.println("Signature matches? " + CryptoWrapper.verifySignature(signedObject, bPublicKey));
							
							boolean msgOk = CryptoWrapper.verifySignature(signedObject, bPublicKey) &&
							eoom.equals(eorm.getEOOm().getObject());
							
							if (msgOk) {
								System.err.println("EORm validation succeeded!");
								
								k = new K(secretKey, bPublicKey);
								signedEORm = signedObject; // so that we are able to resolve
								
								state = 2;
								
								if (Configurations.DEBUG) {
									System.out.println("To resolve now type 'r'. " +
											"To send an invalid K press 'k'. " +
											"To send a bogus message press 'b'. " +
											"To continue type anything else.");
									String s = br.readLine();
									if (s.equals("r")) {
										resolve(signedEORm);
										System.exit(0);
									}
									if (s.equals("k")) {
										k = new K(CryptoWrapper.generateSecretKey(), bPublicKey);
									}
									if (s.equals("b")) {
										oos.writeObject(new String("Olá B!"));
									}
								}
								
								oos.writeObject(k);
							} else {
								System.err.println("EORm validation failed.");
								errorA(state, signedEORm, signedABt);
							}
						} else {
							errorA(state, signedEORm, signedABt);
						}
						System.err.println("Ended step 1.");
					} else {
						errorA(state, signedEORm, signedABt);
					}
					break;
				case 2: // get EORk
					System.err.println("Starting step 2 - want a SignedObject.");
					if (obj instanceof SignedObject) {						
						signedObject = (SignedObject) obj;
						EORk eork = (EORk) signedObject.getObject();
						boolean msgOk = CryptoWrapper.verifySignature(signedObject, bPublicKey) &&
							(signedObject.getObject() instanceof EORk) &&
							eork.getA().equals(Configurations.A_IDENTITY) &&
							eork.getK().equals(k.getK()) &&
							Arrays.equals(eork.getDigest(), digest);
						
						if (msgOk) {
							// everything is fine! we may terminate
							System.out.println("Urray! Mission accomplished.");

							running = false;
						} else {
							System.err.println("EORk validation failed.");
							errorA(state, signedEORm, signedABt);
						}
					}
					System.err.println("Ended step 3.");
					break;
				}

				oos.flush();
			}

			ois.close();
			oos.close();
			bis.close();
			bos.close();
			socket.close();
		} catch (Exception e) {
			e.printStackTrace();
			errorA(state, signedEORm, signedABt);
		}
	}
	
	private static void errorB(final int state, final SignedObject eorm, final SealedObject Mk) {
		Message msg = null;
		switch (state) {
		case 3:
			msg = resolve(eorm);
			if (msg instanceof ABt) {
				System.out.println("Session was already aborted by the other party. "
						+ "Unable to resolve this session.");
			} else if (msg instanceof Et) {
				SecretKey secretKey = ((Et) msg).getK();
				try {
					Text text = (Text) CryptoWrapper.symmetricUncipher(Mk, secretKey);
					System.out.println("Session resolved. The secret message is: " + text.getText());
				} catch (Exception e) {
					System.err.println("The TTP sent us a wrong K!!! WHAT THE HELL?");
				}
			} else {
				System.out.println("An error occured while trying to deal with an error. "
						+ "Life ain't fair!");
			}
			break;	
		}
		System.out.println("Quitting.");
		System.exit(0);
	}

	private static void exchangeB(Socket socket) {
		// exchange protocol -- B side

		/*
		 * Step 1: Get Hello
		 * Step 2: Get Mk
		 * Step 3: Get EOOm, send EORm
		 * Step 4: Get K, send EORk
		 */

		int state = 0;
		
		InputStreamReader isr = new InputStreamReader(System.in);
		BufferedReader br = new BufferedReader(isr);
		
		// needed to resolve the protocol
		SignedObject signedEORm = null;
		SealedObject Mk = null;

		try {
			BufferedInputStream bis = new BufferedInputStream(socket.getInputStream());
			BufferedOutputStream bos = new BufferedOutputStream(socket.getOutputStream());
			ObjectOutputStream oos = new ObjectOutputStream(bos);
			oos.flush();
			ObjectInputStream ois = new ObjectInputStream(bis);

			String uid = null;
			byte[] digest = null;

			boolean running = true;
			while (running) {
				Object obj = null;

				System.err.println("Waiting for an object.");
				TimeoutThread timeoutThread = new TimeoutThread(Configurations.TIMEOUT);
				timeoutThread.start();
				while (bis.available() == 0 && !timeoutThread.getTimeout());
				if (bis.available() > 0) {
					obj = ois.readObject();
					System.err.println("Received object of type " + obj.getClass().getCanonicalName());
				} else {
					System.err.println("Connection timed-out.");
					socket.close();
					errorB(state, signedEORm, Mk);
				}

				switch (state) {
				case 0:	 // get Hello
					System.err.println("Starting step 0 - want a Hello");
					if (obj instanceof Hello) {
						Hello hello = (Hello) obj;
						Configurations.A_IDENTITY = hello.getIdentity();
						System.err.println("Received a Hello from the user with identity "
								+ Configurations.A_IDENTITY);
						state = 1;
					} else {
						errorB(state, signedEORm, Mk);
					}
					System.err.println("Ended step 0.");
					break;
				case 1: // get Mk
					System.err.println("Starting step 1 - want a SealedObject.");
					if (obj instanceof SealedObject) {
						Mk = (SealedObject) obj;
						state = 2;
					} else {
						errorB(state, signedEORm, Mk);
					}
					System.err.println("Ended step 1.");
					break;
				case 2: // get EOOm, send EORm
					System.err.println("Starting step 2 - want a SignedObject.");
					if (obj instanceof SignedObject) {
						SignedObject signedEOOm = (SignedObject) obj;
						EOOm eoom = (EOOm) signedEOOm.getObject();
						
						boolean msgOk = CryptoWrapper.verifySignature(signedEOOm,
								CryptoWrapper.loadPublicKey(eoom.getA())) &&
								eoom.getB().equals(Configurations.B_IDENTITY) &&
								eoom.getT().equals(Configurations.TTP_IDENTITY) &&
								Arrays.equals(eoom.getDigest(), Misc.convertObjectToByteArray(Mk));

						if (msgOk) {
							System.err.println("EOOm verification succeeded!");
							uid = eoom.getA();
							digest = eoom.getDigest();

							EORm eorm = new EORm(signedEOOm);
							signedEORm = CryptoWrapper.sign(eorm, Configurations.USER_KEYPAIR.getPrivate());
							
							state = 3;
							
							if (Configurations.DEBUG) {
								System.out.println("To resolve now type 'r'. " +
										"To sign the EORm with a bogus key press 'k'. " +
										"To send a bogus message press 'm'. " +
										"To continue type anything else.");
								String s = br.readLine();
								if (s.equals("r")) {
									resolve(signedEORm);
									System.exit(0);
								}
								if (s.equals("k")) {
									KeyPair bogusKeyPair = CryptoWrapper.generateKeyPair();
									oos.writeObject(CryptoWrapper.sign(eorm, bogusKeyPair.getPrivate()));
								}
								if (s.equals("m")) {
									oos.writeObject(new String("Olá A!"));
								}
							}
							
							oos.writeObject(signedEORm);
						} else {
							System.err.println("EOOm verification failed");
							errorB(state, signedEORm, Mk);
						}
					} else {
						errorB(state, signedEORm, Mk);
					}
					System.err.println("Ended step 2.");
					break;
				case 3: // get K, send EORk
					System.err.println("Starting step 3 - want a K");
					if (obj instanceof K) {
						K k = (K) obj;
						SecretKey secretKey = null;
						Text text = null;
						try {
							secretKey = (SecretKey) CryptoWrapper.asymmetricUncipher
								(k.getK(), Configurations.USER_KEYPAIR.getPrivate());
							text = (Text) CryptoWrapper.symmetricUncipher(Mk, secretKey);
						} catch (Exception e) {
							System.err.println("Unable to uncipher data.");
							errorB(state, signedEORm, Mk);
						}
						// everything is fine! we may terminate
						System.out.println("Urray! The exchanged message is: " + text.getText());
						EORk eork = new EORk(uid, digest, k.getK());
						
						if (Configurations.DEBUG) {
							System.out.println("To resolve now type 'r'. " +
									"To fake the EORk press 'k'. " +
									"To continue type anything else.");
							String s = br.readLine();
							if (s.equals("r")) {
								resolve(signedEORm);
								System.exit(0);
							}
							if (s.equals("k")) {
								String bogusString = "I was frozen today!";
								eork = new EORk(bogusString, bogusString.getBytes(), k.getK());
							}
						}
						
						oos.writeObject(CryptoWrapper.sign(eork, Configurations.USER_KEYPAIR.getPrivate()));

						running = false;
					} else {
						errorB(state, signedEORm, Mk);
					}
					System.err.println("Ended step 3.");
					break;
				}

				oos.flush();
			}
			
			ois.close();
			oos.close();
			bis.close();
			bos.close();
			socket.close();
		} catch (Exception e) {
			e.printStackTrace();
			errorB(state, signedEORm, Mk);
		}
	}
	
	private static Message resolve(SignedObject eorm) {
		Message message = null;
		
		try {
			String[] host = Configurations.TTP_ADDRESS.split(":");
			Socket socket = new Socket(host[0], Integer.parseInt(host[1]));
			System.err.println("Connected to the trusted third-party. Starting the resolution process.");
			
			BufferedInputStream bis = new BufferedInputStream(socket.getInputStream());
			BufferedOutputStream bos = new BufferedOutputStream(socket.getOutputStream());
			ObjectOutputStream oos = new ObjectOutputStream(bos);
			oos.flush();
			ObjectInputStream ois = new ObjectInputStream(bis);
			
			oos.writeObject(eorm);
			oos.flush();
			
			EOOm eoom = (EOOm) ((EORm) eorm.getObject()).getEOOm().getObject();
			
			Object obj = ois.readObject();
			
			if (obj instanceof SignedObject) {
				SignedObject signedObject = (SignedObject) obj;
				boolean signatureOk = CryptoWrapper.verifySignature(signedObject,
						CryptoWrapper.loadPublicKey(Configurations.TTP_IDENTITY));
				
				if (signatureOk && signedObject.getObject() instanceof ABt) {
					ABt abt = (ABt) signedObject.getObject();
					
					boolean msgOk = abt.getA().equals(Configurations.A_IDENTITY) &&
						abt.getB().equals(Configurations.B_IDENTITY) &&
						Arrays.equals(abt.getDigest(), eoom.getDigest());
					
					if (msgOk) {
						message = abt;
					}
				} else if (signatureOk && signedObject.getObject() instanceof Et) {
					Et et = (Et) signedObject.getObject();
					
					boolean msgOk = et.getA().equals(Configurations.A_IDENTITY) &&
						et.getB().equals(Configurations.B_IDENTITY) &&
						Arrays.equals(eoom.getDigest(), et.getDigest());
					
					if (msgOk) {
						message = et;
					}
				}
			}
			
			ois.close();
			oos.close();
			bis.close();
			bos.close();
			socket.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return message;
	}
	
	private static Message abort(SignedObject abt) {
		Message message = null;
		
		try {
			String[] host = Configurations.TTP_ADDRESS.split(":");
			Socket socket = new Socket(host[0], Integer.parseInt(host[1]));
			System.err.println("Connected to the trusted third-party. Starting the abort process.");
			
			BufferedInputStream bis = new BufferedInputStream(socket.getInputStream());
			BufferedOutputStream bos = new BufferedOutputStream(socket.getOutputStream());
			ObjectOutputStream oos = new ObjectOutputStream(bos);
			oos.flush();
			ObjectInputStream ois = new ObjectInputStream(bis);
			
			oos.writeObject(abt);
			oos.flush();
			
			Object obj = ois.readObject();
			if (obj instanceof SignedObject) {
				SignedObject signedObject = (SignedObject) obj;
				boolean signatureOk = CryptoWrapper.verifySignature(signedObject,
						CryptoWrapper.loadPublicKey(Configurations.TTP_IDENTITY));
				
				if (signatureOk && signedObject.getObject() instanceof ABt) {
					ABt rabt = (ABt) signedObject.getObject();

					boolean msgOk = rabt.getA().equals(Configurations.A_IDENTITY) &&
						rabt.getB().equals(Configurations.B_IDENTITY) &&
						Arrays.equals(rabt.getDigest(), ((ABt) abt.getObject()).getDigest());
					
					if (msgOk) {
						message = rabt;
					}
				} else if (signatureOk && signedObject.getObject() instanceof Et) {
					Et et = (Et) signedObject.getObject();
					
					boolean msgOk = et.getA().equals(Configurations.A_IDENTITY) &&
						et.getB().equals(Configurations.B_IDENTITY) &&
						Arrays.equals(et.getDigest(), ((ABt) abt.getObject()).getDigest());
					
					if (msgOk) {
						message = et;
					}
				}
			}
			
			ois.close();
			oos.close();
			bis.close();
			bos.close();
			socket.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return message;
	}

	public static void execute() {
		try {
			if (Configurations.PRINCIPAL.equals(Configurations.Principal.A)) {
				String[] host = Configurations.B_ADDRESS.split(":");
				Socket socket = new Socket(host[0], Integer.parseInt(host[1]));
				System.err.println("Starting in mode A. Connected to " + host[0] + " on port " + host[1]);
				
				exchangeA(socket);
			} else if (Configurations.PRINCIPAL.equals(Configurations.Principal.B)) {
				ServerSocket serverSocket = new ServerSocket(Integer.parseInt(Configurations.B_PORT));
				System.err.println("Starting in mode B. Listening on port " + Configurations.B_PORT);
				Socket socket = serverSocket.accept();
				System.err.println("Someone connected.");
				
				exchangeB(socket);
			}
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}
	}

}
