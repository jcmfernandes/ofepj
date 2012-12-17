// Group 9

package app.ttp;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SignedObject;
import java.util.Set;

import protocols.Message;
import protocols.exchange.EOOm;
import protocols.exchange.EORm;
import protocols.ttp.ABt;
import protocols.ttp.Et;
import util.CryptoWrapper;
import util.KeyIDPair;
import app.Configurations;

public class ClientThread implements Runnable {
	
	private static int n = 0;

	private int request;
	private Socket socket;
	private Set<DBEntry> db;


	public ClientThread(Socket socket, Set<DBEntry> db) {
		this.socket = socket;
		this.db = db;
		synchronized (this.getClass()) {
			this.request = n++;
		}
	}

	@Override
	public void run() {
		System.err.println("[" + request + "] " + "New connection from " + socket.getRemoteSocketAddress());
		
		try {
			BufferedInputStream bis = new BufferedInputStream(socket.getInputStream());
			BufferedOutputStream bos = new BufferedOutputStream(socket.getOutputStream());
			ObjectInputStream ois = new ObjectInputStream(bis);
			ObjectOutputStream oos = new ObjectOutputStream(bos);
			oos.flush();
			
			Object obj = null;
			System.err.println("[" + request + "] " + "Waiting for an object.");
			obj = ois.readObject();
			System.err.println("[" + request + "] " + "Received object of type " + obj.getClass().getCanonicalName());

			if (obj instanceof SignedObject && ((SignedObject) obj).getObject() instanceof Message) {
				SignedObject sobj = (SignedObject) obj;
				Message msg = (Message) sobj.getObject();

				if (msg instanceof EORm) { // resolution protocol
					System.err.println("[" + request + "] " + "Resolving.");
					EORm eorm = (EORm) msg;
					EOOm eoom = (EOOm) eorm.getEOOm().getObject();
					PublicKey bPublicKey = CryptoWrapper.loadPublicKey(eoom.getB());
					KeyIDPair keyIDPair = (KeyIDPair) CryptoWrapper.asymmetricUncipher(eoom.getKA(),
							Configurations.USER_KEYPAIR.getPrivate());
					PublicKey aPublicKey = CryptoWrapper.loadPublicKey(keyIDPair.getId());

					boolean signStatus = CryptoWrapper.verifySignature(eorm.getEOOm(), aPublicKey) &&
					CryptoWrapper.verifySignature(sobj, bPublicKey); 
					if (signStatus) {
						DBEntry dbEntry = new DBEntry(DBEntry.ABORTED, keyIDPair.getId(), eoom.getB(),
								keyIDPair.getKey(), eoom.getDigest());
						
						synchronized (db) {
							if (!db.contains(dbEntry)) {
								// send Et
								System.err.println("[" + request + "] " + "Sending Et");
								Et et = new Et(keyIDPair.getId(), eoom.getB(), keyIDPair.getKey(), eoom.getDigest());
								dbEntry = new DBEntry(DBEntry.RESOLVED, keyIDPair.getId(), eoom.getB(),
										keyIDPair.getKey(), eoom.getDigest());
								db.add(dbEntry);
								oos.writeObject(CryptoWrapper.sign(et, Configurations.USER_KEYPAIR.getPrivate()));
							} else {
								// send ABt
								System.err.println("[" + request + "] " + "Sending ABt");
								ABt abt = new ABt(keyIDPair.getId(), eoom.getB(), eoom.getDigest(),
										keyIDPair, Configurations.USER_KEYPAIR.getPublic());
								oos.writeObject(CryptoWrapper.sign(abt, Configurations.USER_KEYPAIR.getPrivate()));
							}
						}
					}	
				} else if (msg instanceof ABt) { // abort protocol
					System.err.println("[" + request + "] " + "Aborting.");
					ABt abt = (ABt) msg;
					KeyIDPair keyIDPair = (KeyIDPair) CryptoWrapper.asymmetricUncipher(abt.getKA(),
							Configurations.USER_KEYPAIR.getPrivate());
					PublicKey aPublicKey = CryptoWrapper.loadPublicKey(keyIDPair.getId());

					if (CryptoWrapper.verifySignature(sobj, aPublicKey)) {
						DBEntry dbEntry = new DBEntry(DBEntry.RESOLVED, keyIDPair.getId(), abt.getB(),
								keyIDPair.getKey(), abt.getDigest());

						synchronized (db) {
							if (!db.contains(dbEntry)) {
								// send ABt
								System.err.println("[" + request + "] " + "Sending ABt");
								ABt abtReply = new ABt(keyIDPair.getId(), abt.getB(), abt.getDigest(),
										keyIDPair, Configurations.USER_KEYPAIR.getPublic());
								dbEntry = new DBEntry(DBEntry.ABORTED, keyIDPair.getId(), abt.getB(),
										keyIDPair.getKey(), abt.getDigest());
								db.add(dbEntry);
								oos.writeObject(CryptoWrapper.sign(abtReply, Configurations.USER_KEYPAIR.getPrivate()));
							} else {
								// send Et
								System.err.println("[" + request + "] " + "Sending Et");
								Et et = new Et(keyIDPair.getId(), abt.getB(), keyIDPair.getKey(), abt.getDigest());
								oos.writeObject(CryptoWrapper.sign(et, Configurations.USER_KEYPAIR.getPrivate()));
							}
						}
					}
				} else {
					System.out.println("[" + request + "] " + "Received an unknown message.");
				}

				oos.flush();
			} else {
				// wrong message
				System.err.println("[" + request + "] " + "Wrong type of message received. Closing connection.");
			}

			ois.close();
			oos.close();
			bis.close();
			bos.close();
			socket.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}

}
