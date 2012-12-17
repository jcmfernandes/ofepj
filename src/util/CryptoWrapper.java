// Group 9

package util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignedObject;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

public abstract class CryptoWrapper {
	
	private final static String asymmetricAlgorithm = "RSA";
	private final static String symmetricAlgorithm = "AES";
	private final static String signingAlgorithm = "SHA1withRSA";
	private final static String digestAlgorithm = "SHA-256";
	
	private final static int symmetricKeySize = 128; // bits
	private final static int asymetricKeySize = 2048; // bits

	
	public static KeyPair generateKeyPair() {
		KeyPairGenerator keyGen = null;
		try {
			keyGen = KeyPairGenerator.getInstance(asymmetricAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.exit(-1);
		}
		keyGen.initialize(asymetricKeySize);
		return keyGen.generateKeyPair();
	}
	
	public static SecretKey generateSecretKey() {
		KeyGenerator keyGen = null;
		try {
			keyGen = KeyGenerator.getInstance(symmetricAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.exit(-1);
		}
		keyGen.init(symmetricKeySize);
		return keyGen.generateKey();
	}
	
	public static Cipher getSymmetricCipherToEncrypt(Key key) {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance(symmetricAlgorithm);
			cipher.init(Cipher.ENCRYPT_MODE, key);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}
		return cipher;
	}
	
	public static Cipher getAsymmetricCipherToWrap(Key key) {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance(asymmetricAlgorithm);
			cipher.init(Cipher.WRAP_MODE, key);	
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}
		return cipher;
	}
	
	public static Cipher getAsymmetricCipherToUnwrap(Key key) {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance(asymmetricAlgorithm);
			cipher.init(Cipher.UNWRAP_MODE, key);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}
		return cipher;
	}
	
	public static byte[] digest(byte[] data) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance(digestAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.exit(-1);
		}
		return md.digest(data);
	}
	
	public static SealedObject symmetricCipher(Serializable obj, SecretKey key) {
		SealedObject sobj = null;
		try {
			sobj = new SealedObject(obj, getSymmetricCipherToEncrypt(key));
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}
		return sobj;
	}
	
	public static Object symmetricUncipher(SealedObject obj, SecretKey key) throws InvalidKeyException, NoSuchAlgorithmException, IOException, ClassNotFoundException {
		return obj.getObject(key);
	}
	
	public static AsymmetricSealedObject assymmetricCipher(Serializable obj, PublicKey key) {
		return new AsymmetricSealedObject(obj, getAsymmetricCipherToWrap(key));
	}
	
	public static Object asymmetricUncipher(AsymmetricSealedObject obj, PrivateKey key) throws InvalidKeyException, NoSuchAlgorithmException, IOException, ClassNotFoundException {
		return obj.getObject(key);
	}
	
	public static SignedObject sign(Serializable obj, PrivateKey key) {
		SignedObject sobj = null;
		try {
			sobj = new SignedObject(obj, key, Signature.getInstance(signingAlgorithm));
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}
		return sobj;
	}
	
	public static boolean verifySignature(SignedObject obj, PublicKey key) {
		Boolean res = null;
		try {
			res = obj.verify(key, Signature.getInstance(signingAlgorithm));
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}
		return res;
	}
	
	public static byte[] wrapKey(Key key, Cipher cipher) {
		byte[] retKey = null;
		try {
			retKey = cipher.wrap(key);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}
		return retKey;
	}
	
	public static Key unwrapKey(byte[] key, Cipher cipher, int wrappedKeyType) throws InvalidKeyException {
		Key k = null;
		try {
			if (wrappedKeyType == Cipher.SECRET_KEY) {
				k = cipher.unwrap(key, symmetricAlgorithm, wrappedKeyType);
			} else {
				k = cipher.unwrap(key, asymmetricAlgorithm, wrappedKeyType);
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.exit(-1);
		}
		return k;
	}
	
	public static byte[] convertPublicKeyToByteArray(PublicKey key) {
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(key.getEncoded());
		return x509EncodedKeySpec.getEncoded();
	}
	
	public static PublicKey convertByteArrayToPublicKey(byte[] byteArr) throws InvalidKeySpecException {
		KeyFactory keyFactory = null;
		try {
			keyFactory = KeyFactory.getInstance(asymmetricAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.exit(-1);
		}
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(byteArr);
		return keyFactory.generatePublic(publicKeySpec);
	}
	
	public static byte[] convertPrivateKeyToByteArray(PrivateKey key) {
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(key.getEncoded());
		return pkcs8EncodedKeySpec.getEncoded();
	}
	
	public static PrivateKey convertByteArrayToPrivateKey(byte[] byteArr) throws InvalidKeySpecException {
		KeyFactory keyFactory = null;
		try {
			keyFactory = KeyFactory.getInstance(asymmetricAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.exit(-1);
		}
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(byteArr);
		return keyFactory.generatePrivate(privateKeySpec);
	}
	
	public static void generateKeyPair(String uid) {
		KeyPair keyPair = CryptoWrapper.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();

		FileOutputStream fos;
		try {
			File file = new File(uid + "-public.key");
			file.createNewFile();
			fos = new FileOutputStream(file);
			fos.write(CryptoWrapper.convertPublicKeyToByteArray(publicKey));
			fos.close();
			System.out.println("Saved the public key in file " + file.getName());
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}

		try {
			File file = new File(uid + "-private.key");
			if (file.createNewFile()) {
				fos = new FileOutputStream(file);
				fos.write(CryptoWrapper.convertPrivateKeyToByteArray(privateKey));
				fos.close();
			}
			System.out.println("Saved the private key in file " + file.getName());
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}
	}


	public static KeyPair loadKeyPair(String uid) {
		PublicKey publicKey = loadPublicKey(uid);
		PrivateKey privateKey = loadPrivateKey(uid);

		return new KeyPair(publicKey, privateKey);
	}

	public static PublicKey loadPublicKey(String uid) {
		File filePublicKey = new File(uid + "-public.key");
		FileInputStream fis = null;
		byte[] encodedPublicKey = null;
		PublicKey publicKey = null;
		try {
			fis = new FileInputStream(filePublicKey);
			encodedPublicKey = new byte[(int) filePublicKey.length()];
			fis.read(encodedPublicKey);
			fis.close();

			publicKey = CryptoWrapper.convertByteArrayToPublicKey(encodedPublicKey);
		} catch (FileNotFoundException e) {
			System.out.println("File " + filePublicKey.getName() + " is missing.");
			System.exit(-1);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}

		return publicKey;
	}

	public static PrivateKey loadPrivateKey(String uid) {
		File filePrivateKey = new File(uid + "-private.key");
		FileInputStream fis = null;
		byte[] encodedPrivateKey = null;
		PrivateKey privateKey = null;
		try {
			fis = new FileInputStream(filePrivateKey);
			encodedPrivateKey = new byte[(int) filePrivateKey.length()];
			fis.read(encodedPrivateKey);
			fis.close();
			privateKey = CryptoWrapper.convertByteArrayToPrivateKey(encodedPrivateKey);
		} catch (FileNotFoundException e) {
			System.out.println("File " + filePrivateKey.getName() + " is missing.");
			System.exit(-1);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}

		return privateKey;
	}
	
}
