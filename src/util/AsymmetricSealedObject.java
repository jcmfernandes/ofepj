// Group 9

package util;

import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

public class AsymmetricSealedObject implements Serializable {

	private static final long serialVersionUID = -6683450871292592305L;

	protected SealedObject sobj;
	protected byte[] symmetricKey;


	public AsymmetricSealedObject(Serializable obj, Cipher cipher) {
		try {
			SecretKey skey = CryptoWrapper.generateSecretKey();
			symmetricKey = cipher.wrap(skey);
			sobj = CryptoWrapper.symmetricCipher(obj, skey);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}
	}
	
	public Object getObject(PrivateKey key) throws InvalidKeyException, NoSuchAlgorithmException, IOException, ClassNotFoundException {
		Cipher cipher = CryptoWrapper.getAsymmetricCipherToUnwrap(key);
		SecretKey skey = (SecretKey) CryptoWrapper.unwrapKey(symmetricKey, cipher, Cipher.SECRET_KEY);
		return CryptoWrapper.symmetricUncipher(sobj, skey);
	}
	
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof AsymmetricSealedObject) {
			AsymmetricSealedObject asobj = (AsymmetricSealedObject) obj;
			try {
				return Arrays.equals(Misc.convertObjectToByteArray(asobj), Misc.convertObjectToByteArray(this));
			} catch (IOException e) {
				return false;
			}
		}
		return false;
	}
	
}
