// Group 9

package protocols.exchange;

import java.io.Serializable;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import protocols.Message;
import util.AsymmetricSealedObject;
import util.CryptoWrapper;

public class K extends Message implements Serializable {

	private static final long serialVersionUID = -5607922649059628813L;
	
	protected AsymmetricSealedObject K;
	
	
	public K(SecretKey key, PublicKey recipient_pubkey) {
		K = CryptoWrapper.assymmetricCipher(key, recipient_pubkey);
	}
	
	public AsymmetricSealedObject getK() {
		return K;
	}
	
}
