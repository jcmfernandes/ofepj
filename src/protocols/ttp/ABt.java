// Group 9

package protocols.ttp;

import java.io.Serializable;
import java.security.PublicKey;

import protocols.Message;
import util.AsymmetricSealedObject;
import util.CryptoWrapper;
import util.KeyIDPair;

public class ABt extends Message implements Serializable {

	private static final long serialVersionUID = -2298984003414680811L;
	
	protected String A, B;
	protected byte[] digest;
	protected AsymmetricSealedObject KA;
	
	
	public ABt(String A, String B, byte[] digest, KeyIDPair KA, PublicKey tpp_pubkey) {
		this.A = A;
		this.B = B;
		this.digest = digest;
		this.KA = CryptoWrapper.assymmetricCipher(KA, tpp_pubkey);
	}

	public String getA() {
		return A;
	}

	public String getB() {
		return B;
	}

	public byte[] getDigest() {
		return digest;
	}

	public AsymmetricSealedObject getKA() {
		return KA;
	}
	
}
