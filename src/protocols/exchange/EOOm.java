// Group 9

package protocols.exchange;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.Arrays;

import protocols.Message;
import util.AsymmetricSealedObject;
import util.CryptoWrapper;
import util.KeyIDPair;

public class EOOm extends Message implements Serializable {

	private static final long serialVersionUID = 6347797402596304471L;

	protected String A, B, T;
	protected byte[] digest;
	protected AsymmetricSealedObject KA;


	public EOOm(String A, String B, String T, byte[] digest, KeyIDPair KA, PublicKey tpp_pubkey) {
		this.A = A;
		this.B = B;
		this.T = T;
		//digest = CryptoWrapper.digest(Misc.convertObjectToByteArray(Mk));
		this.digest = digest;
		this.KA = CryptoWrapper.assymmetricCipher(KA, tpp_pubkey);
	}

	public byte[] getDigest() {
		return digest;
	}

	public AsymmetricSealedObject getKA() {
		return KA;
	}
	
	public String getA() {
		return A;
	}

	public String getB() {
		return B;
	}

	public String getT() {
		return T;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof EOOm) {
			EOOm eoom = (EOOm) obj;
			boolean eq = A.equals(eoom.getA()) && B.equals(eoom.getB()) &&
					T.equals(eoom.getT()) && Arrays.equals(digest, eoom.getDigest()) &&
					KA.equals(eoom.getKA());
			return eq;
		}
		return false;
	}
	
	@Override
	public String toString() {
		return "A = " + A +" / B = " + B + " / T = " + T;
	}
	
}
