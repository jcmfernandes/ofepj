// Group 9

package protocols.ttp;

import java.io.Serializable;

import javax.crypto.SecretKey;

import protocols.Message;

public class Et extends Message implements Serializable {
	
	private static final long serialVersionUID = -598953679748149890L;
	
	protected String A, B;
	protected SecretKey K;
	protected byte[] digest;
	
	
	public Et(String A, String B, SecretKey K, byte[] digest) {
		this.A = A;
		this.B = B;
		this.K = K;
		this.digest = digest;
	}
	
	public SecretKey getK() {
		return K;
	}
	
	public byte[] getDigest() {
		return digest;
	}
	
	public String getA() {
		return A;
	}
	
	public String getB() {
		return B;
	}

}
