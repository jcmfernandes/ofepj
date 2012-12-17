// Group 9

package protocols.exchange;

import java.io.Serializable;

import protocols.Message;
import util.AsymmetricSealedObject;

public class EORk extends Message implements Serializable {

	private static final long serialVersionUID = -1156172230429560625L;
	
	protected String A;
	protected byte[] digest;
	protected AsymmetricSealedObject K;
	
	
	public EORk(String A, byte[] digest, AsymmetricSealedObject K) {
		this.A = A;
		this.digest = digest;
		this.K = K;
	}

	public String getA() {
		return A;
	}

	public byte[] getDigest() {
		return digest;
	}
	
	public AsymmetricSealedObject getK() {
		return K;
	}
	
}
