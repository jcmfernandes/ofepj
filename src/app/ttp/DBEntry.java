// Group 9

package app.ttp;

import java.util.Arrays;

import javax.crypto.SecretKey;

public class DBEntry {

	public static final int RESOLVED = 0;
	public static final int ABORTED = 1;
	
	protected int status;
	protected String X, Y; // identities
	protected SecretKey W; // secret symmetric key
	protected byte[] Z; // digest

	
	public DBEntry(int status, String X, String Y, SecretKey W, byte[] Z) {
		this.status = status;
		this.X = X;
		this.Y = Y;
		this.W = W;
		this.Z = Z;
	}
	
	public int getStatus() {
		return status;
	}

	public String getX() {
		return X;
	}

	public String getY() {
		return Y;
	}

	public SecretKey getW() {
		return W;
	}

	public byte[] getZ() {
		return Z;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof DBEntry) {
			DBEntry dbe = (DBEntry) obj;
			if (status == dbe.status && X.equals(dbe.X) && Y.equals(dbe.Y) &&
					W.equals(dbe.W) && Arrays.equals(Z, dbe.Z)) {
				return true;
			}
		}
		return false;
	}
	
	@Override
	public int hashCode() {
		return 0;
	}
	
	@Override
	public String toString() {
		String s = null;
		if (status == RESOLVED)
			s = "resolved";
		else if (status == ABORTED)
			s = "aborted";
		
		return "Status: " + s + " / X = " + X + " / Y = " + Y;
	}
	
}
