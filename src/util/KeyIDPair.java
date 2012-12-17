// Group 9

package util;

import java.io.Serializable;

import javax.crypto.SecretKey;

public class KeyIDPair implements Serializable {

	private static final long serialVersionUID = 8888859936956822654L;
	
	protected SecretKey key;
	protected String id;
	
	
	public KeyIDPair(SecretKey key, String id) {
		this.key = key;
		this.id = id;
	}
	
	public SecretKey getKey() {
		return key;
	}
	
	public String getId() {
		return id;
	}
	
}
