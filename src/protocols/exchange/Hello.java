// Group 9

package protocols.exchange;

import java.io.Serializable;

import protocols.Message;

public class Hello extends Message implements Serializable {

	private static final long serialVersionUID = -3911744605581961959L;
	
	private String identity;
	
	
	public Hello(String identity) {
		this.identity = identity;
	}
	
	public String getIdentity() {
		return identity;
	}

}
