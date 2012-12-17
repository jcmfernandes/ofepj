// Group 9

package protocols.exchange;

import java.io.Serializable;
import java.security.SignedObject;

import protocols.Message;

public class EORm extends Message implements Serializable {

	private static final long serialVersionUID = -3261648721093574744L;
	
	protected SignedObject eoom;
	

	public EORm(SignedObject eoom) {
		this.eoom = eoom;
	}

	public SignedObject getEOOm() {
		return eoom;
	}
	
}
