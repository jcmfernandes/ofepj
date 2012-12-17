// Group 9

package protocols.exchange;

import java.io.Serializable;

import protocols.Message;

public class Text extends Message implements Serializable {
	
	private static final long serialVersionUID = -2787317522446943192L;
	
	protected String text;
	
	
	public Text(String text) {
		this.text = text;
	}
	
	public String getText() {
		return text;
	}
}
