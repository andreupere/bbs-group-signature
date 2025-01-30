package cat.uib.secom.crypto.sig.bbs.core.impl.keys;

import it.unisa.dia.gas.jpbc.Element;
import cat.uib.secom.crypto.sig.bbs.core.keys.BBSGroupManagerPrivateElements;
import cat.uib.secom.crypto.sig.bbs.core.parameters.BBSGroupKey;
import cat.uib.secom.utils.pairing.ElementWrapper;


/**
 * @author Andreu Pere
 * 
 * It stores the private elements for the group manager, it is, the gamma parameter (see BBS paper)
 * 
 * @see BBSGroupKey
 * */
public class BBSGroupManagerPrivateElementsImpl extends BBSGroupKey 
												implements BBSGroupManagerPrivateElements {

	private ElementWrapper gamma;
	
	
	public BBSGroupManagerPrivateElementsImpl(ElementWrapper gamma) {
		super(true);
		this.gamma = gamma;
	}
	
	public ElementWrapper getGamma() {
		return gamma;
	}
	
	public BBSGroupManagerPrivateElementsImpl getBBSGroupManagerPrivateElements() {
		return this;
	}

	public String toString() {
		return "(gamma)";
	}
	
	public String readable() {
		String s = "\n\n" +
				"\n gamma: " + this.getGamma() +
				"\n";
		return s;
	}
}
