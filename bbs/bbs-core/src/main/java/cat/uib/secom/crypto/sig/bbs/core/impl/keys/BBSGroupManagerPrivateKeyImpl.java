package cat.uib.secom.crypto.sig.bbs.core.impl.keys;

import it.unisa.dia.gas.jpbc.Element;
import cat.uib.secom.crypto.sig.bbs.core.parameters.BBSGroupKey;
import cat.uib.secom.utils.pairing.ElementWrapper;

/**
 * @author Andreu Pere
 * 
 * It stores the group manager private key (see BBS paper), it is, delta1 and delta2
 * 
 * @see BBSGroupKey
 * */
public class BBSGroupManagerPrivateKeyImpl extends BBSGroupKey 
									   implements cat.uib.secom.crypto.sig.bbs.core.keys.BBSGroupManagerPrivateKey {
	
	private ElementWrapper delta1;
	private ElementWrapper delta2;

	public BBSGroupManagerPrivateKeyImpl(ElementWrapper delta1, ElementWrapper delta2) {
		super(true);
		this.delta1 = delta1;
		this.delta2 = delta2;
	}
	
	public BBSGroupManagerPrivateKeyImpl getBBSGroupManagerPrivateKey() {
		return this;
	}

	public ElementWrapper getDelta1() {
		return delta1;
	}

	public ElementWrapper getDelta2() {
		return delta2;
	}
	
	
	public String toString() {
		return "(delta1, delta2)";
	}
	
	public String readable() {
		String s = "\n\n" +
				"\n delta1: " + this.getDelta1() +
				"\n delta2: " + this.getDelta2() +
				"\n";
		return s;
	}
	

}
