package cat.uib.secom.crypto.sig.bbs.core.impl.keys;


import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import cat.uib.secom.crypto.sig.bbs.core.parameters.BBSGroupKey;
import cat.uib.secom.utils.pairing.ElementWrapper;
import cat.uib.secom.utils.strings.StringUtils;


/**
 * @author Andreu Pere
 * 
 * It stores the user private key elements (see BBS paper), it is, a and x
 * */
public class BBSUserPrivateKeyImpl extends BBSGroupKey 
							   implements cat.uib.secom.crypto.sig.bbs.core.keys.BBSUserPrivateKey {
	
	private ElementWrapper a;
	private ElementWrapper x;

	/**
	 * Stores the user private key elements
	 * */
	public BBSUserPrivateKeyImpl(ElementWrapper a, ElementWrapper x) {
		super(true);
		this.a = a;
		this.x = x;
	}
	
	/**
	 * Rebuild the user private key from byte[] arrays elements
	 * */
	public BBSUserPrivateKeyImpl(byte[] a, byte[] x, Pairing pairing) {
		super(true);
		Element helperA = pairing.getG1().newOneElement();
		Element helperX = pairing.getZr().newOneElement();
		
		helperA.setFromBytes(a);
		this.a = new ElementWrapper( helperA.getImmutable() );
		
		helperX.setFromBytes(x);
		this.x = new ElementWrapper( helperX.getImmutable() );
		
	}
	
	public BBSUserPrivateKeyImpl(String a, String x, Pairing pairing) {
		this(StringUtils.hexStringToByteArray(a),
			 StringUtils.hexStringToByteArray(x),
			 pairing);
	}
	
	/**
	 * Return the whole object
	 * */
	public BBSUserPrivateKeyImpl getBBSUserPrivateKey() {
		return this;
	}

	public ElementWrapper getA() {
		return a;
	}

	public ElementWrapper getX() {
		return x;
	}
	
	public String toString() {
		return "(Ai, xi)";
	}
	
	public String readable() {
		String s = "\n\n" +
				"\n Ai: " + StringUtils.cut(this.getA()) + 
				"\n xi: " + StringUtils.cut(this.getX()) +
				"\n";
		return s;
	}
	
	
}
