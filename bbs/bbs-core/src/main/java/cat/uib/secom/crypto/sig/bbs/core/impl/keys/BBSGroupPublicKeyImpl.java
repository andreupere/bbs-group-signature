package cat.uib.secom.crypto.sig.bbs.core.impl.keys;


import java.math.BigInteger;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import cat.uib.secom.crypto.sig.bbs.core.parameters.BBSGroupKey;
import cat.uib.secom.utils.pairing.ElementWrapper;
import cat.uib.secom.utils.strings.StringUtils;

/**
 * @author Andreu Pere
 * 
 * It stores the group public key parameters (see BBS paper), it is, g1, g2, h, u, v, omega and pairing
 * */
public class BBSGroupPublicKeyImpl extends BBSGroupKey 
							   implements cat.uib.secom.crypto.sig.bbs.core.keys.BBSGroupPublicKey {
	
	private ElementWrapper g1;
	private ElementWrapper g2;
	private ElementWrapper h;
	private ElementWrapper u;
	private ElementWrapper v;
	private ElementWrapper omega;
	// Pairing function for access it on SIGN and VERIFY algorithms
	private Pairing pairing;
	private String r;

	
	/**
	 * Constructor to store the group public key in the server side. The elements provided are generated previously to the 
	 * method call, it is, in the key generation process
	 * 
	 * @see Element
	 * @see Pairing
	 * */
	public BBSGroupPublicKeyImpl(ElementWrapper g1, ElementWrapper g2, ElementWrapper h, ElementWrapper u, ElementWrapper v, ElementWrapper omega, Pairing pairing, String r) {
		super(false);
		this.g1 = g1;
		this.g2 = g2;
		this.h = h;
		this.u = u;
		this.v = v;
		this.omega = omega;
		this.pairing = pairing;
		this.r = r;
	}
	/**
	 * Constructor to build the group public key in the client side
	 * 
	 * @see Element
	 * @see Pairing
	 * */
	public BBSGroupPublicKeyImpl(byte[] g1, byte[] g2, byte[] h, byte[] u, byte[] v, byte[] omega, Pairing pairing) {
		super(false);
		Element helperG1 = pairing.getG1().newOneElement();
		Element helperG2 = pairing.getG2().newOneElement();
		
		helperG1.setFromBytes(g1);
		this.g1 = new ElementWrapper( helperG1.getImmutable() ); 
		
		helperG2.setFromBytes(g2);
		this.g2 = new ElementWrapper( helperG2.getImmutable() );
		
		helperG1.setFromBytes(h);
		this.h = new ElementWrapper( helperG1.getImmutable() );
		
		helperG1.setFromBytes(u);
		this.u = new ElementWrapper( helperG1.getImmutable() );
		
		helperG1.setFromBytes(v);
		this.v = new ElementWrapper( helperG1.getImmutable() );
		
		helperG2.setFromBytes(omega);
		this.omega = new ElementWrapper( helperG2.getImmutable() );
		
		this.pairing = pairing;
	}
	
	public BBSGroupPublicKeyImpl(String g1, String g2, String h, String u, String v, String omega, Pairing pairing) {
		this(StringUtils.hexStringToByteArray(g1),
			 StringUtils.hexStringToByteArray(g2),
			 StringUtils.hexStringToByteArray(h),
			 StringUtils.hexStringToByteArray(u),
			 StringUtils.hexStringToByteArray(v),
			 StringUtils.hexStringToByteArray(omega),
			 pairing);
	}
	
	/**
	 * Constructor to build it from BigInteger parameters
	 * 
	 * @see Element
	 * @see Pairing
	 * */
	public BBSGroupPublicKeyImpl(BigInteger g1, BigInteger g2, BigInteger h, BigInteger u, BigInteger v, BigInteger omega, Pairing pairing) {
		super(false);
		Element helperG1 = pairing.getG1().newOneElement();
		Element helperG2 = pairing.getG2().newOneElement();
		
		helperG1.setFromBytes(g1.toByteArray());
		this.g1 = new ElementWrapper( helperG1.getImmutable() ); 
		
		helperG2.setFromBytes(g2.toByteArray());
		this.g2 = new ElementWrapper( helperG2.getImmutable() );
		
		helperG1.setFromBytes(h.toByteArray());
		this.h = new ElementWrapper( helperG1.getImmutable() );
		
		helperG1.setFromBytes(u.toByteArray());
		this.u = new ElementWrapper( helperG1.getImmutable() );
		
		helperG1.setFromBytes(v.toByteArray());
		this.v = new ElementWrapper( helperG1.getImmutable() );
		
		helperG2.setFromBytes(omega.toByteArray());
		this.omega = new ElementWrapper( helperG2.getImmutable() );
		
		this.pairing = pairing;
	}

	
	
	public ElementWrapper getG1() {
		return g1;
	}

	public ElementWrapper getG2() {
		return g2;
	}

	public ElementWrapper getH() {
		return h;
	}

	public ElementWrapper getU() {		
		return u;
	}

	public ElementWrapper getV() {
		return v;
	}

	public ElementWrapper getOmega() {
		return omega;
	}
	
	public Pairing getPairing() {
		return pairing;
	}
	
	public String getR() {
		return r;
	}
	
	/**
	 * Return the whole object
	 * */
	public BBSGroupPublicKeyImpl getBBSGroupPublicKey() {
		return this;
	}
	
	
	
	
	public String toString() {
		return "(g1, g2, h, u, v, omega)";
	}
	
	public String readable() {
		String s = "\n\n" +
				"\n g1: " + StringUtils.cut(this.getG1()) + 
				"\n g2: " + this.getG2() + 
				"\n h: " + this.getH() + 
				"\n u: " + this.getU() + 
				"\n v: " + this.getV() + 
				"\n omega: " + this.getOmega() +
				"\n";
		return s;
	}

	

}
