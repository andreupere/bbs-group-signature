package cat.uib.secom.crypto.sig.bbs.core.impl.signature;







import cat.uib.secom.utils.pairing.ElementWrapper;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;


/**
 * @author Andreu Pere
 * 
 * This class is a simple POJO and it contains the definition of a signature over a message
 * 
 * 
 * @see Element
 * */
public class BBSSignatureImpl implements cat.uib.secom.crypto.sig.bbs.core.signature.BBSSignature {
	
	private ElementWrapper t1;
	private ElementWrapper t2;
	private ElementWrapper t3;
	private ElementWrapper c;
	private ElementWrapper salpha;
	private ElementWrapper sbeta;
	private ElementWrapper sx;
	private ElementWrapper sdelta1;
	private ElementWrapper sdelta2;
	
	/**
	 * The signature with its elements
	 * 
	 * @param t1
	 * @param t2
	 * @param t3
	 * @param c
	 * @param salpha
	 * @param sbeta
	 * @param sx
	 * @param sdelta1
	 * @param sdelta2
	 * */
	public BBSSignatureImpl(ElementWrapper t1, ElementWrapper t2, ElementWrapper t3, ElementWrapper c, ElementWrapper salpha, 
			ElementWrapper sbeta, ElementWrapper sx, ElementWrapper sdelta1, ElementWrapper sdelta2) {
		this.t1 = t1;
		this.t2 = t2;
		this.t3 = t3;
		this.c = c;
		this.salpha = salpha;
		this.sbeta = sbeta;
		this.sx = sx;
		this.sdelta1 = sdelta1;
		this.sdelta2 = sdelta2;
	}
	
	public BBSSignatureImpl() {}
	
	/**
	 * This rebuilds a Signature object from byte[] streams in the verifier side after (for example) network transmission
	 * */
	public BBSSignatureImpl(byte[] t1, byte[] t2, byte[] t3, byte[] c, byte[] salpha,
					byte[] sbeta, byte[] sx, byte[] sdelta1, byte[] sdelta2, Pairing pairing) {
		Element helperG1 = pairing.getG1().newOneElement();
		Element helperZr = pairing.getZr().newOneElement();
		
		helperG1.setFromBytes(t1);
		this.t1 = new ElementWrapper( helperG1 );
		
		helperG1.setFromBytes(t2);
		this.t2 = new ElementWrapper( helperG1 );
		
		helperG1.setFromBytes(t3);
		this.t3 = new ElementWrapper( helperG1 );
		
		helperZr.setFromBytes(c);
		this.c = new ElementWrapper( helperZr );
		
		helperZr.setFromBytes(salpha);
		this.salpha = new ElementWrapper( helperZr );
		
		helperZr.setFromBytes(sbeta);
		this.sbeta = new ElementWrapper( helperZr );
		
		helperZr.setFromBytes(sx);
		this.sx = new ElementWrapper( helperZr );
		
		helperZr.setFromBytes(sdelta1);
		this.sdelta1 = new ElementWrapper( helperZr );
		
		helperZr.setFromBytes(sdelta2);
		this.sdelta2 = new ElementWrapper( helperZr );
		
	}
	
	

	public ElementWrapper getT1() {
		return t1;
	}
	

	public ElementWrapper getT2() {
		return t2;
	}
	

	public ElementWrapper getT3() {
		return t3;
	}
	

	public ElementWrapper getC() {
		return c;
	}
	

	public ElementWrapper getSalpha() {
		return salpha;
	}
	

	public ElementWrapper getSbeta() {
		return sbeta;
	}
	

	public ElementWrapper getSx() {
		return sx;
	}
	

	public ElementWrapper getSdelta1() {
		return sdelta1;
	}
	

	public ElementWrapper getSdelta2() {
		return sdelta2;
	}
	
	
	
	
	
	

	public String readable() {
		// TODO Auto-generated method stub
		return null;
	}
	
	public String toString() {
		String s = "(T1, T2, T3, c, salpha, sbeta, sx, sdelta1, sdelta2)";
		return s;
	}
	
	

}
