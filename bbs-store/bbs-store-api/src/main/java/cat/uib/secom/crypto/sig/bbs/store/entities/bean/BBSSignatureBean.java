package cat.uib.secom.crypto.sig.bbs.store.entities.bean;

import org.simpleframework.xml.Element;
import org.simpleframework.xml.Root;

import cat.uib.secom.crypto.sig.bbs.store.entities.BBSSignature;


@Root(name="group-signature")
public class BBSSignatureBean implements BBSSignature {

	@Element
	protected String t1;
	
	@Element
	protected String t2;
	
	@Element
	protected String t3;
	
	@Element
	protected String c;
	
	@Element
	protected String salpha;
	
	@Element
	protected String sbeta;
	
	@Element
	protected String sx;
	
	@Element
	protected String sdelta1;
	
	@Element
	protected String sdelta2;

	
	
	
	
	
	public String getT1() {
		return t1;
	}
	

	public String getT2() {
		return t2;
	}
	

	public String getT3() {
		return t3;
	}
	

	public String getC() {
		return c;
	}
	

	public String getSalpha() {
		return salpha;
	}

	public String getSbeta() {
		return sbeta;
	}

	public String getSx() {
		return sx;
	}

	public String getSdelta1() {
		return sdelta1;
	}

	public String getSdelta2() {
		return sdelta2;
	}

	
	
	
	
	public void setT1(String t1) {
		this.t1 = t1;
	}

	public void setT2(String t2) {
		this.t2 = t2;
	}

	public void setT3(String t3) {
		this.t3 = t3;
	}

	public void setC(String c) {
		this.c = c;
	}

	public void setSalpha(String salpha) {
		this.salpha = salpha;
	}

	public void setSbeta(String sbeta) {
		this.sbeta = sbeta;
	}

	public void setSx(String sx) {
		this.sx = sx;
	}

	public void setSdelta1(String sdelta1) {
		this.sdelta1 = sdelta1;
	}

	public void setSdelta2(String sdelta2) {
		this.sdelta2 = sdelta2;
	}
	
}
