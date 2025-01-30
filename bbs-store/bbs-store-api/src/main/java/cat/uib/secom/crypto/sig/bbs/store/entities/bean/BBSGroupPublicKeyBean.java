package cat.uib.secom.crypto.sig.bbs.store.entities.bean;

import org.simpleframework.xml.Element;
import org.simpleframework.xml.Root;

import cat.uib.secom.crypto.sig.bbs.store.entities.BBSGroupPublicKey;


@Root(name="bbs-group-public-key")
public class BBSGroupPublicKeyBean implements BBSGroupPublicKey {

	@Element
	protected String g1;
	
	@Element
	protected String g2;
	
	@Element
	protected String h;
	
	@Element
	protected String u;
	
	@Element
	protected String v;
	
	@Element
	protected String omega;

	
	
	
	
	
	public String getG1() {
		return g1;
	}

	public String getG2() {
		return g2;
	}

	public String getH() {
		return h;
	}

	public String getU() {
		return u;
	}

	public String getV() {
		return v;
	}

	public String getOmega() {
		return omega;
	}

	public void setG1(String g1) {
		this.g1 = g1;
	}

	public void setG2(String g2) {
		this.g2 = g2;
	}

	public void setH(String h) {
		this.h = h;
	}

	public void setU(String u) {
		this.u = u;
	}

	public void setV(String v) {
		this.v = v;
	}

	public void setOmega(String omega) {
		this.omega = omega;
	}
	
	

	
	


	
}
