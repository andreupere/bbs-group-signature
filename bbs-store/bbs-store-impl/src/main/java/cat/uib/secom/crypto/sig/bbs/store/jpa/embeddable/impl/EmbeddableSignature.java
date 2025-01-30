package cat.uib.secom.crypto.sig.bbs.store.jpa.embeddable.impl;



import javax.persistence.Column;
import javax.persistence.Embeddable;

import cat.uib.secom.crypto.sig.bbs.store.entities.ForceSerializable;



@Embeddable
public class EmbeddableSignature implements cat.uib.secom.crypto.sig.bbs.store.entities.BBSSignature,
											ForceSerializable {

	@Column(name="TIN_OMEGA_SIGN_T1")
	private String t1;

	
	@Column(name="TIN_OMEGA_SIGN_T2")
	private String t2;

	
	@Column(name="TIN_OMEGA_SIGN_T3")
	private String t3;

	
	@Column(name="TIN_OMEGA_SIGN_C")
	private String c;

	
	@Column(name="TIN_OMEGA_SIGN_SALPHA")
	private String salpha;

	
	@Column(name="TIN_OMEGA_SIGN_SBETA")
	private String sbeta;

	
	@Column(name="TIN_OMEGA_SIGN_SX")
	private String sx;

	
	@Column(name="TIN_OMEGA_SIGN_SDELTA1")
	private String sdelta1;

	
	@Column(name="TIN_OMEGA_SIGN_DELTA2")
	private String sdelta2;

	
	
	
	
	
	
	
	
	
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
	
	
	
	
	
	
	public ForceSerializable deserialize(String in) {
		String[] p = in.split(" ");
		EmbeddableSignature s = new EmbeddableSignature();
		s.t1 = p[0];
		s.t2 = p[1];
		s.t3 = p[2];
		s.c = p[3];
		s.sx = p[4];
		s.salpha = p[5];
		s.sbeta = p[6];
		s.sdelta1 = p[7];
		s.sdelta2 = p[8];
		return s;
	}
	
	
	public String serialize() {
		String out = t1 + " " +
					 t2 + " " +
					 t3 + " " +
					 c + " " +
					 sx + " " +
					 salpha + " " +
					 sbeta + " " +
					 sdelta1 + " " +
					 sdelta2;
		return out;
	}
	
	
	

}
