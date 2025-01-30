package cat.uib.secom.crypto.sig.bbs.store.jpa.embeddable.impl;


import javax.persistence.Column;
import javax.persistence.Embeddable;
import javax.persistence.Transient;

import cat.uib.secom.crypto.sig.bbs.core.impl.keys.BBSGroupPublicKey;
import cat.uib.secom.crypto.sig.bbs.core.parameters.BBSParameters;
import cat.uib.secom.crypto.sig.bbs.store.entities.ForceSerializable;
import cat.uib.secom.crypto.sig.bbs.store.entities.bean.BBSGroupPublicKeyBean;
import cat.uib.secom.utils.strings.StringUtils;


@Embeddable
public class EmbeddableBBSGroupPublicKey implements cat.uib.secom.crypto.sig.bbs.store.entities.BBSGroupPublicKey, 
													ForceSerializable {

	
	@Column(name="GROUP_PUBLIC_KEY_G1")
	protected String g1;
	
	@Column(name="GROUP_PUBLIC_KEY_G2", length=270)
	protected String g2;
	
	@Column(name="GROUP_PUBLIC_KEY_H")
	protected String h;
	
	@Column(name="GROUP_PUBLIC_KEY_U")
	protected String u;
	
	@Column(name="GROUP_PUBLIC_KEY_V")
	protected String v;
	
	@Column(name="GROUP_PUBLIC_KEY_OMEGA", length=270)
	protected String omega;
	
	
	@Transient
	private BBSGroupPublicKey bbsGroupPublicKey;
	
	
	
	public EmbeddableBBSGroupPublicKey() {}
	
	
	
	public BBSGroupPublicKeyBean toBean() {
		BBSGroupPublicKeyBean gpkb = new BBSGroupPublicKeyBean();
		gpkb.setG1(this.g1);
		gpkb.setG2(g2);
		gpkb.setH(h);
		gpkb.setOmega(omega);
		gpkb.setU(u);
		gpkb.setV(v);
		return gpkb;
	}
	
	public EmbeddableBBSGroupPublicKey fromBean(BBSGroupPublicKeyBean gpkb) {
		EmbeddableBBSGroupPublicKey egpk = new EmbeddableBBSGroupPublicKey();
		egpk.setG1( gpkb.getG1() );
		egpk.setG2( gpkb.getG2() );
		egpk.setH( gpkb.getH() );
		egpk.setU( gpkb.getU() );
		egpk.setV( gpkb.getV() );
		egpk.setOmega( gpkb.getOmega() );
		return egpk;
		
	}
	
	
	
	public void setBbsGroupPublicKey(BBSGroupPublicKey bbsGroupPublicKey) {
		this.bbsGroupPublicKey = bbsGroupPublicKey; 
	}
	public BBSGroupPublicKey getBbsGroupPublicKey() {
		return bbsGroupPublicKey;
	}
	
	
	public BBSGroupPublicKey restoreBBSGroupPublicKey(BBSParameters bbsParameters) {

		bbsGroupPublicKey = new BBSGroupPublicKey( StringUtils.hexStringToByteArray( g1 ), 
												   StringUtils.hexStringToByteArray( g2 ), 
												   StringUtils.hexStringToByteArray( h ), 
												   StringUtils.hexStringToByteArray( u ), 
												   StringUtils.hexStringToByteArray( v ),
												   StringUtils.hexStringToByteArray( omega ), 
												   bbsParameters.getPairing() );
		
		return bbsGroupPublicKey;
	}




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






	public ForceSerializable deserialize(String in) {
		String[] p = in.split(" ");
		
		EmbeddableBBSGroupPublicKey gpk = new EmbeddableBBSGroupPublicKey();
		gpk.g1 = p[0];
		gpk.g2 = p[1];
		gpk.h = p[2];
		gpk.u = p[3];
		gpk.v = p[4];
		gpk.omega = p[5];
		
		return gpk;
	}




	public String serialize() {
		String out = g1 + " " +
					 g2 + " " +
					 h + " " +
					 u + " " +
					 v + " " +
					 omega;
		return out;
	}
	
	
	
	
	
	
	
	
}
