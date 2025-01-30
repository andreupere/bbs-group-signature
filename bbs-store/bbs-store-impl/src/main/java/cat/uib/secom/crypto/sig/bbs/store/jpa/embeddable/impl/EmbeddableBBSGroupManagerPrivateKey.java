package cat.uib.secom.crypto.sig.bbs.store.jpa.embeddable.impl;

import java.math.BigInteger;

import javax.persistence.Column;
import javax.persistence.Embeddable;
import javax.persistence.Transient;

import cat.uib.secom.crypto.sig.bbs.store.entities.ForceSerializable;







@Embeddable
public class EmbeddableBBSGroupManagerPrivateKey implements cat.uib.secom.crypto.sig.bbs.store.entities.BBSGroupManagerPrivateKey,
															ForceSerializable {


	
	@Column(name="DELTA1")
	private String delta1;

	
	@Column(name="DELTA2")
	private String delta2;
	
	
	@Column(name="GAMMA")
	private String gamma;

	
	
	

	public String getDelta1() {
		return delta1;
	}


	public String getDelta2() {
		return delta2;
	}


	public String getGamma() {
		return gamma;
	}


	public void setDelta1(String delta1) {
		this.delta1 = delta1;
	}


	public void setDelta2(String delta2) {
		this.delta2 = delta2;
	}


	public void setGamma(String gamma) {
		this.gamma = gamma;
	}


	
	
	
	public ForceSerializable deserialize(String in) {
		return null;
	}


	public String serialize() {

		return null;
	}


	

	
	
	
	
	
	
	
}
