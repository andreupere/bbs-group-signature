package cat.uib.secom.crypto.sig.bbs.store.jpa.embeddable.impl;



import javax.persistence.Column;
import javax.persistence.Embeddable;
import javax.persistence.Transient;

import cat.uib.secom.crypto.sig.bbs.core.impl.keys.BBSGroupPublicKey;
import cat.uib.secom.crypto.sig.bbs.core.impl.keys.BBSUserPrivateKey;
import cat.uib.secom.crypto.sig.bbs.store.entities.ForceSerializable;
import cat.uib.secom.crypto.sig.bbs.store.entities.bean.BBSUserPrivateKeyBean;
import cat.uib.secom.utils.strings.StringUtils;


@Embeddable
public class EmbeddableBBSUserPrivateKey implements cat.uib.secom.crypto.sig.bbs.store.entities.BBSUserPrivateKey,
													ForceSerializable {
	
	
	@Column(name="USER_PK_A")
	private String ai;
	
	
	@Column(name="USER_PK_X")
	private String xi;
	
	
	@Transient
	private BBSUserPrivateKey bbsUserPrivateKey;
	
	
	
	
	public String getAi() {
		return ai;
	}
	public void setAi(String ai) {
		this.ai = ai;
	}
	
	
	public String getXi() {
		return xi;
	}
	public void setXi(String xi) {
		this.xi = xi;
	}
	
	
	public void setBbsUserPrivateKey(BBSUserPrivateKey bbsUserPrivateKey) {
		this.bbsUserPrivateKey = bbsUserPrivateKey;
	}
	public BBSUserPrivateKey getBbsUserPrivateKey() {
		return bbsUserPrivateKey;
	}
	
	
	
	public BBSUserPrivateKey restoreBBSUserPrivateKey(BBSGroupPublicKey bbsGroupPublicKey) {
		bbsUserPrivateKey = new BBSUserPrivateKey( StringUtils.hexStringToByteArray( ai), 
												   StringUtils.hexStringToByteArray( xi ), 
												   bbsGroupPublicKey.getPairing());
		return bbsUserPrivateKey;
	}
	

	
	
	
	
	
	public ForceSerializable deserialize( String in ) {
		String[] p = in.split(" ");
		
		EmbeddableBBSUserPrivateKey usk = new EmbeddableBBSUserPrivateKey();
		usk.xi = p[0];
		usk.ai = p[1];
		
		return usk;
	}
	
	
	public String serialize() {
		String out = xi  + " " +
		 			 ai;
		
		return out;
	}
	
	
	public BBSUserPrivateKeyBean toBean() {
		BBSUserPrivateKeyBean uskb = new BBSUserPrivateKeyBean();
		uskb.setAi(ai);
		uskb.setXi(xi);
		return uskb;
	}
	
	

}
