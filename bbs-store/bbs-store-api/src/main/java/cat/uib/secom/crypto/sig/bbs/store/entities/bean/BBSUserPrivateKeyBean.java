package cat.uib.secom.crypto.sig.bbs.store.entities.bean;

import org.simpleframework.xml.Element;
import org.simpleframework.xml.Root;

import cat.uib.secom.crypto.sig.bbs.store.entities.BBSUserPrivateKey;


@Root(name="private-key")
public class BBSUserPrivateKeyBean implements BBSUserPrivateKey {

	@Element
	private String ai;
	
	@Element
	private String xi;
	
	
	
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
	
}
