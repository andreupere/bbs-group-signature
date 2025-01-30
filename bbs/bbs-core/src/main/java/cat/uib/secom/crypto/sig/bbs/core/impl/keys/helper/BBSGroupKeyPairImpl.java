package cat.uib.secom.crypto.sig.bbs.core.impl.keys.helper;

import cat.uib.secom.crypto.sig.bbs.core.impl.keys.BBSGroupPublicKeyImpl;
import cat.uib.secom.crypto.sig.bbs.core.impl.keys.BBSUserPrivateKeyImpl;

public class BBSGroupKeyPairImpl {

	private BBSGroupPublicKeyImpl gpk;
	private BBSUserPrivateKeyImpl upk;
	
	public BBSGroupKeyPairImpl(BBSGroupPublicKeyImpl gpk, BBSUserPrivateKeyImpl upk) {
		this.gpk = gpk;
		this.upk = upk;
	}

	
	
	public BBSUserPrivateKeyImpl getUserPrivateKey() {
		return upk;
	}

	public void setUserPrivateKey(BBSUserPrivateKeyImpl upk) {
		this.upk = upk;
	}

	public BBSGroupPublicKeyImpl getGroupPublicKey() {
		return gpk;
	}

	public void setGroupPublicKey(BBSGroupPublicKeyImpl gpk) {
		this.gpk = gpk;
	}
	
}
