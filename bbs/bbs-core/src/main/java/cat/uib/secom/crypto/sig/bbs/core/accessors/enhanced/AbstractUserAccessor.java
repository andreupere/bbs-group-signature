package cat.uib.secom.crypto.sig.bbs.core.accessors.enhanced;

import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.CipherParameters;

import cat.uib.secom.crypto.sig.bbs.core.engines.AbstractBBSEngine;
import cat.uib.secom.crypto.sig.bbs.core.keys.BBSGroupPublicKey;
import cat.uib.secom.crypto.sig.bbs.core.keys.BBSUserPrivateKey;
import cat.uib.secom.crypto.sig.bbs.core.signature.BBSSignature;

/**
 * @author Andreu Pere
 * 
 * Abstract class which is the base class for Signer and Verifier classes
 * 
 * @see SignerAccessor
 * @see VerifierAccessor
 * */
public abstract class AbstractUserAccessor {

	public static String VERIFIER = "VERIFIER";
	public static String SIGNER = "SIGNER";
	private String behaviour;
	
	protected BBSGroupPublicKey groupPublicKey;
	protected BBSUserPrivateKey userPrivateKey;
	
	protected AbstractBBSEngine engine;
	
	
	public AbstractUserAccessor(String behaviour, AbstractBBSEngine engine) {
		this.setBehaviour(behaviour);
		this.engine = engine;
	}
	
	
	
	

	public BBSGroupPublicKey getGroupPublicKey() {
		return groupPublicKey;
	}

	public BBSUserPrivateKey getUserPrivateKey() {
		return userPrivateKey;
	}

	public AbstractBBSEngine getEngine() {
		return engine;
	}

	public void setGroupPublicKey(BBSGroupPublicKey groupPublicKey) {
		this.groupPublicKey = groupPublicKey;
	}


	public void setUserPrivateKey(BBSUserPrivateKey userPrivateKey) {
		this.userPrivateKey = userPrivateKey;
	}


	public void setEngine(AbstractBBSEngine engine) {
		this.engine = engine;
	}

	
	protected void setBehaviour(String behaviour) {
		this.behaviour = behaviour;
	}

	protected String getBehaviour() {
		return behaviour;
	}
}
