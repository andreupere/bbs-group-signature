package cat.uib.secom.crypto.sig.bbs.core.parameters;

import java.security.SecureRandom;

import org.spongycastle.crypto.KeyGenerationParameters;

import cat.uib.secom.crypto.sig.bbs.core.impl.keys.BBSGroupManagerPrivateElementsImpl;
import cat.uib.secom.crypto.sig.bbs.core.impl.keys.BBSGroupManagerPrivateKeyImpl;
import cat.uib.secom.crypto.sig.bbs.core.impl.keys.BBSGroupPublicKeyImpl;


/**
 * @author Andreu Pere
 * 
 * POJO object to store parameters and data about the key generation process
 * 
 * It is mandatory by bouncy castle framework
 * 
 * */
public class BBSKeyGenerationParameters extends KeyGenerationParameters {

	private BBSParameters bbsParameters;
	private BBSGroupPublicKeyImpl bbsGroupPublicKey;
	private BBSGroupManagerPrivateKeyImpl bbsGroupManagerPrivateKey;
	private BBSGroupManagerPrivateElementsImpl bbsGroupManagerPrivateElements;

	public BBSKeyGenerationParameters(BBSParameters parameters, 
									BBSGroupPublicKeyImpl bbsGroupPublicKey,
									BBSGroupManagerPrivateKeyImpl bbsGroupManagerPrivateKey,
									BBSGroupManagerPrivateElementsImpl bbsGroupManagerPrivateElements) {
		// TODO: arreglar SecureRandom()
		super(new SecureRandom(), parameters.getG1().getElement().getField().getLengthInBytes());
		this.bbsParameters = parameters;
		this.bbsGroupPublicKey = bbsGroupPublicKey;
		this.bbsGroupManagerPrivateKey = bbsGroupManagerPrivateKey;
		this.bbsGroupManagerPrivateElements = bbsGroupManagerPrivateElements;
	}
	
	
	
	public BBSParameters getBBSParameters() {
		return bbsParameters;
	}
	
	public BBSGroupPublicKeyImpl getBBSGroupPublicKey() {
		return bbsGroupPublicKey;
	}
	
	public BBSGroupManagerPrivateKeyImpl getBBSGroupManagerPrivateKey() {
		return bbsGroupManagerPrivateKey;
	}
	
	public BBSGroupManagerPrivateElementsImpl getBBSGroupManagerPrivateElements() {
		return bbsGroupManagerPrivateElements;
	}

}
