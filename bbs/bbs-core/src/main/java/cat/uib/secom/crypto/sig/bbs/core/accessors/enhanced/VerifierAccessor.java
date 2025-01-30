package cat.uib.secom.crypto.sig.bbs.core.accessors.enhanced;



import cat.uib.secom.crypto.sig.bbs.core.engines.AbstractBBSEngine;
import cat.uib.secom.crypto.sig.bbs.core.engines.BBSEngineTraceable;
import cat.uib.secom.crypto.sig.bbs.core.keys.BBSGroupPublicKey;
import cat.uib.secom.crypto.sig.bbs.core.signature.BBSSignature;

/**
 * @author Andreu Pere
 * 
 * It represents the verifier actions
 * 
 * @see AbstractUserAccessor
 * @see BBSGroupPublicKey
 * */
public class VerifierAccessor extends AbstractUserAccessor {

	public VerifierAccessor(AbstractBBSEngine engine) {
		super(AbstractUserAccessor.VERIFIER, engine);
	}
	
	public boolean verify(BBSSignature signature, String message) throws Exception {

		boolean verify = engine.verify(signature, message);
		return verify;
	}
	
	public boolean verifySameSigner(BBSSignature signature1, BBSSignature signature2) throws Exception {
		if ( this.engine instanceof BBSEngineTraceable ) {
			return ((BBSEngineTraceable) engine).verifySameSigner(signature1, signature2);
		}
		throw new Exception("Method only used when BBSEngineTraceable is provided...");
	}
	

}
