package cat.uib.secom.crypto.sig.bbs.core.engines;

import it.unisa.dia.gas.jpbc.Element;


import cat.uib.secom.crypto.sig.bbs.core.exception.VerificationFailsException;
import cat.uib.secom.crypto.sig.bbs.core.keys.BBSGroupManagerPrivateKey;
import cat.uib.secom.crypto.sig.bbs.core.keys.BBSGroupPublicKey;
import cat.uib.secom.crypto.sig.bbs.core.keys.BBSUserPrivateKey;
import cat.uib.secom.crypto.sig.bbs.core.signature.BBSSignature;



/**
 * BBSEngine with precomputations enabled
 * 
 * @author Andreu Pere / Arnau
 * */
public class BBSEnginePrecomputation extends AbstractBBSEngine {
	
	public static String VERIFIER = "verifier";
	public static String SIGNER = "signer";
	
	/**
	 * @deprecated
	 * Constructor used for user who has groupPublicKey and his own userPrivateKey
	 * */
	public BBSEnginePrecomputation(BBSGroupPublicKey groupPublicKey, BBSUserPrivateKey userPrivateKey) {
		super();
		this.precomputation = true;
		super.init(groupPublicKey, userPrivateKey);
		super.pairingsPrecomputation();
		super.preRandomAlphaBeta();
		super.preRandoms();
		super.preComputationRelatedToAlphaBeta();
		super.precomputation();
		super.verifierPrecomputation();
	}
	
	
	/**
	 * Constructor used for user who has groupPublicKey and his own userPrivateKey
	 * */
	public BBSEnginePrecomputation(BBSGroupPublicKey groupPublicKey, BBSUserPrivateKey userPrivateKey, String operation) {
		super();
		this.precomputation = true;
		super.init(groupPublicKey, userPrivateKey);
		if (operation.equals(SIGNER)) {
			super.pairingsPrecomputation();
			super.preRandomAlphaBeta();
			super.preRandoms();
			super.preComputationRelatedToAlphaBeta();
			super.precomputation();
		}
		else if (operation.equals(VERIFIER)) {
			super.verifierPrecomputation();
		}

	}
	
	
	/**
	 * @deprecated
	 * Constructor used for user who has only groupPublicKey (e.g. external verifier, not group member)
	 * */
	public BBSEnginePrecomputation(BBSGroupPublicKey groupPublicKey) {
		super();
		this.precomputation = true;
		this.init(groupPublicKey);
		super.pairingsPrecomputation();
		super.preRandomAlphaBeta();
		super.preRandoms();
		super.preComputationRelatedToAlphaBeta();
		super.precomputation();
		super.verifierPrecomputation();
	}
	
	/**
	 * Constructor used by user who has only groupPublicKey (e.g. external verifier, not group member, 
	 * or group member verifier, but without providing groupPrivateKey)
	 * 
	 * @param operation detones if this instantiation is for SIGNER o VERIFIER operation
	 * */
	public BBSEnginePrecomputation(BBSGroupPublicKey groupPublicKey, String operation) {
		super();
		this.precomputation = true;
		this.init(groupPublicKey);
		if (operation.equals(SIGNER) ) {
			super.pairingsPrecomputation();
			super.preRandomAlphaBeta();
			super.preRandoms();
			super.preComputationRelatedToAlphaBeta();
			super.precomputation();
		}
		else if (operation.equals(VERIFIER) ) {
			super.verifierPrecomputation();
		}
	}
	
	/**
	 * Convenience constructor. You should don't use it directly. This is used for subclasses
	 * */
	public BBSEnginePrecomputation() {
		super();
	}
	
	
	/**
	 * This method signs a message string
	 * 
	 * @param message as the string message to be signed
	 * 
	 * @return Signature object 
	 * 
	 * */
	public BBSSignature sign(String message) throws Exception {
		BBSSignature signature = super.doSign(message);
		//System.out.println("doSign (total): " + (System.currentTimeMillis() - initSignature) + "ms");
		return signature;
	}
	
	
	/**
	 * This method opens the signature and reveals the signer identity. This method is a group manager method.
	 * 
	 * @param message as the signed message
	 * @param signature as the message signature
	 * @param groupManagerPrivateKey as the manager private key used to open the signature
	 * 
	 * @return Element from the (Ai,Xi) pair. This can be used to search the user identity in the manager data store
	 * 
	 * @throws VerificationFailsException if the signature verification is not true
	 * */
	@Override
	public Element open(String message, BBSSignature signature, BBSGroupManagerPrivateKey groupManagerPrivateKey)
			throws VerificationFailsException {
		boolean verification = this.doVerify(signature, message);
		if (!verification) 
			throw new VerificationFailsException("Signature verification failed...");
		// if verification==true -> reveal identity
		Element e = super.doOpen(message, signature, groupManagerPrivateKey);
		
		return e;
	}

	
	



	
	/**
	 * This method verifies the signature over a message
	 * 
	 * @param signature to be verified
	 * @param message as the signed string
	 * */
	@Override
	public boolean verify(BBSSignature signature, String message) {
		return super.doVerify(signature, message);
	}

}
