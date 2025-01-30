package cat.uib.secom.crypto.sig.bbs.core.engines;


import it.unisa.dia.gas.jpbc.Element;



import cat.uib.secom.crypto.sig.bbs.core.exception.VerificationFailsException;
import cat.uib.secom.crypto.sig.bbs.core.keys.BBSGroupManagerPrivateKey;
import cat.uib.secom.crypto.sig.bbs.core.keys.BBSGroupPublicKey;
import cat.uib.secom.crypto.sig.bbs.core.keys.BBSUserPrivateKey;
import cat.uib.secom.crypto.sig.bbs.core.signature.BBSSignature;


/**
 * BBS Engine for sign and verify group signature without any kind of precomputation. The whole computation is done
 * just before signature process.
 * 
 * @see AbstractBBSEngine
 * 
 * @author Andreu Pere
 * */
public class BBSEngine extends AbstractBBSEngine {
	
	
//	public BBSEngine() {
//		super();
//		this.precomputation = false;
//		zp = gpk.getPairing().getZr();
//	}
	
	/** 
	 * Constructor used for a user who knows groupPublicKey and userPrivateKey
	 * 
	 * @param groupPublicKey
	 * @param userPrivateKey
	 * 
	 * */
	public BBSEngine(BBSGroupPublicKey groupPublicKey, BBSUserPrivateKey userPrivateKey) {
		super();
		this.precomputation = false;
		this.init(groupPublicKey, userPrivateKey);
		
	}
	
	/** 
	 * Constructor used for a user who only knows groupPublicKey (e.g. external verifier, not a group member)
	 * 
	 * @param groupPublicKey
	 * 
	 * */
	public BBSEngine(BBSGroupPublicKey groupPublicKey) {
		super();
		this.precomputation = false;
		this.init(groupPublicKey);
	}
	


	/**
	 * This method signs a message
	 * 
	 * @param message as the string to be signed
	 * */
	public BBSSignature sign(String message) throws Exception {
		//long initPairingPrecomputation = System.currentTimeMillis();
		super.preRandomAlphaBeta();
		super.preRandoms();
		super.preComputationRelatedToAlphaBeta();
		super.pairingsPrecomputation();
		//System.out.println("pairings precomputation: " + (System.currentTimeMillis() - initPairingPrecomputation) + "ms" );
		
		//long initPrecomputation = System.currentTimeMillis();
		super.precomputation();
		//System.out.println("precomputation: " + (System.currentTimeMillis() - initPrecomputation));
		
		//long initSignature = System.currentTimeMillis();
		BBSSignature signature = super.doSign(message);
		//System.out.println("doSign: " + (System.currentTimeMillis() - initSignature) + "ms");
		
		//System.out.println("total: " + ( System.currentTimeMillis() - initPairingPrecomputation ) + "ms" );
		return signature;
	}
	
	



	
	
	/**
	 * This method verifies a signature over a message
	 * 
	 * @param signature to be verified
	 * @param message to be verified with the signature
	 * 
	 * @return boolean
	 * */
	public boolean verify(BBSSignature signature, String message) throws Exception {
		super.verifierPrecomputation();
		return super.doVerify(signature, message);
	}



	
	/**
	 * This method opens the identity of the message signer
	 * 
	 * @param message which is signed
	 * @param signature
	 * @param groupManagerPrivateKey as the private key known by the group manager
	 * 
	 * @return Element from the (Ai,Xi) pair. This can be used to search the user identity in the manager data store
	 * 
	 * @throws VerificationFailsException if the signature verification is not true
	 * */
	@Override
	public Element open(String message, 
						BBSSignature signature, 
						BBSGroupManagerPrivateKey groupManagerPrivateKey)
			throws VerificationFailsException {
		//this.verifierPrecomputation();
		//boolean verification = this.doVerify(signature, message);
		boolean verification = true;
		if (!verification) 
			throw new VerificationFailsException("Signature verification failed...");
		// if verification==true -> reveal identity
		Element e = super.doOpen(message, signature, groupManagerPrivateKey);
		
		return e;
	}

}
