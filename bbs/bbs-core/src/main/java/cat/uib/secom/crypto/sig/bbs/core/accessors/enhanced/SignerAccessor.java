package cat.uib.secom.crypto.sig.bbs.core.accessors.enhanced;


import cat.uib.secom.crypto.sig.bbs.core.engines.AbstractBBSEngine;
import cat.uib.secom.crypto.sig.bbs.core.impl.signature.BBSSignatureImpl;


/**
 * @author Andreu Pere
 * 
 * This object represents the signer user actions: sign message
 * 
 * @see AbstractUserAccessor
 * @see Signature
 * */
public class SignerAccessor extends AbstractUserAccessor {

	/**
	 * The constructor builds a new Signer, using the BBSEngine class to access to the sign method
	 * */
	public SignerAccessor(AbstractBBSEngine engine) {
		super(AbstractUserAccessor.SIGNER, engine);
	}
	
	
	public BBSSignatureImpl sign(String message) throws Exception {
		BBSSignatureImpl signature = (BBSSignatureImpl) engine.sign(message);
		return signature;
	}
	
	/**
	 * Sign a message. 
	 * This method needs to set a message and a keyPair before to execute it
	 * 
	 * @return Signature It is a object that represents the signature over the message
	 * @throws IllegalArgumentException
	 * @see Signature
	 * */
//	public Signature sign() {
//		if (message == null)
//			throw new IllegalArgumentException("message is NULL. message needs to be set before to call this method");
//		if (keyPair == null)
//			throw new IllegalArgumentException("keyPair is NULL. keyPair needs to be set before to call this method");
//		
//		
//		return bbsSigner.sign(message, keyPair.getPublic(), keyPair.getPrivate());
//		
//	}
	
	
	
	
	

}
