package cat.uib.secom.crypto.sig.bbs.core.engines;





import cat.uib.secom.crypto.sig.bbs.core.keys.BBSGroupPublicKey;
import cat.uib.secom.crypto.sig.bbs.core.keys.BBSUserPrivateKey;
import cat.uib.secom.crypto.sig.bbs.core.signature.BBSSignature;

public class BBSEngineTraceable extends BBSEngine {

	
	public BBSEngineTraceable(BBSGroupPublicKey groupPublicKey) {
		super(groupPublicKey);
//		this.precomputation = false;
//		this.init(groupPublicKey);
	}
	
	public BBSEngineTraceable(BBSGroupPublicKey groupPublicKey, BBSUserPrivateKey userPrivateKey) {
		super(groupPublicKey, userPrivateKey);
		super.preRandomAlphaBeta();
		
	}
	
//	public BBSEngineTraceable() {
//		super();
//	}

	/**
	 * sign using the same alpha and beta from the first sign event
	 * @throws Exception 
	 * */
	public BBSSignature sign(String message) throws Exception {
		System.out.println(this.alpha);
		System.out.println(this.beta);
		
		if (this.alpha == null || this.beta == null)
			throw new Exception("alpha or beta cannot be null..."); 

		super.preRandoms();
		super.preComputationRelatedToAlphaBeta();
		super.pairingsPrecomputation();
		super.precomputation();
		return super.doSign(message);
		
	}
	
	
	
	
	/**
	 * Verifies that two signatures have the same signer
	 * 
	 * @param signature1 First signature
	 * @param signature2 Second signature
	 * @return boolean as the verification result
	 * 
	 */
	public boolean verifySameSigner(BBSSignature signature1, BBSSignature signature2){
		boolean r1,r2,r3;
		
		r1 = signature1.getT1().getElement().equals(signature2.getT1().getElement());
		r2 = signature1.getT2().getElement().equals(signature2.getT2().getElement());
		r3 = signature1.getT3().getElement().equals(signature2.getT3().getElement());
		
		return (r1 && r2 && r3);
	}
	
	
	

}
