package cat.uib.secom.crypto.sig.bbs.core.exception;

public class VerificationFailsException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 7041621929067963188L;
	
	
	public VerificationFailsException() {
		super("The signature verification fails...");
	}
	public VerificationFailsException(String str) {
		super(str);
	}

	
}
