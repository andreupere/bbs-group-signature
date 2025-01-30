package cat.uib.secom.crypto.sig.bbs.store.exceptions;


/**
 * @author Andreu Pere
 * 
 * Thrown when the requester user is already served by the manager, it is,
 * his identity is already linked to a private key in the data store
 * 
 * @see GroupManagerException
 * */
public class UserAlreadyServedException extends GroupManagerException {

	/**
	 * serial version UID 
	 */
	private static final long serialVersionUID = 7735324679735500304L;

	/**
	 * Constructor with a string explaining the exception's reason
	 * @param str as a custom string passed by the application
	 * */
	public UserAlreadyServedException(String str) {
		super(str);
	}
	
	/**
	 * Constructor without custom string
	 * */
	public UserAlreadyServedException() {
		super("User is already served by the system...");
	}
	
}
