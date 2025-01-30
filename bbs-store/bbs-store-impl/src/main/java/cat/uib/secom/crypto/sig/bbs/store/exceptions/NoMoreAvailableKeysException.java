package cat.uib.secom.crypto.sig.bbs.store.exceptions;


/**
 * @author Andreu Pere
 * 
 * Thrown when the group manager has not any available user private key, 
 * it is, all the keys stored in the data store backend are already issued
 * @see GroupManagerException
 * */
public class NoMoreAvailableKeysException extends GroupManagerException {

	/**
	 * serial version UID 
	 */
	private static final long serialVersionUID = 8591565291018679171L;

	/**
	 * Exception constructor with a custom string passed by the application
	 * @param str exception's reason
	 * */
	public NoMoreAvailableKeysException(String str) {
		super(str);
	}
	
	/**
	 * Exception constructor without custom string 
	 * */
	public NoMoreAvailableKeysException() {
		super("No more available keys... I need to deploy a new group signature...");
	}
}
