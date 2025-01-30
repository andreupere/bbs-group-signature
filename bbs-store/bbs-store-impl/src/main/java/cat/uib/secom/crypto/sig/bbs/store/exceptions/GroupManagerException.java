package cat.uib.secom.crypto.sig.bbs.store.exceptions;


/**
 * @author Andreu Pere
 * 
 * Base exception for the data store
 * */
public class GroupManagerException extends Exception {

	/**
	 * serial version UID 
	 */
	private static final long serialVersionUID = 8507482208444806745L;

	/**
	 * Constructor without string with the exception's reason
	 * */
	public GroupManagerException() {
		super();
	}
	
	/**
	 * Constructor with a custom string explaining the exception's reason
	 * 
	 * @param str String with exception's reason
	 * */
	public GroupManagerException(String str) {
		super(str);
	}
	
}
