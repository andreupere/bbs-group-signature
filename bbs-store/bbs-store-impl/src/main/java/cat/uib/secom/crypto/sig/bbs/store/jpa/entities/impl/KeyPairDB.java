package cat.uib.secom.crypto.sig.bbs.store.jpa.entities.impl;


/**
 * @author Andreu Pere
 * 
 * This class is a POJO with gets and sets
 * It stores a public/private key pair as stored in the data store
 * 
 * @see GroupPublicKeyDB
 * @see UserPrivateKeyDB
 * */
public class KeyPairDB {

	/**
	 * Group public key as stored in the database
	 * */
	private GroupPublicKeyDB groupPublicKeyDB;
	/**
	 * User private key as stored in the database
	 * */
	private UserPrivateKeyDB userPrivateKeyDB;
	
	
	public KeyPairDB(GroupPublicKeyDB gpkDB, UserPrivateKeyDB uskDB) {
		this.setGroupPublicKeyDB(gpkDB);
		this.setUserPrivateKeyDB(uskDB);
	}

	public void setGroupPublicKeyDB(GroupPublicKeyDB groupPublicKeyDB) {
		this.groupPublicKeyDB = groupPublicKeyDB;
	}

	public GroupPublicKeyDB getGroupPublicKeyDB() {
		return groupPublicKeyDB;
	}

	public void setUserPrivateKeyDB(UserPrivateKeyDB userPrivateKeyDB) {
		this.userPrivateKeyDB = userPrivateKeyDB;
	}

	public UserPrivateKeyDB getUserPrivateKeyDB() {
		return userPrivateKeyDB;
	}
}
