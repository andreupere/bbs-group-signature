package cat.uib.secom.crypto.sig.bbs.store.jpa.business;

import java.math.BigInteger;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Set;


import javax.persistence.Query;




import cat.uib.secom.crypto.sig.bbs.core.keys.BBSGroupManagerPrivateElements;
import cat.uib.secom.crypto.sig.bbs.core.keys.BBSGroupManagerPrivateKey;
import cat.uib.secom.crypto.sig.bbs.core.keys.BBSGroupPublicKey;
import cat.uib.secom.crypto.sig.bbs.core.keys.BBSUserPrivateKey;
import cat.uib.secom.crypto.sig.bbs.core.accessors.enhanced.GroupManagerAccessor;
import cat.uib.secom.crypto.sig.bbs.store.exceptions.NoMoreAvailableKeysException;
import cat.uib.secom.crypto.sig.bbs.store.exceptions.UserAlreadyServedException;
import cat.uib.secom.crypto.sig.bbs.store.jpa.embeddable.impl.EmbeddableBBSGroupManagerPrivateKey;
import cat.uib.secom.crypto.sig.bbs.store.jpa.embeddable.impl.EmbeddableBBSGroupPublicKey;
import cat.uib.secom.crypto.sig.bbs.store.jpa.embeddable.impl.EmbeddableBBSUserPrivateKey;
import cat.uib.secom.crypto.sig.bbs.store.jpa.entities.impl.GroupManagerPrivateKeyDB;
import cat.uib.secom.crypto.sig.bbs.store.jpa.entities.impl.GroupPublicKeyDB;
import cat.uib.secom.crypto.sig.bbs.store.jpa.entities.impl.KeyPairDB;
import cat.uib.secom.crypto.sig.bbs.store.jpa.entities.impl.UserPrivateKeyDB;

public class GroupManagerEntityManagerBean extends AbstractEntityManagerBean {

	private final static String PU_NAME = "groupManager-PU";
	
	/**
	 * It builds a new BBSStoreDataBase in order to query the database
	 * It uses JPA
	 * It creates the entity manager to query the database
	 * 
	 * It needs to be created every time you want to query the database, because all the
	 * methods in this class close the entity manager when they end
	 * 
	 * @param persistenceUnitName is a string with the name of the persistence unit 
	 * @see persistence.xml
	 * */
	public GroupManagerEntityManagerBean() {
		super(PU_NAME);
	}
	public GroupManagerEntityManagerBean(String persistenceUnitName) {
		super(persistenceUnitName);
	}
	
	
	
	/**
	 * @deprecated
	 * */
	public void initGroup(Integer numberUsers, String curveFileName, byte[] g1) {
		
		GroupManagerAccessor groupManager = new GroupManagerAccessor(numberUsers, curveFileName);
		// group manager setup (init parameters, load curve, key generation)
		
		groupManager.setup(g1);
		
		// TODO: remove
		
		/*this.storeGroupUserData(groupManager.extractUserPrivateKeys(), 
								groupManager.extractGroupPublicKey(),
								groupManager.extractGroupManagerPrivateKey(),
								groupManager.extractGroupManagerPrivateElements());*/
		
	}
	
	
	/**
	 * @deprecated
	 * */
	public void initGroup(Integer numberUsers, String curveFileName) {
		
		
		GroupManagerAccessor groupManager = new GroupManagerAccessor(numberUsers, curveFileName);
		// group manager setup (init parameters, load curve, key generation)
		
		groupManager.setup();
		
		// TODO: remove
		/*this.storeGroupUserData(groupManager.extractUserPrivateKeys(), 
								groupManager.extractGroupPublicKey(),
								groupManager.extractGroupManagerPrivateKey(),
								groupManager.extractGroupManagerPrivateElements());*/
		
	}
	
	
	public GroupPublicKeyDB retrieveGroupPublicKey(Long id) {
		super.preparePersistence();
		GroupPublicKeyDB gpk = super.getEntityManager().find(GroupPublicKeyDB.class, id);
		System.out.println(gpk);
		super.closePersistence();
		return gpk;
	}
	


	/**
	 * This method issues a key pair (group public key and user private key) to a user. It checks
	 * if the user is already served by manager and if there are more available keys to issue
	 * 
	 * @param uIdentity Integer that represents the identity of user
	 * @see KeyPairDB
	 * @return KeyPairDB containing the SK/PK key pair as it was stored in the database (byte[])
	 * @throws UserAlreadyServedException when the user who made the request was already served
	 * @throws NoMoreAvailableKeysException when there are not more available keys to issue to users
	 * */
	@SuppressWarnings("unchecked")
	public KeyPairDB issueKeyPair(String uIdentity) throws UserAlreadyServedException, NoMoreAvailableKeysException {
		
		super.preparePersistence();
		
		Query q = super.getEntityManager().createNamedQuery("isIssued");
		q.setParameter(1, uIdentity );
		List<UserPrivateKeyDB> lu = q.getResultList();
		
		// if any result, then throw new UserAlreadyServedException (the user is already registered with a PK/SK key pair)
		if ( !lu.isEmpty() ) {
			throw new UserAlreadyServedException(""); 
		}
		
		// looking for a key not issued
		q = super.getEntityManager().createNamedQuery("issueKeyPair");
		// if no results, no more available keys, so throw new NoMoreAvailableKeysException
		lu = q.getResultList(); 
		
		if ( lu.isEmpty() ) {
			throw new NoMoreAvailableKeysException("");
		}
		// if results, get the first result and issue the key to user uIdentity
		UserPrivateKeyDB u = (UserPrivateKeyDB)lu.get(0);
		u.setDateIssued(new Date());
		u.setIssued(true);
		u.setuIdentity(uIdentity);
		
		
		// update user
		super.getEntityManager().merge(u);
		// commit changes
		super.getEntityTransaction().commit();
		
		
		// get public key
		GroupPublicKeyDB gpkDB = u.getGroupPublicKeyDB();
		// get private key
		UserPrivateKeyDB uskDB = u;

		
		super.closePersistence();
		
		
		// key pair (group public key / user private key) with fields returned in byte[] and BigInteger formats
		return new KeyPairDB(gpkDB, uskDB);
	}

	
	
	public void storeGroupData(GroupManagerAccessor gma) {
		this.storeGroupData(gma.getUserPrivateKeys(),
					   gma.getGroupPublicKey(),
					   gma.getGroupManagerPrivateKey(),
					   gma.getGroupManagerPrivateElements());
	}

	
	/**
	 * This method stores all data related to a group (group public key, users private keys 
	 * and group private keys and elements)
	 * It should be invoked to store the data generated after the KEYGEN(n) algorithm of BBS scheme
	 * 
	 * @param uskMap the hash map containing all user private keys generated before
	 * @param gpk the group public key object
	 * @param gmsk the group manager private key object
	 * @param gmse the group manager private element
	 * 
	 * @return void
	 * */
	protected void storeGroupData(HashMap<Integer, BBSUserPrivateKey> uskMap, 
								BBSGroupPublicKey gpk, 
								BBSGroupManagerPrivateKey gmsk, 
								BBSGroupManagerPrivateElements gmse) {
		
		super.preparePersistence();
		
		// we build the entity GrouPublicKeyDB
		GroupPublicKeyDB gpkDB = new GroupPublicKeyDB();
		
		// we build the entity GroupManagerPrivateKeyDB
		GroupManagerPrivateKeyDB gmskDB = new GroupManagerPrivateKeyDB();
		
		
		// we set gpkDB groupPublicKey
		EmbeddableBBSGroupPublicKey groupPublicKey = new EmbeddableBBSGroupPublicKey();
		
		//System.out.println("store: g1: " + gpk.getG1().toHexString());
		//System.out.println("store: g2: " + gpk.getG2().toHexString().length() );
		//System.out.println("store: v: " + gpk.getV().toHexString());
		
		groupPublicKey.setG1( gpk.getG1().toHexString() );
		groupPublicKey.setG2( gpk.getG2().toHexString() );
		groupPublicKey.setH( gpk.getH().toHexString() );
		groupPublicKey.setU( gpk.getU().toHexString() );
		groupPublicKey.setV( gpk.getV().toHexString() );
		groupPublicKey.setOmega( gpk.getOmega().toHexString() );
		
		//System.out.println("store: g1: " + groupPublicKey.getG1() );
		
		gpkDB.setGroupPublicKey(groupPublicKey);
		
		//System.out.println("store: g1: " + gpkDB.getGroupPublicKey().getG1() );
		//System.out.println("store: g1: " + gpkDB.getId() );

		
		// persist instance
		super.getEntityManager().persist( gpkDB );
		
		
		// we set gmskDB fields
		EmbeddableBBSGroupManagerPrivateKey groupManagerPrivateKey = new EmbeddableBBSGroupManagerPrivateKey();
		groupManagerPrivateKey.setDelta1( gmsk.getDelta1().toHexString() );
		groupManagerPrivateKey.setDelta2( gmsk.getDelta2().toHexString() );
		groupManagerPrivateKey.setGamma( gmse.getGamma().toHexString() );
		gmskDB.setGroupManagerPrivateKey(groupManagerPrivateKey);
		gmskDB.setGpkDB(gpkDB);
		

		// persist instance
		super.getEntityManager().persist(gmskDB);
		
		
		// we set upkDB fields for all users
		Set<Integer> s = uskMap.keySet();
		Iterator<Integer> it = s.iterator();
		while (it.hasNext()) {
			Integer key = (Integer) it.next();
			BBSUserPrivateKey singleBBSupk = uskMap.get(key);
			// we build the entity UserPrivateKeyDB
			UserPrivateKeyDB upkDB = new UserPrivateKeyDB();
			
			EmbeddableBBSUserPrivateKey userPrivateKey = new EmbeddableBBSUserPrivateKey();
			userPrivateKey.setAi( singleBBSupk.getA().toHexString() );
			userPrivateKey.setXi( singleBBSupk.getX().toHexString() );
			
			upkDB.setUserPrivateKey(userPrivateKey);

			upkDB.setDateIssued(new Date());
			upkDB.setIssued(false);
			upkDB.setRevoked(false);
			upkDB.setGroupManager(gpkDB);
			// persist instance
			super.getEntityManager().persist(upkDB);
		}
		
		super.getEntityTransaction().commit();
		
		//System.out.println("store: g1: " + gpkDB.getGroupPublicKey().getG1() );
		
		
		super.closePersistence();
		
	}
	

}
