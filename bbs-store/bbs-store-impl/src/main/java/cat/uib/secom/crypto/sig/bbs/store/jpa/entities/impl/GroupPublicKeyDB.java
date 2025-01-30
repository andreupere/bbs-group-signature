package cat.uib.secom.crypto.sig.bbs.store.jpa.entities.impl;


import java.util.Set;

import javax.persistence.Column;
import javax.persistence.Embedded;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.Table;

import cat.uib.secom.crypto.sig.bbs.store.jpa.embeddable.impl.EmbeddableBBSGroupPublicKey;


/**
 * @author Andreu Pere
 * 
 * Entity that represents the group public key structure in the database.
 * The group public key is stored as byte[] in the database.
 * It also defines get methods that returns BigInteger
 * 
 * @see UserPrivateKeyDB
 * @see GroupManagerPrivateKeyDB
 * */
@Entity
@Table(name="GROUP_MANAGER_GROUP_PUBLIC_KEY")
@Inheritance(strategy = InheritanceType.SINGLE_TABLE)
public class GroupPublicKeyDB {
	
	/**
	 * Primary key for this entity (table), so it is unique and the ID generation
	 * is delegated to the underlying database manager
	 * */
	@Id
	@GeneratedValue()
	@Column(name="ID")
	private long id;
	
	
	@Embedded
	private EmbeddableBBSGroupPublicKey groupPublicKey;


	
	
	/**
	 * A set of user private keys related to this group public key
	 * */
	@OneToMany(targetEntity=cat.uib.secom.crypto.sig.bbs.store.jpa.entities.impl.UserPrivateKeyDB.class, 
			cascade=javax.persistence.CascadeType.ALL, 
			mappedBy="group")
	private Set<UserPrivateKeyDB> users;
	
	/**
	 * The private group manager key and private element related to this group public key 
	 * */
	@OneToOne(mappedBy="gpkDB",
			cascade=javax.persistence.CascadeType.ALL)
	private GroupManagerPrivateKeyDB gmskDB;
	
	
	
	
	///////////////////////// GET and SETs methods ////////////////////////
	
	public long getId() {
		return id;
	}
	public void setId(long id) {
		this.id = id;
	}
	

	public void setUsers(Set<UserPrivateKeyDB> users) {
		this.users = users;
	}
	public Set<UserPrivateKeyDB> getUsers() {
		return users;
	}
	
	

	
	
	
	
	public void setGmskDB(GroupManagerPrivateKeyDB gmskDB) {
		this.gmskDB = gmskDB;
	}
	public GroupManagerPrivateKeyDB getGmskDB() {
		return gmskDB;
	}
	
	
	public void setGroupPublicKey(EmbeddableBBSGroupPublicKey groupPublicKey) {
		this.groupPublicKey = groupPublicKey;
	}
	public EmbeddableBBSGroupPublicKey getGroupPublicKey() {
		return groupPublicKey;
	}
	
	
	
	public String toString() {
		String r = "GroupPublicKeyDB: {id: " + id + ";}";
		return r;
	}

}
