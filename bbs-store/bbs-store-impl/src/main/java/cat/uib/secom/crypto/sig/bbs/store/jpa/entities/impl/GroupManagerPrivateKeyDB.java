package cat.uib.secom.crypto.sig.bbs.store.jpa.entities.impl;



import javax.persistence.Column;
import javax.persistence.Embedded;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.Table;

import cat.uib.secom.crypto.sig.bbs.store.jpa.embeddable.impl.EmbeddableBBSGroupManagerPrivateKey;


/**
 * @author Andreu Pere
 * 
 * Entity object that represents the group private key and group manager private element
 * structure in the database.
 * The group manager private parameters are stored as byte[]
 * It also defines get methods returning BigInteger for parameters
 * 
 * @see GroupPublicKeyDB
 * */
@Entity
@Table(name="GROUP_MANAGER_PRIVATE_KEY")
@Inheritance(strategy = InheritanceType.SINGLE_TABLE)
public class GroupManagerPrivateKeyDB {

	/**
	 * Primary key for this entity (table), so it is unique and the ID generation
	 * is delegated to the underlying database manager
	 * */
	@Id
	@GeneratedValue()
	@Column(name="ID")
	private long id;
	
	// Group Manager Private Key definition
	@Embedded
	private EmbeddableBBSGroupManagerPrivateKey groupManagerPrivateKey;

	
	/**
	 * One to one relation to the group public key.
	 * This will be translated into a column in this database table storing 
	 * the ID of the group public key
	 * */
	@OneToOne
	@JoinColumn(name="GROUP_PUBLIC_KEY_ID_FK")
	private GroupPublicKeyDB gpkDB;
	
	
	
	
	
	public void setId(long id) {
		this.id = id;
	}
	public long getId() {
		return id;
	}
	
	
	
	
	
	public void setGpkDB(GroupPublicKeyDB gpkDB) {
		this.gpkDB = gpkDB;
	}
	public GroupPublicKeyDB getGpkDB() {
		return gpkDB;
	}
	public void setGroupManagerPrivateKey(EmbeddableBBSGroupManagerPrivateKey groupManagerPrivateKey) {
		this.groupManagerPrivateKey = groupManagerPrivateKey;
	}
	public EmbeddableBBSGroupManagerPrivateKey getGroupManagerPrivateKey() {
		return groupManagerPrivateKey;
	}
	
}
