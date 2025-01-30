package cat.uib.secom.crypto.sig.bbs.store.jpa.entities.impl;


import java.util.Date;

import javax.persistence.Column;
import javax.persistence.DiscriminatorColumn;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Embedded;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;
import javax.persistence.Temporal;

import cat.uib.secom.crypto.sig.bbs.store.jpa.embeddable.impl.EmbeddableBBSUserPrivateKey;



/**
 * @author Andreu Pere
 * 
 * Entity object that represents the user private key structure in the database.
 * The user private key definition is stored as byte[] (Ai and xi, where i is a user number).
 * It also has get methods returning BigInteger for Ai and xi parameters
 * 
 * It contains NamedQueries to query the database
 * 
 * @see GroupPublicKeyDB
 * */
@Entity
@Table(name="GROUP_MANAGER_USER_PRIVATE_KEY")
@NamedQueries({
@NamedQuery(name="isIssued",
		query="SELECT u FROM UserPrivateKeyDB u WHERE u.uIdentity = ?1"),
@NamedQuery(name="issueKeyPair",
		query="SELECT u FROM UserPrivateKeyDB u WHERE u.issued = false"),
@NamedQuery(name="open",
		query="SELECT u FROM UserPrivateKeyDB u WHERE u.userPrivateKey.ai = ?1")
})
@Inheritance(strategy = InheritanceType.SINGLE_TABLE)
@DiscriminatorColumn(name="DISC", discriminatorType=javax.persistence.DiscriminatorType.STRING)
@DiscriminatorValue("USER_PRIVATE_KEY_DB")
public class UserPrivateKeyDB {

	/**
	 * Primary key for this entity (table), so it is unique and the ID generation
	 * is delegated to the underlying database manager
	 * */
	@Id
	@GeneratedValue
	@Column(name="ID")
	private long id;
	
	
	// User Private Key definition
	@Embedded
	private EmbeddableBBSUserPrivateKey userPrivateKey;
	

	
	
	// relation to group key
	/**
	 * Many to one relation to the related group public key. 
	 * This will be translated into a column in this database table storing the id of
	 * the group public key.
	 * */
	@ManyToOne
	@JoinColumn(name="GROUP_PUBLIC_KEY_ID_FK", nullable=false)
	private GroupPublicKeyDB group;
	
	/**
	 * It marks if the user private key is already issued
	 * */
	@Column(name="IS_ISSUED")
	private boolean issued;
	
	/**
	 * It stores the user identity who has the user private key
	 * */
	@Column(name="USER_IDENTITY")
	private String uIdentity;
	
	/**
	 * It stores the date when this key was issued
	 * */
	@Temporal(javax.persistence.TemporalType.TIMESTAMP)
	@Column(name="ISSUE_DATE")
	private Date dateIssued;
	
	/**
	 * It marks if the user private key is revoked
	 * */
	@Column(name="IS_REVOKED")
	private boolean revoked;

	
	
	public long getId() {
		return id;
	}
	public void setId(long id) {
		this.id = id;
	}
	
	
	public void setGroupManager(GroupPublicKeyDB group) {
		this.group = group;
	}
	public GroupPublicKeyDB getGroupPublicKeyDB() {
		return group;
	}

	
	public boolean isIssued() {
		return issued;
	}
	public void setIssued(boolean issued) {
		this.issued = issued;
	}

	
	public void setuIdentity(String uIdentity) {
		this.uIdentity = uIdentity;
	}
	public String getuIdentity() {
		return uIdentity;
	}


	
	public void setDateIssued(Date dateIssued) {
		this.dateIssued = dateIssued;
	}

	public Date getDateIssued() {
		return dateIssued;
	}

	
	public void setRevoked(boolean revoked) {
		this.revoked = revoked;
	}
	public boolean isRevoked() {
		return revoked;
	}
	
	
	
	public void setUserPrivateKey(EmbeddableBBSUserPrivateKey userPrivateKey) {
		this.userPrivateKey = userPrivateKey;
	}
	public EmbeddableBBSUserPrivateKey getUserPrivateKey() {
		return userPrivateKey;
	}
	public String toString() {
		String r = "User: {id:" + id + "; uIdentity: " + uIdentity + "; revoked: " + revoked + "; issued: "+ issued + "}";
		return r;
	}

	
}
