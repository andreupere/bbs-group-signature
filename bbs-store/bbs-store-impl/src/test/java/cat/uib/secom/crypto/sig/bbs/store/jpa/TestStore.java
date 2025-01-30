package cat.uib.secom.crypto.sig.bbs.store.jpa;




import java.io.File;
import java.io.StringWriter;

import org.simpleframework.xml.Serializer;
import org.simpleframework.xml.core.Persister;

import junit.framework.TestCase;


import cat.uib.secom.utils.crypto.RandomGenerator;
import cat.uib.secom.crypto.sig.bbs.core.accessors.enhanced.GroupManagerAccessor;
import cat.uib.secom.crypto.sig.bbs.store.entities.bean.BBSGroupPublicKeyBean;
import cat.uib.secom.crypto.sig.bbs.store.exceptions.NoMoreAvailableKeysException;
import cat.uib.secom.crypto.sig.bbs.store.exceptions.UserAlreadyServedException;
import cat.uib.secom.crypto.sig.bbs.store.jpa.business.GroupManagerEntityManagerBean;
import cat.uib.secom.crypto.sig.bbs.store.jpa.entities.impl.KeyPairDB;
import cat.uib.secom.crypto.sig.bbs.store.logic.GroupManagerLogic;
import cat.uib.secom.crypto.sig.bbs.store.jpa.util.Conveter;


/**
 * @author Andreu Pere
 * Test about Hibernate connection to database and set objects
 * */
public class TestStore extends TestCase {
	
	protected String message = "hello world";
	protected int n = 10;
	protected String CURVE_FILE_NAME = "d840347-175-161.param";
	protected GroupManagerAccessor gma;
	protected GroupManagerEntityManagerBean store;
	
	public TestStore() {
		// deploy group PK, users SK and private group manager elements
		gma = GroupManagerLogic.initGroup(n, CURVE_FILE_NAME);
		
	}

	
	public void testStoreUserKeys() {
		store = new GroupManagerEntityManagerBean("testingBBSmysql-PU");
		
		store.storeGroupData( gma );
		
		// check number of generated user keys
		assertEquals("number of users? ", gma.getUserPrivateKeys().size(), n);
	}
	
	public void testIssueKey() {
		KeyPairDB keyPairDB = null;
		store = new GroupManagerEntityManagerBean("testingBBSmysql-PU");
		
		
		try {
			String uIdentity  = "hola_som_jo";
			keyPairDB = store.issueKeyPair( uIdentity );
			
			keyPairDB.getGroupPublicKeyDB().getGroupPublicKey();
			Serializer serializer = new Persister();
			BBSGroupPublicKeyBean gpkb = new BBSGroupPublicKeyBean();
			gpkb = keyPairDB.getGroupPublicKeyDB().getGroupPublicKey().toBean();
			
			File result = new File("proves.xml");
			
			try {
				serializer.write(gpkb, result);
				System.out.println(result.getAbsolutePath());
				
				BBSGroupPublicKeyBean gpkb2 = serializer.read(BBSGroupPublicKeyBean.class, result);
				System.out.println("g1 after deserialization " + gpkb2.getG1() );
				
			} catch (Exception e) {
				e.printStackTrace();
			}
			
			
			assertEquals("same uIdentity? ", keyPairDB.getUserPrivateKeyDB().getuIdentity(), uIdentity );
			assertTrue("key issued? ", keyPairDB.getUserPrivateKeyDB().isIssued() );
		} catch (UserAlreadyServedException e) {
			e.printStackTrace();
		} catch (NoMoreAvailableKeysException e) {
			e.printStackTrace();
		}
	}
	

	public void testReIssueKey() {
		
		
		KeyPairDB keyPairDB = null;
		store = new GroupManagerEntityManagerBean("testingBBSmysql-PU");
		

		try {
			String uIdentity  = "hola_som_jo";
			keyPairDB = store.issueKeyPair( uIdentity );
			fail("UserAlreadyServedException should be thrown here...");
			//assertEquals("same uIdentity? ", keyPairDB.getUserPrivateKeyDB().getuIdentity(), uIdentity );
			//assertTrue("key issued? ", keyPairDB.getUserPrivateKeyDB().isIssued() );
		} catch (UserAlreadyServedException e) {
			e.printStackTrace();
		} catch (NoMoreAvailableKeysException e) {
			e.printStackTrace();
		}
	}
	
	
	public void testIssueAllKeys() {
		// consuming all remaining user private keys
		KeyPairDB keyPairDB = null;
		
		store = new GroupManagerEntityManagerBean("testingBBSmysql-PU");
		
		int a = 1;
		while (a<n+1) {
			try {
				
				keyPairDB = store.issueKeyPair( (new Integer(a)).toString() );
				
			} catch(NoMoreAvailableKeysException e) {
				System.out.println("There are not more available user private keys for this group...");
			} catch(UserAlreadyServedException e) {
				System.out.println("The user " + a + " is already served by me...");
			} catch(Exception e) {
				e.printStackTrace();
			}
			a++;
		}
		
		
	}
	
	

}



