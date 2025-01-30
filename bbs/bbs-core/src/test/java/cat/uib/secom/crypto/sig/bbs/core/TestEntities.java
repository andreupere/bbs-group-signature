package cat.uib.secom.crypto.sig.bbs.core;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import cat.uib.secom.crypto.sig.bbs.core.engines.BBSEngine;
import cat.uib.secom.crypto.sig.bbs.core.engines.BBSEnginePrecomputation;
import cat.uib.secom.crypto.sig.bbs.core.engines.BBSEngineTraceable;
import cat.uib.secom.crypto.sig.bbs.core.exception.VerificationFailsException;
import cat.uib.secom.crypto.sig.bbs.core.impl.keys.helper.BBSGroupKeyPairImpl;
import cat.uib.secom.crypto.sig.bbs.core.impl.keys.BBSGroupPublicKeyImpl;
import cat.uib.secom.crypto.sig.bbs.core.impl.keys.BBSUserPrivateKeyImpl;
import cat.uib.secom.crypto.sig.bbs.core.signature.BBSSignature;
import cat.uib.secom.crypto.sig.bbs.core.accessors.enhanced.GroupManagerAccessor;
import cat.uib.secom.crypto.sig.bbs.core.accessors.enhanced.SignerAccessor;
import cat.uib.secom.crypto.sig.bbs.core.accessors.enhanced.VerifierAccessor;



public class TestEntities {
	
	private static GroupManagerAccessor groupManager;
	private static SignerAccessor signer, signer2;
	private static VerifierAccessor verifier;
	private static Integer numberUsers = 10;
	private static String message = "hello world";
	private static String CURVE_FILE_NAME = "a_181_603.param";
	private BBSSignature signature;
	
	private static Integer signerID = 5;
	private static Integer verifierID = 4;
	
	private static BBSGroupKeyPairImpl groupKeyPairSigner, groupKeyPairSigner2;
	private static BBSGroupKeyPairImpl groupKeyPairVerifier;
	
	
	/**
	 * Parameter deployment testing.
	 * */
	@BeforeClass
	public static void start() {
		// group manager is initialized with the number of the users of the group and the selected pairing file descriptor
		groupManager = new GroupManagerAccessor(numberUsers, CURVE_FILE_NAME);
		// group manager inits
		groupManager.setup();
		
		// get methods: get BBS parameters, group public key and user private key indexed by the signer ID (for instance, it is an Integer)
		groupManager.getBBSParameters();
		groupManager.getGroupPublicKey();
		groupManager.getUserPrivateKey(signerID);
		
		// the way to extract a group key pair composed by the group public key and the corresponding user private key
		groupKeyPairSigner = new BBSGroupKeyPairImpl( (BBSGroupPublicKeyImpl) groupManager.getGroupPublicKey(),
												  (BBSUserPrivateKeyImpl) groupManager.getUserPrivateKey(signerID));
		
		// the same for the verifier user
		groupKeyPairVerifier = new BBSGroupKeyPairImpl( (BBSGroupPublicKeyImpl) groupManager.getGroupPublicKey(),
				  									(BBSUserPrivateKeyImpl) groupManager.getUserPrivateKey(verifierID));
		
		// the same for another verifier user
		groupKeyPairSigner2 = new BBSGroupKeyPairImpl( (BBSGroupPublicKeyImpl) groupManager.getGroupPublicKey(),
				  								   (BBSUserPrivateKeyImpl) groupManager.getUserPrivateKey(verifierID));

		
	}
	
	/**
	 * Testing group signature generation and verification without enabling precomputation. Open procedure is also tested.
	 * */
	@Test
	public void processNoPrecomputation() {
		try {
			// start signer logic
			signer = new SignerAccessor( new BBSEngine( groupKeyPairSigner.getGroupPublicKey(), groupKeyPairSigner.getUserPrivateKey() ) );
			
			// start verifier logic
			verifier = new VerifierAccessor( new BBSEngine( groupKeyPairVerifier.getGroupPublicKey() ) );
			
			// group signature generation
			signature = signer.sign(message);
	
			// group signature verification
			boolean verification = verifier.verify(signature, message);
			
			Assert.assertTrue(verification);
		
		
		// open
		
			Integer idOpened = groupManager.open(message, signature);
			Assert.assertEquals(idOpened, signerID);
			
		} catch (VerificationFailsException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	
	/**
	 * Testing group signature generation and verification enabling precomputation. Open procedure is also tested.
	 * */
	@Test
	public void processPrecomputation() {
		try {
			// start signer logic with precomputation engine
			signer = new SignerAccessor( new BBSEnginePrecomputation( groupKeyPairSigner.getGroupPublicKey(), groupKeyPairSigner.getUserPrivateKey(), BBSEnginePrecomputation.SIGNER ) );
			
			// start verifier logic with precomputation engine
			verifier = new VerifierAccessor( new BBSEnginePrecomputation( groupKeyPairVerifier.getGroupPublicKey(), groupKeyPairVerifier.getUserPrivateKey(), BBSEnginePrecomputation.VERIFIER ) );
			
			// group signature generation
			signature = signer.sign(message);
			
			// group signature verification
			boolean verification = verifier.verify(signature, message);
			
			Assert.assertTrue(verification);
			
			// open
		
			Integer idOpened = groupManager.open(message, signature);
			Assert.assertEquals(idOpened, signerID);
			
		} catch (VerificationFailsException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
	
	
	/**
	 * Testing group signature generation and verification testing whether it is the same signer who signs twice.
	 * */
	@Test
	public void processTraceable() {
		try {
			// start signer logic
			signer = new SignerAccessor( new BBSEngineTraceable( groupKeyPairSigner.getGroupPublicKey(), groupKeyPairSigner.getUserPrivateKey() ) );
			
			
			// to verify the traceability, I create a new signer to force an error in the verifySameSigner method
			signer2 = new SignerAccessor( new BBSEngineTraceable( groupKeyPairSigner2.getGroupPublicKey(), groupKeyPairSigner2.getUserPrivateKey() ) );
			
			// start verifier logic
			verifier = new VerifierAccessor( new BBSEngineTraceable( groupKeyPairVerifier.getGroupPublicKey() ) );
			
			// group signature generation with traceability
			BBSSignature signature1 = signer.sign(message);
			BBSSignature signature2 = signer.sign(message);
			BBSSignature signature3 = signer2.sign(message);
			
			// group signature verification (over signature1)
			boolean verification = verifier.verify(signature1, message); 
			Assert.assertTrue(verification);
			
			// group signature verification (over signature2)
			verification = verifier.verify(signature2, message);
			Assert.assertTrue(verification);
			
			// verify same signer (verify traceability). I want sameSigner=TRUE	result
			boolean sameSigner = verifier.verifySameSigner(signature1, signature2);
			Assert.assertTrue(sameSigner);
			
			// verify same signer (verify traceability). Now, I want sameSigner=FALSE result
			sameSigner = verifier.verifySameSigner(signature1, signature3);
			Assert.assertFalse(sameSigner);
			
		
		} catch (VerificationFailsException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}


}
