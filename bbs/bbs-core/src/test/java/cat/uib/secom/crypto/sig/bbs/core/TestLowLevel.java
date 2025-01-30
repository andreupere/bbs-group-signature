package cat.uib.secom.crypto.sig.bbs.core;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;



import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.Assert;
import org.junit.Test;

import cat.uib.secom.crypto.sig.bbs.core.engines.BBSEngine;
import cat.uib.secom.crypto.sig.bbs.core.engines.BBSEnginePrecomputation;
import cat.uib.secom.crypto.sig.bbs.core.engines.BBSEngineTraceable;
import cat.uib.secom.crypto.sig.bbs.core.generators.BBSGroupKeyGenerator;
import cat.uib.secom.crypto.sig.bbs.core.generators.BBSKeyPairGenerator;
import cat.uib.secom.crypto.sig.bbs.core.keys.BBSGroupPublicKey;
import cat.uib.secom.crypto.sig.bbs.core.keys.BBSUserPrivateKey;
import cat.uib.secom.crypto.sig.bbs.core.signature.BBSSignature;
import cat.uib.secom.crypto.sig.bbs.core.parameters.BBSKeyGenerationParameters;
import cat.uib.secom.crypto.sig.bbs.core.parameters.BBSParameters;

public class TestLowLevel {

	@Test
	public void deploySignVerifyOpen() {
		int n = 10;
		String message = "Holaaaaa";
		//byte[] message = "Holaaaaa".getBytes();
		
		BBSParameters bbsParameters = new BBSParameters("a_181_603.param", n);
		bbsParameters.generate();
		
		BBSGroupKeyGenerator bbsGroupKeyGenerator = new BBSGroupKeyGenerator(bbsParameters);
		bbsGroupKeyGenerator.generate();
		
		BBSKeyGenerationParameters bbsKGP = new BBSKeyGenerationParameters(bbsParameters,
													bbsGroupKeyGenerator.getBBSGroupPublicKey(),
													bbsGroupKeyGenerator.getBBSGroupManagerPrivateKey(),
													bbsGroupKeyGenerator.getBBSGroupManagerPrivateElements());
		
		BBSKeyPairGenerator bbsKeyPairGenerator = new BBSKeyPairGenerator();
		bbsKeyPairGenerator.init(bbsKGP);
		
		System.out.println("\n\n ** Start generation of key pair for " + bbsParameters.getNumberUsers()  + " users ** \n");
		
		HashMap<Integer, AsymmetricCipherKeyPair> hm = new HashMap<Integer, AsymmetricCipherKeyPair>(bbsParameters.getNumberUsers(), (float) 0.75);
		
		int i = 1;
		while ( i <= bbsParameters.getNumberUsers() ) {
			// each user key pair (group PK and user SK)
			AsymmetricCipherKeyPair keyPair = bbsKeyPairGenerator.generateKeyPair();
			hm.put(i, keyPair);
			i++;
		}
		
		System.out.println("\n\n ** End generation of key pairs ** \n");
		
		Set<Integer> s = hm.keySet();
		Iterator<Integer> it = s.iterator();
		while (it.hasNext()) {
			Integer key = (Integer) it.next();
			AsymmetricCipherKeyPair ackp = hm.get(key);
			
			System.out.println("key: " + key + " value: (PKg: " + ackp.getPublic() + ") (SKui: " + ackp.getPrivate() + ")");
			
		}
		
		System.out.println("GroupManagerPrivateKey: " + bbsGroupKeyGenerator.getBBSGroupManagerPrivateKey());
		System.out.println("GroupManagerPrivateElements: " + bbsGroupKeyGenerator.getBBSGroupManagerPrivateElements());
		
		
				
		AsymmetricCipherKeyPair user1KeyPair = hm.get(1);
		AsymmetricCipherKeyPair user2KeyPair = hm.get(2);
		
		
		try {
			System.out.println("Signature and verification without precomputation");
			long initEngine = System.currentTimeMillis();
			BBSEngine bbsEngine1 = new BBSEngine((BBSGroupPublicKey) user1KeyPair.getPublic(), (BBSUserPrivateKey) user1KeyPair.getPrivate());
			long initSignature = System.currentTimeMillis();
			BBSSignature signature = bbsEngine1.sign(message);
			long initEngine2 = System.currentTimeMillis();
			BBSEngine bbsEngine2 = new BBSEngine((BBSGroupPublicKey)user2KeyPair.getPublic(), (BBSUserPrivateKey)user2KeyPair.getPrivate());
			long initVerification = System.currentTimeMillis();
			boolean verification = bbsEngine2.verify(signature, message);
			System.out.println("initEngine: " + (initSignature - initEngine) + "ms; " +
							   "sign: " + (initEngine2 - initSignature) + "ms; " +
							   "verification: " + (System.currentTimeMillis() - initVerification ) + "ms");
			Assert.assertTrue(verification);
			
			
			
			
			System.out.println("Signature and verification with precomputation");
			initEngine = System.currentTimeMillis();
			BBSEnginePrecomputation bbsepre1 = new BBSEnginePrecomputation((BBSGroupPublicKey) user1KeyPair.getPublic(), (BBSUserPrivateKey) user1KeyPair.getPrivate());
			initSignature = System.currentTimeMillis();
			BBSSignature sig = bbsepre1.sign(message);
			initEngine2 = System.currentTimeMillis();
			BBSEnginePrecomputation bbsepre2 = new BBSEnginePrecomputation((BBSGroupPublicKey)user2KeyPair.getPublic(), (BBSUserPrivateKey)user2KeyPair.getPrivate());
			initVerification = System.currentTimeMillis();
			verification = bbsepre2.verify(sig, message);
			System.out.println("initEngine: " + (initSignature - initEngine) + "ms; " +
					   		   "sign: " + (initEngine2 - initSignature) + "ms; " +
					   		   "verification: " + (System.currentTimeMillis() - initVerification ) + "ms");
			Assert.assertTrue(verification);
			
			
			
			
			
			System.out.println("Traceable signature: signature, 2n signature (traceable) and verification");
			BBSEngineTraceable bbset = new BBSEngineTraceable((BBSGroupPublicKey)user2KeyPair.getPublic(), (BBSUserPrivateKey)user2KeyPair.getPrivate());
		
			BBSSignature entranceSignature = bbset.sign(message);		
			BBSSignature exitSignature = bbset.sign(message);
			
			BBSEngineTraceable bbset2 = new BBSEngineTraceable((BBSGroupPublicKey)user2KeyPair.getPublic());
			boolean b1 = bbset2.verify(exitSignature, message);
			boolean b2 = bbset2.verify(entranceSignature, message);
			boolean b3 = bbset2.verifySameSigner(entranceSignature, exitSignature);
			
			Assert.assertTrue(b1);
			Assert.assertTrue(b2);
			Assert.assertTrue(b3);
			
		} catch (Exception e) {
			e.printStackTrace();
		} 
		
		
	}
}
