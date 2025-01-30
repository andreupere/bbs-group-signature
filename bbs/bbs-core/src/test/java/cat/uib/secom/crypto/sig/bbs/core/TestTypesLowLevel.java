package cat.uib.secom.crypto.sig.bbs.core;

import it.unisa.dia.gas.jpbc.Element;

import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;

import java.math.BigInteger;
import java.util.HashMap;

import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Ignore;


import cat.uib.secom.crypto.sig.bbs.core.generators.BBSGroupKeyGenerator;
import cat.uib.secom.crypto.sig.bbs.core.generators.BBSKeyPairGenerator;
import cat.uib.secom.crypto.sig.bbs.core.impl.keys.BBSGroupPublicKeyImpl;
import cat.uib.secom.crypto.sig.bbs.core.parameters.BBSKeyGenerationParameters;
import cat.uib.secom.crypto.sig.bbs.core.parameters.BBSParameters;

public class TestTypesLowLevel {
	
	private static BBSGroupKeyGenerator bbsGroupKeyGenerator;
	private static HashMap<Integer, AsymmetricCipherKeyPair> hm;
	
	@BeforeClass
	public static void start() {
		
		int n = 10;
		BBSParameters bbsParameters = new BBSParameters("a_181_603.param", n);
		bbsParameters.generate();
		
		bbsGroupKeyGenerator = new BBSGroupKeyGenerator(bbsParameters);
		bbsGroupKeyGenerator.generate();
		
		BBSKeyGenerationParameters bbsKGP = new BBSKeyGenerationParameters(bbsParameters,
													bbsGroupKeyGenerator.getBBSGroupPublicKey(),
													bbsGroupKeyGenerator.getBBSGroupManagerPrivateKey(),
													bbsGroupKeyGenerator.getBBSGroupManagerPrivateElements());
		
		BBSKeyPairGenerator bbsKeyPairGenerator = new BBSKeyPairGenerator();
		bbsKeyPairGenerator.init(bbsKGP);
		
		hm = new HashMap<Integer, AsymmetricCipherKeyPair>(bbsParameters.getNumberUsers(), (float) 0.75);
		
		int i = 1;
		while ( i <= bbsParameters.getNumberUsers() ) {
			// each user key pair (group PK and user SK)
			AsymmetricCipherKeyPair keyPair = bbsKeyPairGenerator.generateKeyPair();
			hm.put(i, keyPair);
			i++;
		}
		
	}
	
	@Ignore("not using")
	@Test
	public void testTypes() {		
		
		BBSGroupPublicKeyImpl gpk = bbsGroupKeyGenerator.getBBSGroupPublicKey();
		Element g1 = gpk.getG1().getElement();
		System.out.println("g1 is " + g1.getClass().getName() + " (" + g1 + ")");
		// cast to CurveElement
		CurveElement ce = ( (CurveElement)gpk.getG1().getElement() );
		// get X coordinate
		Element xCoordinate = ce.getX();
		System.out.println("x is " + xCoordinate.getClass().getName() + " (" + ce.getX() + ")");
		// CurveElement to bytes (to store in the BBDD)
		byte[] ceByte = ce.toBytes();
		// CurveElement to BigInteger
		//BigInteger bi = ce.toBigInteger(); // not implemented
		// CurveElement to BigInteger through byte[]
		BigInteger bi = new BigInteger(ceByte);
		System.out.println("bi is " + bi.getClass().getName() + " (" + bi + ")");
		//byte[] bbb = bi.toByteArray();
		
		// SEND TO NETWORK
		// create new curve element from byte[]
		CurveElement<?> ceRenew = (CurveElement<?>) gpk.getG1().getElement().setToOne();
		// regenerate initial CurveElement
		ceRenew.setFromBytes(ceByte); 
		System.out.println("ceRenew is " + ceRenew.getClass().getName() + " " + ceRenew );
		
		// create new curve element from BigInteger
		CurveElement ceRenew2 = (CurveElement) gpk.getG1().getElement().setToOne();
		byte[] biByte = bi.toByteArray();
		ceRenew2.setFromBytes(biByte);
		System.out.println("ceRenew2 is " + ceRenew2.getClass().getName() + " " + ceRenew2 );
		
		Assert.assertTrue( g1.isEqual(ceRenew2) );
		Assert.assertTrue( g1.isEqual(ceRenew) );
		Assert.assertTrue( ceRenew.isEqual(ceRenew2) );
		
		

		// simulate the situation where client receives a set of BigIntegers representing the object group public key
		
		// elements to bytes (this will be stored in the manager database)
		byte[] g1r = gpk.getG1().toByteArray();
		byte[] g2r = gpk.getG2().toByteArray();
		byte[] hre = gpk.getH().toByteArray();
		byte[] ure = gpk.getU().toByteArray();
		byte[] vre = gpk.getV().toByteArray();
		byte[] omegar = gpk.getOmega().toByteArray();
		
		// the client receive BigIntegers, so simulate it
		BigInteger g1b = new BigInteger(g1r);
		BigInteger g2b = new BigInteger(g2r);
		BigInteger hb = new BigInteger(hre);
		BigInteger ub = new BigInteger(ure);
		BigInteger vb = new BigInteger(vre);
		BigInteger omegab = new BigInteger(omegar);
		
		// till here is the manager side
		
		// SEND TO NETWORK
		
		// now is the client side
		
		// rebuild BBSParameters in the client side
		BBSParameters bbsParameters = new BBSParameters("a_181_603.param");
		bbsParameters.generate(g1r, g2r);
		// now the client side has access to pairing field and g1 and g2 are set
		
		// rebuild the group public key in the client side
		BBSGroupPublicKeyImpl gpkr = new BBSGroupPublicKeyImpl(g1b,
															   g2b,
															   hb,
															   ub,
															   vb,
															   omegab,
															   bbsParameters.getPairing());
		
		
		Assert.assertTrue( gpk.getG1().getElement().isEqual(gpkr.getG1().getElement()) );
		Assert.assertTrue( gpk.getG2().getElement().isEqual(gpkr.getG2().getElement()) );
		Assert.assertTrue( gpk.getH().getElement().isEqual(gpkr.getH().getElement()) );
		Assert.assertTrue( gpk.getU().getElement().isEqual(gpkr.getU().getElement()) );
		Assert.assertTrue( gpk.getV().getElement().isEqual(gpkr.getV().getElement()) );
		Assert.assertTrue( gpk.getOmega().getElement().isEqual(gpkr.getOmega().getElement()) );
		
	}


	

}
