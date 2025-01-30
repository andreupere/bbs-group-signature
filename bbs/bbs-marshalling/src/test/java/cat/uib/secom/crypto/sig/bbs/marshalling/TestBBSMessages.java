package cat.uib.secom.crypto.sig.bbs.marshalling;

import org.junit.BeforeClass;
import org.junit.Test;

import cat.uib.secom.crypto.sig.bbs.core.accessors.enhanced.GroupManagerAccessor;
import cat.uib.secom.crypto.sig.bbs.core.accessors.enhanced.SignerAccessor;
import cat.uib.secom.crypto.sig.bbs.core.engines.BBSEngine;
import cat.uib.secom.crypto.sig.bbs.core.impl.keys.helper.BBSGroupKeyPairImpl;
import cat.uib.secom.crypto.sig.bbs.core.impl.keys.BBSGroupPublicKeyImpl;
import cat.uib.secom.crypto.sig.bbs.core.impl.keys.BBSUserPrivateKeyImpl;
import cat.uib.secom.crypto.sig.bbs.core.impl.signature.BBSSignatureImpl;
import cat.uib.secom.crypto.sig.bbs.core.parameters.BBSParameters;
import cat.uib.secom.crypto.sig.bbs.marshalling.BBSGroupKeyPairMSG;
import cat.uib.secom.crypto.sig.bbs.marshalling.BBSGroupPublicKeyMSG;
import cat.uib.secom.crypto.sig.bbs.marshalling.BBSSignatureMSG;
import cat.uib.secom.crypto.sig.bbs.marshalling.utils.Constants;
import cat.uib.secom.utils.strings.MSGFormatConstants;
import junit.framework.Assert;

/**
 * Testing serialization and deserialization of different messages generated using the BBS group signature from bbs-core project
 * */
public class TestBBSMessages {
	
	private static GroupManagerAccessor groupManager;
	private SignerAccessor signer;
	private static String curve = "dtype_q175_r167.param";
	
	private BBSSignatureImpl bbsSignatureImpl;
	private String message = "hello world BBS signature scheme";
	
	private static BBSGroupKeyPairImpl gkPair;
	private static BBSParameters bbsParameters;
	
	
	/**
	 * Parameter deploying
	 * */
	@BeforeClass
	public static void start() {
		groupManager = new GroupManagerAccessor(2, curve);
		groupManager.setup();
		
		gkPair = new BBSGroupKeyPairImpl( (BBSGroupPublicKeyImpl) groupManager.getGroupPublicKey(),
									  (BBSUserPrivateKeyImpl) groupManager.getUserPrivateKey(1));
		
		bbsParameters = groupManager.getBBSParameters();
		
	}
	
	
	/**
	 * Testing the signature generation and serialization to XML.
	 * 
	 * Testing the signature deserialization from XML to the corresponding object, comparing whether an element from the original
	 * signature is the same as in the deserialized object
	 * */
	@Test
	public void BBSSignature() {
		 
		signer = new SignerAccessor( new BBSEngine(gkPair.getGroupPublicKey(),
									 			   gkPair.getUserPrivateKey()));

		
		try {
			System.out.println("Testing BBSSignatureImpl and BBSSignatureMSG conversions with XML");
			
			bbsSignatureImpl = (BBSSignatureImpl) signer.sign(message);

			//BBSSignatureMSG sigMSG = new BBSSignatureMSG(signature);
			BBSSignatureMSG sigMSG = (BBSSignatureMSG) BBSReaderFactory.getBBSMSG(bbsSignatureImpl);
			byte[] sigMSGByteArray = sigMSG.serialize( MSGFormatConstants.XML );
			
			String msg = new String(sigMSGByteArray);
			System.out.println( msg );
			
			// sending through network
			
			BBSSignatureMSG sigMSGReceived = new BBSSignatureMSG();
			sigMSGReceived = (BBSSignatureMSG) sigMSGReceived.deSerialize( sigMSGByteArray, MSGFormatConstants.XML);
			BBSSignatureImpl rebuildBBSSignatureImpl = (BBSSignatureImpl) BBSReaderFactory.getBBS(sigMSGReceived, bbsParameters);
			
//			BBSSignatureImpl rebuiltSignature = (BBSSignatureImpl) sigMSGReceived.toObject(msg, 
//																			 			   bbsParameters);
			
			Assert.assertEquals(rebuildBBSSignatureImpl.getT1().toHexString(), 
						 		bbsSignatureImpl.getT1().toHexString());
			
			
			
			System.out.println("Testing BBSSignatureImpl and BBSSignatureMSG conversions with ASN1");
			// ASN1
			//byte[] b = sigMSG.encodeASN1();
			//byte[] b = sigMSG.serialize( Constants.ASN1 );
			sigMSGByteArray = sigMSG.serialize( MSGFormatConstants.ASN1 );
			// sending through network
			//BBSSignatureMSG sigASN1 = new BBSSignatureMSG();
			sigMSGReceived = (BBSSignatureMSG) sigMSGReceived.deSerialize( sigMSGByteArray , MSGFormatConstants.ASN1);
			//sigASN1.decodeASN1( sigMSGByteArray );
			//BBSSignatureImpl s = (BBSSignatureImpl) sigASN1.toObject(bbsParameters);
			rebuildBBSSignatureImpl = (BBSSignatureImpl) BBSReaderFactory.getBBS(sigMSGReceived, bbsParameters);
			
			sigMSGReceived.printASN1();
			
			Assert.assertEquals(bbsSignatureImpl.getT1().toHexString(), rebuildBBSSignatureImpl.getT1().toHexString());
			Assert.assertEquals(bbsSignatureImpl.getT2().toHexString(), rebuildBBSSignatureImpl.getT2().toHexString());
			Assert.assertEquals(bbsSignatureImpl.getT3().toHexString(), rebuildBBSSignatureImpl.getT3().toHexString());
			Assert.assertEquals(bbsSignatureImpl.getC().toHexString(), rebuildBBSSignatureImpl.getC().toHexString());
			Assert.assertEquals(bbsSignatureImpl.getSalpha().toHexString(), rebuildBBSSignatureImpl.getSalpha().toHexString());
			Assert.assertEquals(bbsSignatureImpl.getSbeta().toHexString(), rebuildBBSSignatureImpl.getSbeta().toHexString());
			Assert.assertEquals(bbsSignatureImpl.getSx().toHexString(), rebuildBBSSignatureImpl.getSx().toHexString());
			Assert.assertEquals(bbsSignatureImpl.getSdelta1().toHexString(), rebuildBBSSignatureImpl.getSdelta1().toHexString());
			Assert.assertEquals(bbsSignatureImpl.getSdelta2().toHexString(), rebuildBBSSignatureImpl.getSdelta2().toHexString());
			
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	
	/**
	 * Testing the group public key generation and serialization to XML
	 * 
	 * 
	 * */
	@Test
	public void groupPublicKey() {

		
		try {
			
			System.out.println("Testing BBSGroupPublicKeyImpl and BBSGroupPublicKeyMSG conversions with XML");
			//String xml = gpkXML.toXML(); 
			//System.out.println( xml );
			
			BBSGroupPublicKeyImpl gpkImpl = gkPair.getGroupPublicKey(); 
			BBSGroupPublicKeyMSG gpkMSG = (BBSGroupPublicKeyMSG) BBSReaderFactory.getBBSMSG(gpkImpl);
			
			byte[] gpkMSGByteArray = gpkMSG.serialize(MSGFormatConstants.XML);
			System.out.println( new String(gpkMSGByteArray) );
			
			// enviat per xarxa
			
			BBSGroupPublicKeyMSG gpkMSGReceived = new BBSGroupPublicKeyMSG();
			gpkMSGReceived = (BBSGroupPublicKeyMSG) gpkMSGReceived.deSerialize(gpkMSGByteArray, MSGFormatConstants.XML);
			//BBSGroupPublicKey gpk = (BBSGroupPublicKey) gpkXMLReceived.toObject(xml, bbsParameters);
			//BBSGroupPublicKeyImpl gpk = (BBSGroupPublicKeyImpl) gpkMSGReceived.deSerialize(b, Constants.XML, bbsParameters);
			BBSGroupPublicKeyImpl rebuildGPKImpl = (BBSGroupPublicKeyImpl) BBSReaderFactory.getBBS(gpkMSGReceived, bbsParameters);
			
			Assert.assertEquals(rebuildGPKImpl.getOmega().toHexString(), 
								gkPair.getGroupPublicKey().getOmega().toHexString());
			
			
			
			System.out.println("Testing BBSGroupPublicKeyImpl and BBSGroupPublicKeyMSG conversions with ASN1");
			
			///byte[] b2 = gpkXML.encodeASN1();
			gpkMSGByteArray = gpkMSG.serialize( MSGFormatConstants.ASN1 );
			// sending through network
			gpkMSGReceived =  (BBSGroupPublicKeyMSG) gpkMSGReceived.deSerialize(gpkMSGByteArray, MSGFormatConstants.ASN1);
			//gpkASN1.decodeASN1(b);
			//gpk = (BBSGroupPublicKey) gpkASN1.toObject(bbsParameters);
			
			rebuildGPKImpl = (BBSGroupPublicKeyImpl) BBSReaderFactory.getBBS(gpkMSGReceived, bbsParameters);
			
			Assert.assertEquals(rebuildGPKImpl.getOmega().toHexString(), gkPair.getGroupPublicKey().getOmega().toHexString());
			
			gpkMSGReceived.printASN1();
			
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Testing the group key pair generation and serialization to XML
	 * */
	@Test
	public void groupKeyPair() {
		
		try {
			
			System.out.println("Testing BBSGroupPublicKeyImpl and BBSGroupPublicKeyMSG conversions with XML");
			BBSGroupKeyPairMSG gkpMSG = (BBSGroupKeyPairMSG) BBSReaderFactory.getBBSMSG(gkPair);
			
			//BBSGroupKeyPairMSG gkp = new BBSGroupKeyPairMSG(gkPair.getGroupPublicKey(), gkPair.getUserPrivateKey());
			
			byte[] gkpMSGByteArray = gkpMSG.serialize(MSGFormatConstants.XML);
			System.out.println(new String(gkpMSGByteArray));
			
			// enviat per xarxa
			
			BBSGroupKeyPairMSG gkpMSGReceived = new BBSGroupKeyPairMSG();
			gkpMSGReceived = (BBSGroupKeyPairMSG) gkpMSGReceived.deSerialize(gkpMSGByteArray, MSGFormatConstants.XML);//.toObject(xml, bbsParameters);
			BBSGroupKeyPairImpl gpkImpl = (BBSGroupKeyPairImpl) BBSReaderFactory.getBBS(gkpMSGReceived, bbsParameters);
			
			Assert.assertEquals(gpkImpl.getGroupPublicKey().getH().toHexString(),
								gkPair.getGroupPublicKey().getH().toHexString());
			
			

			
			System.out.println("Testing BBSGroupPublicKeyImpl and BBSGroupPublicKeyMSG conversions with ASN1");
			
			gkpMSGByteArray = gkpMSG.serialize(MSGFormatConstants.ASN1);
			
			// enviat per xarxa
			
			gkpMSGReceived = new BBSGroupKeyPairMSG();
			gkpMSGReceived = (BBSGroupKeyPairMSG) gkpMSGReceived.deSerialize(gkpMSGByteArray, MSGFormatConstants.ASN1);
			//gkPairRebuilt = (BBSGroupKeyPairImpl) gkp.deSerialize(b2, Constants.ASN1, bbsParameters);
			gpkImpl = (BBSGroupKeyPairImpl) BBSReaderFactory.getBBS(gkpMSGReceived, bbsParameters);
			
			gkpMSGReceived.printASN1();
			
			Assert.assertEquals(gpkImpl.getUserPrivateKey().getA().toHexString(), 
								gkPair.getUserPrivateKey().getA().toHexString());
			
			
		} catch(Exception e) {
			e.printStackTrace();
		}
		
	}
	
	
	
	

}
