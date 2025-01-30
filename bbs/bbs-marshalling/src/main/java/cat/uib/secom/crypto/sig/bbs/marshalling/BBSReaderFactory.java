package cat.uib.secom.crypto.sig.bbs.marshalling;


import cat.uib.secom.crypto.sig.bbs.core.impl.keys.BBSGroupPublicKeyImpl;
import cat.uib.secom.crypto.sig.bbs.core.impl.keys.BBSUserPrivateKeyImpl;
import cat.uib.secom.crypto.sig.bbs.core.impl.keys.helper.BBSGroupKeyPairImpl;
import cat.uib.secom.crypto.sig.bbs.core.impl.signature.BBSSignatureImpl;
import cat.uib.secom.crypto.sig.bbs.core.parameters.BBSParameters;
import cat.uib.secom.crypto.sig.bbs.marshalling.AbstractBBSMSG;
import cat.uib.secom.crypto.sig.bbs.marshalling.BBSGroupPublicKeyMSG;
import cat.uib.secom.crypto.sig.bbs.marshalling.BBSSignatureMSG;
import cat.uib.secom.crypto.sig.bbs.marshalling.BBSUserPrivateKeyMSG;

public class BBSReaderFactory {

	public static AbstractBBSMSG getBBSMSG(Object bbsObject) throws Exception {
		
		if (bbsObject instanceof BBSGroupPublicKeyImpl)
			return new BBSGroupPublicKeyMSG( (BBSGroupPublicKeyImpl) bbsObject);
		
		else if (bbsObject instanceof BBSUserPrivateKeyImpl)
			return new BBSUserPrivateKeyMSG( (BBSUserPrivateKeyImpl) bbsObject );
		
		else if (bbsObject instanceof BBSSignatureImpl)
			return new BBSSignatureMSG( (BBSSignatureImpl) bbsObject );
		
		else if (bbsObject instanceof BBSGroupKeyPairImpl)
			return new BBSGroupKeyPairMSG( (BBSGroupKeyPairImpl) bbsObject );
		
		else
			throw new Exception("I do not know the provided object type...");
	}
	
	
	
	public static Object getBBS(AbstractBBSMSG bbsMSGObject, BBSParameters bbsParameters) throws Exception {
		
		if (bbsMSGObject instanceof BBSGroupPublicKeyMSG)
			return (BBSGroupPublicKeyImpl) bbsMSGObject.toObject(bbsParameters);
		
		else if (bbsMSGObject instanceof BBSUserPrivateKeyMSG)
			return (BBSUserPrivateKeyImpl) bbsMSGObject.toObject(bbsParameters);
		
		else if (bbsMSGObject instanceof BBSSignatureMSG)
			return (BBSSignatureImpl) bbsMSGObject.toObject(bbsParameters);
		
		else if (bbsMSGObject instanceof BBSGroupKeyPairMSG)
			return (BBSGroupKeyPairImpl) bbsMSGObject.toObject(bbsParameters);
		
		else
			throw new Exception("I do not know the provided object type...");

	}
	
}
