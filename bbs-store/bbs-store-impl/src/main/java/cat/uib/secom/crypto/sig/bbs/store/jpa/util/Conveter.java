package cat.uib.secom.crypto.sig.bbs.store.jpa.util;

import cat.uib.secom.crypto.sig.bbs.store.entities.BBSGroupPublicKey;
import cat.uib.secom.crypto.sig.bbs.store.entities.BBSSignature;
import cat.uib.secom.crypto.sig.bbs.store.entities.BBSUserPrivateKey;
import cat.uib.secom.crypto.sig.bbs.store.entities.bean.BBSGroupPublicKeyBean;
import cat.uib.secom.crypto.sig.bbs.store.entities.bean.BBSSignatureBean;
import cat.uib.secom.crypto.sig.bbs.store.entities.bean.BBSUserPrivateKeyBean;

public class Conveter {

	public static BBSSignature convert(BBSSignatureBean signatureBean, BBSSignature signature) {
		
		signature.setT1( signatureBean.getT1() );
		signature.setT2( signatureBean.getT2() );
		signature.setT3( signatureBean.getT3() );
		signature.setC( signatureBean.getC() );
		signature.setSx( signatureBean.getSx() );
		signature.setSalpha( signatureBean.getSalpha() );
		signature.setSbeta( signatureBean.getSbeta() );
		signature.setSdelta1( signatureBean.getSdelta1() );
		signature.setSdelta2( signatureBean.getSdelta2() );
		
		return signature;
		
	}
	
	
	
	public static BBSGroupPublicKey convert(BBSGroupPublicKeyBean gpkb, BBSGroupPublicKey gpk) {
		
		gpk.setG1( gpkb.getG1() );
		gpk.setG2(  gpkb.getG2() );
		gpk.setH( gpkb.getH() );
		gpk.setU( gpkb.getU()  );
		gpk.setV( gpkb.getV() );
		gpk.setOmega( gpkb.getOmega() );
		
		return gpk;
	}
	
	public static BBSUserPrivateKey convert(BBSUserPrivateKeyBean uskb, BBSUserPrivateKey usk) {
		
		usk.setAi( uskb.getAi() );
		usk.setXi( uskb.getXi() );
		
		return usk;
	}
	
	
	
}
