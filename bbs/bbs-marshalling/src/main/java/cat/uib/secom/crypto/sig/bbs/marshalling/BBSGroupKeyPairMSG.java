package cat.uib.secom.crypto.sig.bbs.marshalling;


import java.io.IOException;

import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DLSequence;
import org.spongycastle.asn1.util.ASN1Dump;
import org.simpleframework.xml.Element;
import org.simpleframework.xml.Root;

import cat.uib.secom.crypto.sig.bbs.core.impl.keys.helper.BBSGroupKeyPairImpl;
import cat.uib.secom.crypto.sig.bbs.core.impl.keys.BBSGroupPublicKeyImpl;
import cat.uib.secom.crypto.sig.bbs.core.impl.keys.BBSUserPrivateKeyImpl;
import cat.uib.secom.crypto.sig.bbs.core.parameters.BBSParameters;
import cat.uib.secom.crypto.sig.bbs.marshalling.utils.Constants;






@Root(name=Constants.BBS_GROUP_KEY_PAIR)
//@Default(DefaultType.PROPERTY)
public class BBSGroupKeyPairMSG extends AbstractBBSMSG {
	
	
	@SuppressWarnings("unused")
	private BBSGroupPublicKeyImpl gpk;
	@SuppressWarnings("unused")
	private BBSUserPrivateKeyImpl upk;
	
	
	private BBSGroupPublicKeyMSG gpkMSG;
	private BBSUserPrivateKeyMSG upkMSG;
	
	//protected ASN1Sequence asn1Object;
	

	public BBSGroupKeyPairMSG() {
		super(null);
	}
	
	public BBSGroupKeyPairMSG(BBSGroupPublicKeyImpl gpk, BBSUserPrivateKeyImpl upk) {
		super(null);
		this.gpk = gpk;
		this.upk = upk;
		this.gpkMSG = new BBSGroupPublicKeyMSG(gpk);
		this.upkMSG = new BBSUserPrivateKeyMSG(upk);
	}
	
	public BBSGroupKeyPairMSG(BBSGroupKeyPairImpl gkp) {
		super(null);
		this.gpk = gkp.getGroupPublicKey();
		this.upk = gkp.getUserPrivateKey();
		this.gpkMSG = new BBSGroupPublicKeyMSG(gpk);
		this.upkMSG = new BBSUserPrivateKeyMSG(upk);
	}
	

	@Override
	protected BBSGroupKeyPairMSG toHexStrings() {
		this.gpkMSG = (BBSGroupPublicKeyMSG) gpkMSG.toHexStrings();
		//System.out.println("hola");
		//System.out.println("g1   : " + this.gpk.getG1().toHexString());
		//System.out.println("g1XML: " + this.gpkXML.getG1());
		this.upkMSG = (BBSUserPrivateKeyMSG) upkMSG.toHexStrings();
		
		return this;
	}

	@Override
	protected BBSGroupKeyPairImpl fromHexStrings(AbstractBBSMSG bbsMSG, BBSParameters bbsParameters) throws Exception {
		BBSGroupKeyPairMSG gkpMSG = (BBSGroupKeyPairMSG) bbsMSG; // getAbstractMSG(); 
		

		
		BBSGroupPublicKeyMSG gpkMSG = gkpMSG.getGroupPublicKeyMSG();
		BBSUserPrivateKeyMSG upkMSG = gkpMSG.getUserPrivateKeyMSG();
		
//		gpkMSG.setAbstractMSG(gpkMSG);
//		upkMSG.setAbstractMSG(upkMSG);
//	
		
		BBSGroupPublicKeyImpl gpk = gkpMSG.getGroupPublicKeyMSG().fromHexStrings(gpkMSG, bbsParameters);
		BBSUserPrivateKeyImpl upk = gkpMSG.getUserPrivateKeyMSG().fromHexStrings(upkMSG, bbsParameters);
		

		return new BBSGroupKeyPairImpl(gpk, upk);
	}
	
	
	
	

	@Element(name="bbs-group-public-key")
	public BBSGroupPublicKeyMSG getGroupPublicKeyMSG() {
		return gpkMSG;
	}

	@Element(name="bbs-group-public-key")
	public void setGroupPublicKeyMSG(BBSGroupPublicKeyMSG gpkMSG) {
		this.gpkMSG = gpkMSG;
	}

	
	@Element(name="bbs-user-private-key")
	public BBSUserPrivateKeyMSG getUserPrivateKeyMSG() {
		return upkMSG;
	}

	@Element(name="bbs-user-private-key")
	public void setUserPrivateKeyMSG(BBSUserPrivateKeyMSG upkMSG) {
		this.upkMSG = upkMSG;
	}

//	@Override
//	protected AbstractBBSMSG getAbstractMSG() {
//		return this.abstractMSG;
//	}
//
//	@Override
//	protected void setAbstractMSG(AbstractBBSMSG abm) {
//		this.abstractMSG = abm;
//		
//	}
	
	public ASN1Object toASNObject() {
		ASN1EncodableVector tmp = new ASN1EncodableVector();
		tmp.add( gpkMSG.toASNObject() );
		tmp.add( upkMSG.toASNObject() );
		asn1Object = new DERSequence(tmp);
		return asn1Object.toASN1Primitive();
	}

	@Override
	protected byte[] encodeASN1ToByteArray() {
		try {
			toASNObject();
			return asn1Object.getEncoded();
		} catch(IOException e) {
			return null;
		}
	}
	
	public boolean decode(ASN1Object asn) {
		asn1Object = (ASN1Sequence) asn;
		return getValues(asn1Object);
	}
	
	
	private boolean getValues(ASN1Sequence asn) {
		DLSequence tmp1 = ((DLSequence)asn1Object.getObjectAt(0));
		DLSequence tmp2 = ((DLSequence)asn1Object.getObjectAt(1));
		gpkMSG = new BBSGroupPublicKeyMSG();
		gpkMSG.decode(tmp1);
		
		upkMSG = new BBSUserPrivateKeyMSG();
		upkMSG.decode(tmp2);
		
		//super.abstractMSG = this;
		return true;
	}

	@Override
	protected Object decodeASN1FromByteArray(byte[] b) {
		try {
			asn1Object = (ASN1Sequence) ASN1Primitive.fromByteArray(b);
		} catch(IOException e) {
			e.printStackTrace();
			return false;
		}
		getValues(asn1Object);
		return this;
		
	}
	
	

	@Override
	public void printASN1() {
		System.out.println( ASN1Dump.dumpAsString(asn1Object) );	
	}
	
	
	
	
	

}
