package cat.uib.secom.crypto.sig.bbs.marshalling;


import java.io.IOException;

import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERGeneralString;
import org.spongycastle.asn1.DERSequence;
import org.simpleframework.xml.Element;
import org.simpleframework.xml.Root;

import cat.uib.secom.crypto.sig.bbs.core.impl.keys.BBSUserPrivateKeyImpl;
import cat.uib.secom.crypto.sig.bbs.core.parameters.BBSParameters;
import cat.uib.secom.crypto.sig.bbs.core.transformations.TransformationHelper;
import cat.uib.secom.crypto.sig.bbs.marshalling.utils.Constants;


@Root(name=Constants.BBS_USER_PRIVATE_KEY)
//@Default(DefaultType.PROPERTY)
public class BBSUserPrivateKeyMSG extends AbstractBBSMSG {

	@Element(name="a")
	private String a;
	
	@Element(name="x")
	private String x;
	
	
	private BBSUserPrivateKeyImpl upk;
	
	//protected ASN1Sequence asn1Object;
	
	
	public BBSUserPrivateKeyMSG() {
		super(BBSUserPrivateKeyImpl.class);
	}


	public BBSUserPrivateKeyMSG(BBSUserPrivateKeyImpl upk) {
		super(BBSUserPrivateKeyImpl.class);
		this.upk = upk;
		this.toHexStrings();
	}


	@Override
	protected Object toHexStrings() {
		this.a = upk.getA().toHexString();
		this.x = upk.getX().toHexString();
		return this;
	}




	@Override
	protected BBSUserPrivateKeyImpl fromHexStrings(AbstractBBSMSG bbsMSG, BBSParameters bbsParameters) throws Exception {
		BBSUserPrivateKeyMSG upkMSG = (BBSUserPrivateKeyMSG) bbsMSG; //getAbstractMSG();
		
		BBSUserPrivateKeyImpl upk = new BBSUserPrivateKeyImpl( TransformationHelper.toElementWrapperFromHexString(upkMSG.a, TransformationHelper.A, bbsParameters),
													   		   TransformationHelper.toElementWrapperFromHexString(upkMSG.x, TransformationHelper.X, bbsParameters));
		
		return upk;
	}




	public String getA() {
		return a;
	}




	public void setA(String a) {
		this.a = a;
	}




	public String getX() {
		return x;
	}




	public void setX(String x) {
		this.x = x;
	}


//	@Override
//	protected AbstractBBSMSG getAbstractMSG() {
//		return this.abstractMSG;
//	}
//
//
//	@Override
//	protected void setAbstractMSG(AbstractBBSMSG abm) {
//		this.abstractMSG = abm;
//	}

	public ASN1Object toASNObject() {
		ASN1EncodableVector tmp = new ASN1EncodableVector();
		tmp.add(new DERGeneralString(this.a));
		tmp.add(new DERGeneralString(this.x));
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


	@Override
	protected Object decodeASN1FromByteArray(byte[] b) {
		try {
			asn1Object = (ASN1Sequence) ASN1Primitive.fromByteArray(b);
		}catch(IOException e) {
			e.printStackTrace();
			return false;
		}
		getValues(asn1Object);
		return this;
	}
	
	public boolean decode(ASN1Object asn) {
		asn1Object = (ASN1Sequence) asn;
		return getValues(asn1Object);
	}
	
	private boolean getValues(ASN1Sequence asn) {
		a = (( DERGeneralString ) asn1Object.getObjectAt(0)).getString();
		x = (( DERGeneralString ) asn1Object.getObjectAt(1)).getString();
		//super.abstractMSG = this;
		return true;
	}


	
	
	
}
