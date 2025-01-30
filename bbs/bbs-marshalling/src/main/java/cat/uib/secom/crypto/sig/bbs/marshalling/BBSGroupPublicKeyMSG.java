package cat.uib.secom.crypto.sig.bbs.marshalling;


import java.io.IOException;

import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERGeneralString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.util.ASN1Dump;
import org.simpleframework.xml.Element;
import org.simpleframework.xml.Root;

import cat.uib.secom.crypto.sig.bbs.core.impl.keys.BBSGroupPublicKeyImpl;
import cat.uib.secom.crypto.sig.bbs.core.parameters.BBSParameters;
import cat.uib.secom.crypto.sig.bbs.core.transformations.TransformationHelper;
import cat.uib.secom.crypto.sig.bbs.marshalling.utils.Constants;




@Root(name=Constants.BBS_GROUP_PUBLIC_KEY)
//@Default(DefaultType.PROPERTY)
public class BBSGroupPublicKeyMSG extends AbstractBBSMSG {
	
	@Element(name="g1")
	private String g1;
	
	@Element(name="g2")
	private String g2;
	
	@Element(name="h")
	private String h;
	
	@Element(name="u")
	private String u;
	
	@Element(name="v")
	private String v;
	
	@Element(name="omega")
	private String omega;
	
	private BBSGroupPublicKeyImpl gpk;
	
	//private ASN1Sequence asn1Object;


	
	public BBSGroupPublicKeyMSG() {
		super(BBSGroupPublicKeyImpl.class);
	}

	public BBSGroupPublicKeyMSG(BBSGroupPublicKeyImpl gpk) {
		super(BBSGroupPublicKeyImpl.class);
		this.gpk = gpk;
		this.toHexStrings();
	}
	
	@Override
	protected BBSGroupPublicKeyMSG toHexStrings() {
		this.g1 = gpk.getG1().toHexString();
		this.g2 = gpk.getG2().toHexString();
		this.h = gpk.getH().toHexString();
		this.u = gpk.getU().toHexString();
		this.v = gpk.getV().toHexString();
		this.omega = gpk.getOmega().toHexString();
		
		return this;
	}

	@Override
	protected BBSGroupPublicKeyImpl fromHexStrings(AbstractBBSMSG bbsMSG, BBSParameters bbsParameters) throws Exception {
		//BBSGroupPublicKeyMSG gpkMSG = (BBSGroupPublicKeyMSG) getAbstractMSG();
		BBSGroupPublicKeyMSG gpkMSG = (BBSGroupPublicKeyMSG) bbsMSG;
		
		BBSGroupPublicKeyImpl gpk = new BBSGroupPublicKeyImpl( TransformationHelper.toElementWrapperFromHexString(gpkMSG.g1, TransformationHelper.G1, bbsParameters),
													   TransformationHelper.toElementWrapperFromHexString(gpkMSG.g2, TransformationHelper.G2, bbsParameters),
													   TransformationHelper.toElementWrapperFromHexString(gpkMSG.h, TransformationHelper.H, bbsParameters),
													   TransformationHelper.toElementWrapperFromHexString(gpkMSG.u, TransformationHelper.U, bbsParameters),
													   TransformationHelper.toElementWrapperFromHexString(gpkMSG.v, TransformationHelper.V, bbsParameters),
													   TransformationHelper.toElementWrapperFromHexString(gpkMSG.omega, TransformationHelper.OMEGA, bbsParameters),
													   bbsParameters.getPairing(),
													   "");
		
		return gpk;
	}
	
	
	

	public String getG1() {
		return g1;
	}

	public void setG1(String g1) {
		this.g1 = g1;
	}

	public String getG2() {
		return g2;
	}

	public void setG2(String g2) {
		this.g2 = g2;
	}

	public String getH() {
		return h;
	}

	public void setH(String h) {
		this.h = h;
	}

	public String getU() {
		return u;
	}

	public void setU(String u) {
		this.u = u;
	}

	public String getV() {
		return v;
	}

	public void setV(String v) {
		this.v = v;
	}

	public String getOmega() {
		return omega;
	}

	public void setOmega(String omega) {
		this.omega = omega;
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

	
	
	
	
	
	// ASN1 encoding and decoding
	
	
	public ASN1Object toASNObject(){
		
		ASN1EncodableVector tmp = new ASN1EncodableVector();
		tmp.add(new DERGeneralString(g1));
		tmp.add(new DERGeneralString(g2));
		tmp.add(new DERGeneralString(h));
		tmp.add(new DERGeneralString(u));
		tmp.add(new DERGeneralString(v));
		tmp.add(new DERGeneralString(omega));
		
		asn1Object = new DERSequence(tmp);
		return asn1Object.toASN1Primitive();
	}
	
	@Override
	protected byte[] encodeASN1ToByteArray() {
		try {
			toASNObject();
			return asn1Object.getEncoded();
		} catch (IOException e) {
			return null;
		}
	}

	@Override
	protected Object decodeASN1FromByteArray(byte[] b) {
		try {
			asn1Object = (ASN1Sequence) ASN1Primitive.fromByteArray(b);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
		getValues(asn1Object);
		return this;
	}
	
	
	
	
	public boolean decode(ASN1Object asn){
		asn1Object = (ASN1Sequence) asn;
		return getValues(asn1Object);
	}
	
	private boolean getValues(ASN1Sequence pkASN){
		g1 = ((DERGeneralString) pkASN.getObjectAt(0)).getString();
		g2 = ((DERGeneralString) pkASN.getObjectAt(1)).getString();
		h = ((DERGeneralString) pkASN.getObjectAt(2)).getString();
		u = ((DERGeneralString) pkASN.getObjectAt(3)).getString();
		v = ((DERGeneralString) pkASN.getObjectAt(4)).getString();
		omega = ((DERGeneralString) pkASN.getObjectAt(5)).getString();
		
		//super.abstractMSG = this;
		
		return true;
	}

	@Override
	public void printASN1() {
		System.out.println( ASN1Dump.dumpAsString(asn1Object) );
	}

	
	
	
}
