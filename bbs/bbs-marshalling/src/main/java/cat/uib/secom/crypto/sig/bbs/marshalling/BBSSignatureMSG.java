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

import cat.uib.secom.crypto.sig.bbs.core.impl.signature.BBSSignatureImpl;
import cat.uib.secom.crypto.sig.bbs.core.parameters.BBSParameters;
import cat.uib.secom.crypto.sig.bbs.core.transformations.TransformationHelper;
import cat.uib.secom.crypto.sig.bbs.marshalling.utils.Constants;




@Root(name=Constants.BBS_SIGNATURE)
//@Default(DefaultType.PROPERTY)
public class BBSSignatureMSG extends AbstractBBSMSG  {
	
	@Element(name="t1")
	protected String t1;
	
	@Element(name="t2")
	protected String t2;
	
	@Element(name="t3")
	protected String t3;
	
	@Element(name="c")
	protected String c;
	
	@Element(name="salpha")
	protected String salpha;
	
	@Element(name="sbeta")
	protected String sbeta;
	
	@Element(name="sx")
	protected String sx;
	
	@Element(name="sdelta1")
	protected String sdelta1;
	
	@Element(name="sdelta2")
	protected String sdelta2;
	
	private BBSSignatureImpl signature;
	
	//private ASN1Sequence asn1Object;
	
	
	
	public BBSSignatureMSG(BBSSignatureImpl sig) {	
		super(BBSSignatureImpl.class);
		this.signature = sig;
		this.toHexStrings();
	}
	
	public BBSSignatureMSG() {
		super(BBSSignatureImpl.class);
	}
	
	
	protected BBSSignatureMSG toHexStrings() {
		this.t1 = signature.getT1().toHexString();
		this.t2 = signature.getT2().toHexString();
		this.t3 = signature.getT3().toHexString();
		this.c = signature.getC().toHexString();
		this.salpha = signature.getSalpha().toHexString();
		this.sbeta = signature.getSbeta().toHexString();
		this.sx = signature.getSx().toHexString();
		this.sdelta1 = signature.getSdelta1().toHexString();
		this.sdelta2 = signature.getSdelta2().toHexString();
		return this;
	}
	
	protected BBSSignatureImpl fromHexStrings(AbstractBBSMSG bbsMSG, BBSParameters bbsParameters) throws Exception {
		BBSSignatureMSG sigXML = (BBSSignatureMSG) bbsMSG; //getAbstractMSG();
		
		BBSSignatureImpl signature = new BBSSignatureImpl( TransformationHelper.toElementWrapperFromHexString(sigXML.t1, TransformationHelper.T1, bbsParameters),
								   TransformationHelper.toElementWrapperFromHexString(sigXML.t2, TransformationHelper.T2, bbsParameters),
								   TransformationHelper.toElementWrapperFromHexString(sigXML.t3, TransformationHelper.T3, bbsParameters),
								   TransformationHelper.toElementWrapperFromHexString(sigXML.c, TransformationHelper.C, bbsParameters),
								   TransformationHelper.toElementWrapperFromHexString(sigXML.salpha, TransformationHelper.SALPHA, bbsParameters),
								   TransformationHelper.toElementWrapperFromHexString(sigXML.sbeta, TransformationHelper.SBETA, bbsParameters),
								   TransformationHelper.toElementWrapperFromHexString(sigXML.sx, TransformationHelper.SX, bbsParameters),
								   TransformationHelper.toElementWrapperFromHexString(sigXML.sdelta1, TransformationHelper.SDELTA1, bbsParameters),
								   TransformationHelper.toElementWrapperFromHexString(sigXML.sdelta2, TransformationHelper.SDELTA2, bbsParameters)
								   );
		return signature;
	}
	
	
	
	

	

	public String getT1() {
		return t1;
	}

	public void setT1(String t1) {
		this.t1 = t1;
	}

	public String getT2() {
		return t2;
	}

	public void setT2(String t2) {
		this.t2 = t2;
	}

	public String getT3() {
		return t3;
	}

	public void setT3(String t3) {
		this.t3 = t3;
	}

	public String getC() {
		return c;
	}

	public void setC(String c) {
		this.c = c;
	}

	public String getSalpha() {
		return salpha;
	}

	public void setSalpha(String salpha) {
		this.salpha = salpha;
	}

	public String getSbeta() {
		return sbeta;
	}

	public void setSbeta(String sbeta) {
		this.sbeta = sbeta;
	}

	public String getSx() {
		return sx;
	}

	public void setSx(String sx) {
		this.sx = sx;
	}

	public String getSdelta1() {
		return sdelta1;
	}

	public void setSdelta1(String sdelta1) {
		this.sdelta1 = sdelta1;
	}

	public String getSdelta2() {
		return sdelta2;
	}

	public void setSdelta2(String sdelta2) {
		this.sdelta2 = sdelta2;
	}

	
	
	
//	@Override
//	protected AbstractBBSMSG getAbstractMSG() {
//		return this.abstractMSG;
//	}
//
//	@Override
//	protected void setAbstractMSG(AbstractBBSMSG abm) {
//		this.abstractMSG = abm;
//	}

	

	
	
	public ASN1Object toASNObject(){
		
		ASN1EncodableVector tmp = new ASN1EncodableVector();
		tmp.add(new DERGeneralString(t1));
		tmp.add(new DERGeneralString(t2));
		tmp.add(new DERGeneralString(t3));
		tmp.add(new DERGeneralString(c));
		tmp.add(new DERGeneralString(salpha));
		tmp.add(new DERGeneralString(sbeta));
		tmp.add(new DERGeneralString(sx));
		tmp.add(new DERGeneralString(sdelta1));
		tmp.add(new DERGeneralString(sdelta2));
		
		asn1Object = new DERSequence(tmp);
		return asn1Object.toASN1Primitive();
	}
	
	public byte[] encodeASN1ToByteArray(){
		try {
			toASNObject();
			return asn1Object.getEncoded();
		} catch (IOException e) {
			return null;
		}
	}
	
	public Object decodeASN1FromByteArray(byte[] der){
		try {
			asn1Object = (ASN1Sequence) ASN1Primitive.fromByteArray(der);
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
		t1 = ((DERGeneralString) pkASN.getObjectAt(0)).getString();
		t2 = ((DERGeneralString) pkASN.getObjectAt(1)).getString();
		t3 = ((DERGeneralString) pkASN.getObjectAt(2)).getString();
		c = ((DERGeneralString) pkASN.getObjectAt(3)).getString();
		salpha = ((DERGeneralString) pkASN.getObjectAt(4)).getString();
		sbeta = ((DERGeneralString) pkASN.getObjectAt(5)).getString();
		sx = ((DERGeneralString) pkASN.getObjectAt(6)).getString();
		sdelta1 = ((DERGeneralString) pkASN.getObjectAt(7)).getString();
		sdelta2 = ((DERGeneralString) pkASN.getObjectAt(8)).getString();
		
		
		//super.abstractMSG = this;
		
		return true;
	}


	public void printASN1() {
		System.out.println( ASN1Dump.dumpAsString(asn1Object) );
	}

}