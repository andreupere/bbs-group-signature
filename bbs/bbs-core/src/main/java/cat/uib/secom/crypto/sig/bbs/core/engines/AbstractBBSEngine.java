package cat.uib.secom.crypto.sig.bbs.core.engines;

import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.SHA1Digest;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import cat.uib.secom.crypto.sig.bbs.core.exception.VerificationFailsException;
import cat.uib.secom.crypto.sig.bbs.core.keys.BBSGroupManagerPrivateKey;
import cat.uib.secom.crypto.sig.bbs.core.keys.BBSGroupPublicKey;
import cat.uib.secom.crypto.sig.bbs.core.keys.BBSUserPrivateKey;
import cat.uib.secom.crypto.sig.bbs.core.signature.BBSSignature;
import cat.uib.secom.security.HashUtils;
import cat.uib.secom.utils.pairing.ElementWrapper;
import cat.uib.secom.utils.strings.StringUtils;


/**
 * Abstract class to be used for all the package subclasses. This class defines the key methods and then a subclass calls
 * this methods as developer needs. For example, engine subclass with precomputation of without it.
 * */
public abstract class AbstractBBSEngine {

	protected Digest digest;
	
	protected boolean precomputation;
	
	protected BBSGroupPublicKey gpk;
	protected BBSUserPrivateKey usk;
	
	protected Element alpha, beta;
	//protected Element exp;
	protected Element t1, t2, t3;
	protected Element delta1, delta2;
	protected Element pairing1, pairing2, pairing3;
	protected Element ralpha, rbeta, rx, rdelta1, rdelta2;
	protected Element r1, r2, r3, r4, r5;
	protected Element ehw, ehg2, eg1g2;
	@SuppressWarnings("unchecked")
	protected Field zp;
	
	public AbstractBBSEngine() {
		this.digest = new SHA1Digest();
	}
	
	
	public AbstractBBSEngine(Digest digest) {
		this.digest = digest;
	}


	public void init(BBSGroupPublicKey groupPublicKey) {
		this.gpk = (BBSGroupPublicKey) groupPublicKey;
		zp = gpk.getPairing().getZr();
	}
	
	public void init(BBSGroupPublicKey groupPublicKey, BBSUserPrivateKey userPrivateKey) {
		this.gpk = (BBSGroupPublicKey) groupPublicKey;
		this.usk = (BBSUserPrivateKey) userPrivateKey;
		zp = gpk.getPairing().getZr();
	}
	
	
	public BBSGroupPublicKey getBBSGroupPublicKey() {
		return this.gpk;
	}
	public BBSUserPrivateKey getBBSUserPrivateKey() {
		return this.usk;
	}
	
	public void setBBSGroupPublicKey(BBSGroupPublicKey groupPublicKey) {
		this.gpk = groupPublicKey;
	}
	public void setBBSUserPrivateKey(BBSUserPrivateKey userPrivateKey) {
		this.usk = userPrivateKey;
	}
	
	
//	public void setBBSGroupPublicKey(CipherParameters groupPublicKey) {
//		this.gpk = (BBSGroupPublicKey) groupPublicKey;
//	}
//	public void setBBSUserPrivateKey(CipherParameters userPrivateKey) {
//		this.usk = (BBSUserPrivateKey) userPrivateKey;
//	}
	
	
	/**
	 * Precompute pairings. It is a time-consuming method
	 * */
	protected void pairingsPrecomputation() {
		this.pairing2 = gpk.getPairing().pairing(gpk.getH().getElement(), gpk.getOmega().getElement()).getImmutable();
		this.pairing3 = gpk.getPairing().pairing(gpk.getH().getElement(), gpk.getG2().getElement()).getImmutable();
	}
	
	
	/**
	 * Compute alpha and beta randoms
	 * */
	protected void preRandomAlphaBeta() {
		this.alpha = zp.newRandomElement().getImmutable();
		this.beta = zp.newRandomElement().getImmutable();
	}
	
	/**
	 * Compute randoms
	 * */
	protected void preRandoms() {
		// random integers modulo r
		this.ralpha = zp.newRandomElement().getImmutable();
		this.rbeta = zp.newRandomElement().getImmutable();
		this.rx = zp.newRandomElement().getImmutable();
		this.rdelta1 = zp.newRandomElement().getImmutable();
		this.rdelta2 = zp.newRandomElement().getImmutable();
	}
	
	
	/**
	 * It computes variables related to alpha and beta randoms
	 * */
	protected void preComputationRelatedToAlphaBeta() {
		// T1
		this.t1 = gpk.getU().getElement().powZn(alpha);
		// T2
		this.t2 = gpk.getV().getElement().powZn(beta);
		// T3
		Element exp = alpha.getImmutable().add(beta);
		this.t3 = gpk.getH().getElement().powZn(exp).mul(usk.getA().getElement());
		
		// delta1
		this.delta1 = usk.getX().getElement().mulZn(alpha);
		// delta2
		this.delta2 = usk.getX().getElement().mulZn(beta);
		// pairing1
		this.pairing1 = gpk.getPairing().pairing(t3, gpk.getG2().getElement()).getImmutable();
	}
	
	
	/**
	 * It Computes elements that depends on parameters computed on @see {@link #preRandoms()} method
	 * */
	protected void precomputation() {		
		
		// R1
		this.r1 = gpk.getU().getElement().powZn(ralpha);
		// R2
		this.r2 = gpk.getV().getElement().powZn(rbeta);
		// R3
		Element r3_1 = pairing1.powZn( rx ).getImmutable();
		Element r3_2 = pairing2.powZn( ralpha.getImmutable().negate().add( rbeta.getImmutable().negate() ) ).getImmutable();
		Element r3_3 = pairing3.powZn( rdelta1.getImmutable().negate().add( rdelta2.getImmutable().negate() ) ).getImmutable();
		this.r3 = r3_1.mul(r3_2).mul(r3_3);
		
		// R4
		Element help1 = gpk.getU().getElement().powZn(rdelta1.getImmutable().negate());
		this.r4 = t1.getImmutable().powZn(rx).mul(help1);
		
		// R5
		Element help2 = gpk.getV().getElement().powZn(rdelta2.getImmutable().negate());
		this.r5 = t2.getImmutable().powZn(rx).mul(help2);

		
	}
	
	
	protected void verifierPrecomputation() {
		this.ehw = gpk.getPairing().pairing(gpk.getH().getElement(), gpk.getOmega().getElement());  //precomp
		this.ehg2 = gpk.getPairing().pairing(gpk.getH().getElement(), gpk.getG2().getElement());  //precomp
		this.eg1g2 = gpk.getPairing().pairing(gpk.getG1().getElement(), gpk.getG2().getElement()); //precomp
		eg1g2.invert(); //precomp
	}

	
	
	/**
	 * This method implements the SIGN() algorithm. Only computation 
	 * related to the input message to be signed is considered. 
	 * 
	 * @param message The message as string
	 * 
	 * @return Signature
	 * 
	 * @see BBSSignature
	 * @see CipherParameters
	 * @see BBSGroupPublicKey
	 * @see BBSUserPrivateKey
	 * */
	protected BBSSignature doSign(String message) {		

		String toHash = concatenateHexTransformation(message, t1, t2, t3, r1, r2, r3, r4, r5);
		//HashUtils hash = new HashUtils(digest, toHash);
		//byte[] ch = hash.generate();
		byte[] ch = HashUtils.getHash2(toHash);
		
		
		// Map hash result to the corresponding value over Zr
		Element c = zp.newElement().setFromHash(ch, 0, ch.length).getImmutable();
		
		
		Element salpha = ralpha.add( c.mulZn(alpha) );
		
		Element sbeta = rbeta.add( c.mulZn(beta) );
		
		Element sx = rx.add( c.mulZn(usk.getX().getElement()) );
		
		Element sdelta1 = rdelta1.add( c.mulZn(delta1) );
		
		Element sdelta2 = rdelta2.add( c.mulZn(delta2) );
		

		
		return new cat.uib.secom.crypto.sig.bbs.core.impl.signature.BBSSignatureImpl( new ElementWrapper( t1 ), 
							  new ElementWrapper( t2 ), 
							  new ElementWrapper( t3 ), 
							  new ElementWrapper( c ), 
							  new ElementWrapper( salpha ), 
							  new ElementWrapper( sbeta ), 
							  new ElementWrapper( sx ), 
							  new ElementWrapper( sdelta1 ), 
							  new ElementWrapper( sdelta2) );
	}
	
	
	
	
	

	
	/**
	 * 
	 * */
	public abstract BBSSignature sign(String message) throws Exception; 
	
	
	/**
	 * This method executes the signature verification. It should be only called by subclasses.
	 * 
	 * @param sign signature to be verified
	 * @param m signed message to be verified with sign
	 * 
	 * @return boolean
	 * */
	protected boolean doVerify(BBSSignature sign, String m) {
		boolean output = false;

		Element r1re = sign.getT1().getElement().powZn(sign.getC().getElement());
		r1re.invert();
		r1re.mul( gpk.getU().getElement().powZn( sign.getSalpha().getElement() ) );
		
		Element r2re = sign.getT2().getElement().powZn( sign.getC().getElement() );
		r2re.invert();
		r2re.mul( gpk.getV().getElement().powZn( sign.getSbeta().getElement() ) );
		

		Element p1 = gpk.getPairing().pairing(sign.getT3().getElement(), gpk.getG2().getElement() );
		p1.powZn( sign.getSx().getElement() );
		//Element p2 = gpk.getPairing().pairing(gpk.getH().getElement(), gpk.getOmega().getElement()); //precomp
		Element exp = sign.getSalpha().getElement().negate();
		exp.add( sign.getSbeta().getElement().negate() );
		ehw.powZn(exp);
		//Element p3 = gpk.getPairing().pairing(gpk.getH().getElement(), gpk.getG2().getElement()); //precomp
		exp = sign.getSdelta1().getElement().negate();
		exp.add( sign.getSdelta2().getElement().negate() );
		ehg2.powZn(exp);
		//Element p4 = gpk.getPairing().pairing(gpk.getG1().getElement(), gpk.getG2().getElement());//precomp
		Element p5 = gpk.getPairing().pairing(sign.getT3().getElement(), gpk.getOmega().getElement());
		//p4.invert();//precomp
		eg1g2.mul(p5);
		eg1g2.powZn(sign.getC().getElement());
		
		
		Element r3re = p1.mul(ehw);
		r3re.mul(ehg2);
		r3re.mul(eg1g2);
		
		Element r4re = gpk.getU().getElement().powZn( sign.getSdelta1().getElement() );
		r4re.invert();
		r4re.mul( sign.getT1().getElement().powZn( sign.getSx().getElement() ) );
		
		Element r5re = gpk.getV().getElement().powZn( sign.getSdelta2().getElement() );
		r5re.invert();
		r5re.mul( sign.getT2().getElement().powZn( sign.getSx().getElement() ) );
		

		String toHash = concatenateHexTransformation(m, 
													 sign.getT1().getElement(), 
													 sign.getT2().getElement(), 
													 sign.getT3().getElement(),
													 r1re,
													 r2re,
													 r3re,
													 r4re,
													 r5re);
		byte[] creb = HashUtils.getHash2(toHash);
		//Hash hash = new Hash(digest, toHash);
		//byte[] creb = hash.generate();
		

		Element newC =  zp.newElement().setFromHash(creb, 0, creb.length).getImmutable();


		if ( newC.equals( sign.getC().getElement() ) ) {
			output = true;
		}
		
		
		return output;
	}
	
	
	
	

	
	/**
	 * Verifies the input signature over the input message with the groupPublicKey
	 * 
	 * @param signature The Signature object
	 * @param message The message as a String. If it is a object, the object must be overrides the .toString() method
	 * 
	 * @return boolean as the verification result
	 * 
	 * @see Signature
	 * */
	public abstract boolean verify(BBSSignature signature, String message) throws Exception;
	
	
	
	
	
	
	/**
	 * This method implements the OPEN() algorithm.
	 * 
	 * It reveals the A element from BBSUserPrivateKey. This element can be used by the group manager to
	 * trace the identity of the signature signer.
	 * 
	 * It should be only used by subclasses
	 * 
	 * @param message
	 * @param signature
	 * @param groupManagerPrivateKey
	 * 
	 * @throws VerificationFailsException Since open algorithm requires the signature verification, this
	 * exception will be thrown if the verification fails
	 * 
	 * @return The A element from the specification. It can be used to trace the signer identity
	 * */
	protected Element doOpen(String message, 
							 BBSSignature signature,
							 BBSGroupManagerPrivateKey groupManagerPrivateKey) 
			throws VerificationFailsException {
		

		BBSGroupManagerPrivateKey gmsk = (BBSGroupManagerPrivateKey) groupManagerPrivateKey;
		return (signature.getT1().getElement().powZn(gmsk.getDelta1().getElement())).mul(signature.getT2().getElement().powZn(gmsk.getDelta2().getElement())).invert().mul(signature.getT3().getElement());

	}
	
	public abstract Element open(String message, BBSSignature signature, BBSGroupManagerPrivateKey groupManagerPrivateKey) 
			throws VerificationFailsException;
	
	
	
	/**
	 * This can be used for transform an Element to a Hex string representation. 
	 * 
	 * */
	protected String concatenateHexTransformation(String message,
												  Element t1, 
												  Element t2, 
												  Element t3, 
												  Element r1, 
												  Element r2, 
												  Element r3, 
												  Element r4, 
												  Element r5) {
		String result = message;
		result += StringUtils.readHexString(t1.toBytes());
		result += StringUtils.readHexString(t2.toBytes());
		result += StringUtils.readHexString(t3.toBytes());
		result += StringUtils.readHexString(r1.toBytes());
		result += StringUtils.readHexString(r2.toBytes());
		result += StringUtils.readHexString(r3.toBytes());
		result += StringUtils.readHexString(r4.toBytes());
		result += StringUtils.readHexString(r5.toBytes());
		
		return result;
	}



	/**
	 * This can be used for transform an Element to a plain string representation. It uses toString() method from jPBC element.
	 * 
	 * */
	protected String concatenateStringTransformation(String message,
													 Element t1, 
													 Element t2, 
													 Element t3, 
													 Element r1, 
													 Element r2, 
													 Element r3, 
													 Element r4, 
													 Element r5) {
		String result = message;
		result += t1.toString();
		result += t2.toString();
		result += t3.toString();
		result += r1.toString();
		result += r2.toString();
		result += r3.toString();
		result += r4.toString();
		result += r5.toString();
		
		return result;
	}


	public boolean isPrecomputation() {
		return precomputation;
	}


	public void setPrecomputation(boolean precomputation) {
		this.precomputation = precomputation;
	}
	
	
	
}
