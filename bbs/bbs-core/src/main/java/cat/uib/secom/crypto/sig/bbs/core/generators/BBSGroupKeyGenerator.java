package cat.uib.secom.crypto.sig.bbs.core.generators;

import it.unisa.dia.gas.jpbc.Element;
import cat.uib.secom.crypto.sig.bbs.core.impl.keys.BBSGroupManagerPrivateElementsImpl;
import cat.uib.secom.crypto.sig.bbs.core.impl.keys.BBSGroupManagerPrivateKeyImpl;
import cat.uib.secom.crypto.sig.bbs.core.impl.keys.BBSGroupPublicKeyImpl;
import cat.uib.secom.crypto.sig.bbs.core.parameters.BBSParameters;
import cat.uib.secom.utils.pairing.ElementWrapper;


/**
 * @author Andreu Pere
 * 
 * This object is the generator of the group public key. It uses BBSParameters object
 * to generate all the group key parameters. It also generates the private elements
 * for group manager
 * 
 * @see BBSParameters
 * @see BBSGroupPublicKey
 * @see BBSGroupManagerPrivateKey
 * @see BBSGroupManagerPrivateElements
 * */
public class BBSGroupKeyGenerator {

	private BBSGroupPublicKeyImpl bbsGroupPublicKey;
	private BBSGroupManagerPrivateKeyImpl bbsGroupManagerPrivateKey;
	private BBSGroupManagerPrivateElementsImpl bbsGroupManagerPrivateElements;
	private BBSParameters bbsParameters;
	
	
	public BBSGroupKeyGenerator(BBSParameters parameters) {
		bbsParameters = parameters;
	}
	
	
	/**
	 * It generates and stores BBSGroupPublicKey, BBSGroupManagerPrivateKey and BBSGroupManagerPrivateElements
	 * */
	public void generate() {
		Element h = bbsParameters.getPairing().getG1().newRandomElement().getImmutable();
		Element delta1 = bbsParameters.getPairing().getZr().newRandomElement().getImmutable();
		Element delta2 = bbsParameters.getPairing().getZr().newRandomElement().getImmutable();
		Element u = h.powZn(delta1.getImmutable().invert());
		Element v = h.powZn(delta2.getImmutable().invert());
		Element gamma = bbsParameters.getPairing().getZr().newRandomElement();
		Element omega = bbsParameters.getG2().getElement().powZn(gamma);
		
		bbsGroupPublicKey = new BBSGroupPublicKeyImpl(bbsParameters.getG1(), 
												  bbsParameters.getG2(), 
												  new ElementWrapper( h ), 
												  new ElementWrapper( u ), 
												  new ElementWrapper( v ), 
												  new ElementWrapper( omega ), 
												  bbsParameters.getPairing(), 
												  bbsParameters.getCurveParams().getString("r", "0"));
		
		bbsGroupManagerPrivateKey = new BBSGroupManagerPrivateKeyImpl(new ElementWrapper( delta1 ),
																  	  new ElementWrapper( delta2 ) );
		bbsGroupManagerPrivateElements = new BBSGroupManagerPrivateElementsImpl( new ElementWrapper( gamma ) );
		
	}

	/**
	 * Gets the BBSGroupPublicKey
	 * 
	 * @return BBSGroupPublicKey
	 * */
	public BBSGroupPublicKeyImpl getBBSGroupPublicKey() {
		return bbsGroupPublicKey;
	}

	/**
	 * Gets the BBSGroupManagerPrivateKey
	 * 
	 * @return BBSGroupManagerPrivateKey
	 * */
	public BBSGroupManagerPrivateKeyImpl getBBSGroupManagerPrivateKey() {
		return bbsGroupManagerPrivateKey;
	}

	/**
	 * Gets the BBSGroupManagerPrivateElements
	 * 
	 * @return BBSGroupManagerPrivateElements
	 * */
	public BBSGroupManagerPrivateElementsImpl getBBSGroupManagerPrivateElements() {
		return bbsGroupManagerPrivateElements;
	}
	
	
}
