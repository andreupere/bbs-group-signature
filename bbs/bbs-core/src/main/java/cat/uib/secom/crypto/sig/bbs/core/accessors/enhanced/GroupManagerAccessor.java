package cat.uib.secom.crypto.sig.bbs.core.accessors.enhanced;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

import it.unisa.dia.gas.jpbc.Element;

import org.spongycastle.crypto.AsymmetricCipherKeyPair;

import cat.uib.secom.crypto.sig.bbs.core.engines.BBSEngine;
import cat.uib.secom.crypto.sig.bbs.core.exception.VerificationFailsException;
import cat.uib.secom.crypto.sig.bbs.core.generators.BBSGroupKeyGenerator;
import cat.uib.secom.crypto.sig.bbs.core.generators.BBSKeyPairGenerator;
import cat.uib.secom.crypto.sig.bbs.core.keys.BBSGroupManagerPrivateElements;
import cat.uib.secom.crypto.sig.bbs.core.keys.BBSGroupManagerPrivateKey;
import cat.uib.secom.crypto.sig.bbs.core.keys.BBSGroupPublicKey;
import cat.uib.secom.crypto.sig.bbs.core.keys.BBSUserPrivateKey;
import cat.uib.secom.crypto.sig.bbs.core.signature.BBSSignature;
import cat.uib.secom.crypto.sig.bbs.core.parameters.BBSKeyGenerationParameters;
import cat.uib.secom.crypto.sig.bbs.core.parameters.BBSParameters;


/**
 * @author Andreu Pere
 * 
 * This class represents the group manager operations: setup, extract keys, open signature
 * */
public class GroupManagerAccessor {
	
	protected BBSEngine bbsEngine;
	protected BBSGroupKeyGenerator bbsGroupKeyGenerator;
	protected BBSParameters bbsParameters;
	protected int n;
	protected String curveFileName;
	protected BBSKeyGenerationParameters bbsKGP;
	protected BBSKeyPairGenerator bbsKeyPairGenerator;
	
	protected HashMap<Integer, AsymmetricCipherKeyPair> hm;
	

	public GroupManagerAccessor(int numberUsers, String curveFileName) {
		n = numberUsers;
		this.curveFileName = curveFileName;
	}
	
	/**
	 * It setups parameters for generate keys and then it generates the
	 * user private keys
	 * At the end of this method, a HashMap is deployed containing a set
	 * of user private keys
	 * */
	public void setup() {
		prepareParameters();
		generateParameters();
		generateKeys();
	}
	
	/**
	 * It setups parameters for generate keys and the it generates the user private keys
	 * It uses as input a g1 element previously generated
	 * At the end of this method, a HashMap is deployed containing a set of user private keys
	 * */
	public void setup(byte[] g1) {
		prepareParameters(g1);
		generateParameters();
		generateKeys();
	}
	
	private void prepareParameters(byte[] g1) {
		bbsParameters = new BBSParameters(curveFileName, n);
		bbsParameters.generate(g1);
	}
	
	private void prepareParameters() {
		bbsParameters = new BBSParameters(curveFileName, n);
		bbsParameters.generate();
		
	}
	
	private void generateParameters() {
		
		bbsGroupKeyGenerator = new BBSGroupKeyGenerator(bbsParameters);
		bbsGroupKeyGenerator.generate();
		
		bbsKGP = new BBSKeyGenerationParameters(bbsParameters,
												bbsGroupKeyGenerator.getBBSGroupPublicKey(),
												bbsGroupKeyGenerator.getBBSGroupManagerPrivateKey(),
												bbsGroupKeyGenerator.getBBSGroupManagerPrivateElements());
	}
	
	private void generateKeys() {
		bbsKeyPairGenerator = new BBSKeyPairGenerator();
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
	
	
	public BBSParameters getBBSParameters() {
		return bbsParameters;
	}

	
	
	
	
	/**
	 * @deprecated
	 * */
	public AsymmetricCipherKeyPair extractKeyPair() {
		return hm.get(1);
	}
	
	public AsymmetricCipherKeyPair getKeyPair(int key) {
		return hm.get(key);
	}
	
	
	/**
	 * Extracts the set of user private keys previously generated and stored in a HashMap
	 * 
	 * @return HashMap<Integer, BBSUserPrivateKey> containing a pair of integer key and
	 * a user private key
	 * @see BBSUserPrivateKey
	 * */
	public HashMap<Integer, BBSUserPrivateKey> getUserPrivateKeys() {
		HashMap<Integer, BBSUserPrivateKey> m = new HashMap<Integer, BBSUserPrivateKey>();
		Set<Integer> s = hm.keySet();
		Iterator<Integer> it = s.iterator();
		while( it.hasNext() ) {
			Integer key = it.next();
			m.put(key, (BBSUserPrivateKey)hm.get(key).getPrivate());
		}
		return m;
	}
	
	/**
	 * Extracts the group manager private key previously generated
	 * 
	 * @return BBSGroupManagerPrivateKey
	 * @see BBSGroupManagerPrivateKey
	 * */
	public BBSGroupManagerPrivateKey getGroupManagerPrivateKey() {
		return bbsKGP.getBBSGroupManagerPrivateKey();
	}
	
	/**
	 * Extracts the group manager private elements
	 * 
	 * @return BBSGroupManagerPrivateElements 
	 * @see BBSGroupManagerPrivateElements
	 * */
	public BBSGroupManagerPrivateElements getGroupManagerPrivateElements() {
		return bbsKGP.getBBSGroupManagerPrivateElements();
	}
	
	public HashMap<Integer, AsymmetricCipherKeyPair> getHashMapKeyPairs() {
		return hm;
	}
	
	public BBSGroupPublicKey getGroupPublicKey() {
		return bbsKGP.getBBSGroupPublicKey();
	}
	public BBSUserPrivateKey getUserPrivateKey(int key) {
		return (BBSUserPrivateKey)hm.get(key).getPrivate();
	}
	
	/**
	 * 
	 * It revokes the anonymity of user who made the signature
	 * 
	 * @param message the signed message
	 * @param signature is the signature object over message string
	 * @param groupPublicKey is the group public key
	 * 
	 * @return id as Integer containing the ID of the user who signs the message
	 * @throws VerificationFailsException 
	 * 
	 * @see Signature
	 * @see BBSGroupPublicKey
	 * */
	public Integer open(String message, BBSSignature signature, BBSGroupPublicKey groupPublicKey) throws VerificationFailsException {
		BBSEngine bbsEngine = new BBSEngine(groupPublicKey);
		Element openedAi = bbsEngine.open(message, signature, bbsGroupKeyGenerator.getBBSGroupManagerPrivateKey());

		// cercar open (A) dins de la taula de hash
		Integer id = searchAiOnDataBase(openedAi); 
		return id;
	}
	
	/**
	 * It revokes the anonymity of user who made the signature
	 * 
	 * @param message the signed message
	 * @param signature is the signature object over message string
	 * 
	 * @return id as Integer containing the ID of the user who signs the message
	 * @throws VerificationFailsException 
	 * 
	 * @see Signature
	 * @see BBSGroupPublicKey
	 * */
	public Integer open(String message, BBSSignature signature) throws VerificationFailsException {
		BBSEngine bbsEngine = new BBSEngine( bbsGroupKeyGenerator.getBBSGroupPublicKey() );
		Element openedAi = bbsEngine.open(message, signature, bbsGroupKeyGenerator.getBBSGroupManagerPrivateKey());

		// cercar open (A) dins de la taula de hash
		Integer id = searchAiOnDataBase(openedAi);
		return id;
	}
	
	
	/**
	 * @deprecated
	 * It revokes the anonymity of user who made the signature
	 * 
	 * @param message the signed message
	 * @param signature is the signature object over message string
	 * @param groupPublicKey is the group public key
	 * 
	 * @return id as Integer containing the ID of the user who signs the message
	 * @throws VerificationFailsException 
	 * 
	 * @see Signature
	 * @see BBSGroupPublicKey
	 * */
	public Integer getIdentity(String message, BBSSignature signature, BBSGroupPublicKey groupPublicKey) throws VerificationFailsException {
		BBSEngine bbsEngine = new BBSEngine(groupPublicKey);
		Element openedAi = bbsEngine.open(message, signature, bbsGroupKeyGenerator.getBBSGroupManagerPrivateKey());

		// cercar open (A) dins de la taula de hash
		Integer id = searchAiOnDataBase(openedAi); 
		return id;
	}
	
	
	
	/**
	 * @deprecated
	 * It revokes the anonymity of user who made the signature
	 * 
	 * @param message the signed message
	 * @param signature is the signature object over message string
	 * 
	 * @return id as Integer containing the ID of the user who signs the message
	 * @throws VerificationFailsException 
	 * 
	 * @see Signature
	 * @see BBSGroupPublicKey
	 * */
	public Integer getIdentity(String message, BBSSignature signature) throws VerificationFailsException {
		BBSEngine bbsEngine = new BBSEngine( bbsGroupKeyGenerator.getBBSGroupPublicKey() );
		Element openedAi = bbsEngine.open(message, signature, bbsGroupKeyGenerator.getBBSGroupManagerPrivateKey());

		// cercar open (A) dins de la taula de hash
		Integer id = searchAiOnDataBase(openedAi);
		return id;
	}
	
	/**
	 * It searches the element in the HashMap corresponding to the Ai element (see OPEN algorithm)
	 * It is a test method. In a production environment, this method should not be used because
	 * the data will be stored in a database (not in a local HashMap)
	 * 
	 * 
	 * @param openedAi is the element Ai
	 * 
	 * @return Integer The user identity who signs the message
	 * */
	protected Integer searchAiOnDataBase(Element openedAi) {
		Set<Integer> s = hm.keySet();
		Iterator<Integer> it = s.iterator();
		while (it.hasNext()) {
			Integer key = (Integer) it.next();
			AsymmetricCipherKeyPair ackp = hm.get(key);
			BBSUserPrivateKey upk = (BBSUserPrivateKey) ackp.getPrivate();
			if (upk.getA().getElement().isEqual(openedAi)) {
				return key;
			}			
		}
		return -1;
	}
	
	
}
