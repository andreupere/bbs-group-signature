package cat.uib.secom.crypto.sig.bbs.core.parameters;



import cat.uib.secom.utils.pairing.ElementWrapper;
import it.unisa.dia.gas.jpbc.CurveParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.CurveParams;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;


/**
 * @author Andreu Pere
 * 
 * Stores elements needed for the KEYGEN algorithm: g1, g2, pairing
 */
public class BBSParameters {
	
	/**
	 * It is the filename (not path) where is stored the elliptic curve parameters
	 * */
	private String curveDescriptionFileName;
	
	/**
	 * Object from jPBC which loads and stores the elliptic curve parameters
	 * */
	private CurveParams curveParams;
	
	/**
	 * A Element representing g1 (random element from G1)
	 * */
	private ElementWrapper g1;
	
	/**
	 * A Element representing g2 (random element from G2)
	 * */
	private ElementWrapper g2;
	
	/**
	 * A Pairing object
	 * */
	private Pairing pairing;
	
	/**
	 * The number of users of the group signature
	 * */
	private int numberUsers;
	
	
	/**
	 * It constructs BBSParameters in the server side
	 * 
	 * @param curveDescriptionFileName is the name of file containing the description of the curve will be used 
	 * @param numberUsers is the number of users in the group
	 */
	public BBSParameters(String curveDescriptionFileName, int numberUsers) {
		this.curveDescriptionFileName = curveDescriptionFileName;
		this.curveParams = new CurveParams();
		this.numberUsers = numberUsers;
	}
	
	/**
	 * It constructs BBSParameters in the client side
	 * 
	 * @param curveDescriptionFileName is the name of file containing the description of the curve will be used
	 * */
	public BBSParameters(String curveDescriptionFileName) {
		this.curveDescriptionFileName = curveDescriptionFileName;
		this.curveParams = new CurveParams();
	}
	
	/**
	 * It generates g1 and g2 from the pairing and loaded curve parameters
	 * */
	public BBSParameters generate() {
		loadCurveParameters();
		g1 = new ElementWrapper( pairing.getG1().newRandomElement().getImmutable() );
		g2 = new ElementWrapper( pairing.getG2().newRandomElement().getImmutable() );
		return this;
	}
	
	
	public ElementWrapper generateG1() {
		loadCurveParameters();
		return new ElementWrapper( pairing.getG1().newRandomElement().getImmutable() );
	}
	public ElementWrapper generateG2() {
		loadCurveParameters();
		return new ElementWrapper( pairing.getG2().newRandomElement().getImmutable() );
	}
	public byte[] generateG1bytes() {
		return generateG1().toByteArray();
	}
	public byte[] generateG2bytes() {
		return generateG2().toByteArray();
	}
	
	
	/**
	 * It generates a random g2 and uses the g1 provided by parameter
	 * It will be useful if g1 is fixed by the system (for generator use; for all users) and
	 * g2 is different for each group signature.
	 * 
	 * @param g1
	 * @return BBSParameters
	 * */
	public BBSParameters generate(byte[] g1) {
		loadCurveParameters();
		Element g1e = pairing.getG1().newOneElement();
		g1e.getImmutable();
		g1e.setFromBytes(g1);
		this.g1 = new ElementWrapper( g1e );
		//this.g1.getElement().setFromBytes(g1);
		//this.g1.getElement().getImmutable();
		this.g2 = new ElementWrapper( pairing.getG2().newRandomElement().getImmutable() );
		return this;
	}
	
	/**
	 * It stores the elements g1 and g2 (in byte[] format) received through the network from GroupManager in the client side
	 * 
	 * @param g1
	 * @param g2
	 * */
	public BBSParameters generate(byte[] g1, byte[] g2) {
		loadCurveParameters();
		Element g1e = pairing.getG1().newElement();
		g1e.setFromBytes(g1);
		g1e.getImmutable();
		Element g2e = pairing.getG2().newElement();
		g1e.setFromBytes(g2);
		g2e.getImmutable();
		this.g1 = new ElementWrapper( g1e );
		this.g2 = new ElementWrapper( g2e );

		// make immutable elements
		this.g1.getElement().getImmutable();
		this.g2.getElement().getImmutable();
		// return object
		return this;
	}
	
	/**
	 * It stores the elements g1 and g2 (in Element format) received through the network from GroupManager in the client side
	 * 
	 * @param g1
	 * @param g2
	 * */
	public BBSParameters generate(ElementWrapper g1, ElementWrapper g2) {
		loadCurveParameters();
		this.g1 = g1;
		this.g2 = g2;
		// make immutable elements
		this.g1.getElement().getImmutable();
		this.g2.getElement().getImmutable();
		// return object
		return this;
	}
	
	
	
	
	public String getCurveDescriptionFileName() {
		return curveDescriptionFileName;
	}


	public ElementWrapper getG2() {
		return g2;
	}

	public ElementWrapper getG1() {
		return g1;
	}
	
	public CurveParameters getCurveParams() {
		return curveParams;
	}
	
	public Pairing getPairing() {
		if ( pairing == null ) {
			loadCurveParameters();
		}
		return pairing;
	}


	public int getNumberUsers() {
		return numberUsers;
	}
	
	
	/**
	 * Load elliptic curve parameters from the specified file
	 * */
	private void loadCurveParameters() {
		//curveParams.load( BBSParameters.class.getClassLoader().getResourceAsStream(BBSHelpers.RESOURCES_PACKAGE + this.getCurveDescriptionFileName()) );
		curveParams.load( getClass().getResourceAsStream("/" + this.getCurveDescriptionFileName()) );
		pairing = PairingFactory.getPairing(getCurveParams());
	}
	
}
