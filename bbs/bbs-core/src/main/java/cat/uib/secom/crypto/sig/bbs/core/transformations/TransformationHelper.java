package cat.uib.secom.crypto.sig.bbs.core.transformations;

import cat.uib.secom.crypto.sig.bbs.core.parameters.BBSParameters;
import cat.uib.secom.utils.pairing.ElementWrapper;
import cat.uib.secom.utils.pairing.PairingHelper;



/**
 * @author Andreu Pere
 * 
 * Helper that helps to transform ElementWrapper elements from hex strings taking account of group (G1, G2 or Zr)
 * 
 * */
public class TransformationHelper {
	
	// elements from group signature
	public static String T1 = "t1";
	public static String T2 = "t2";
	public static String T3 = "t3";
	public static String C = "c";
	public static String SALPHA = "salpha";
	public static String SBETA = "sbeta";
	public static String SX = "sx";
	public static String SDELTA1 = "sdelta1";
	public static String SDELTA2 = "sdelta2";
	
	// elements from user private key
	public static String A = "a";
	public static String X = "x";
	
	
	// elements from group public key	
	public static String G1 = "g1";
	public static String G2 = "g2";
	public static String H = "h";
	public static String U = "u";
	public static String V = "v";
	public static String OMEGA = "omega";
	
	
	private static String group;
	
	public static ElementWrapper toElementWrapperFromHexString(String hexString, String elementName, BBSParameters bbsParameters) throws Exception {
		
		if (elementName == T1)
			group = "G1";
		else if (elementName == T2)
			group = "G1";
		else if (elementName == T3)
			group = "G1";
		else if (elementName == C)
			group = "Zr";
		else if (elementName == SALPHA)
			group = "Zr";
		else if (elementName == SBETA)
			group = "Zr";
		else if (elementName == SX)
			group = "Zr";
		else if (elementName == SDELTA1)
			group = "Zr";
		else if (elementName == SDELTA2)
			group = "Zr";
		else if (elementName == A)
			group = "G1";
		else if (elementName == X)
			group = "Zr";
		else if (elementName == G1)
			group = "G1";
		else if (elementName == G2)
			group = "G2";
		else if (elementName == H)
			group = "G1";
		else if (elementName == U)
			group = "G1";
		else if (elementName == V)
			group = "G1";
		else if (elementName == OMEGA)
			group = "G2";
		else
			throw new Exception("Unknown element name... \n" +
					"			 Allowed names: T1, T2, T3, C, SALPHA, SBETA, SX, SDELTA1, SDELTA2, A, X, G1, G2, H, U, V, OMEGA");
			
		
		ElementWrapper ew = PairingHelper.toElementWrapper(hexString, bbsParameters.getPairing(), group);
		return ew;
	}

}
