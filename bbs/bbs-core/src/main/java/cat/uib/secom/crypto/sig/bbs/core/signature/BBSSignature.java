package cat.uib.secom.crypto.sig.bbs.core.signature;

import it.unisa.dia.gas.jpbc.Element;

import java.math.BigInteger;

import cat.uib.secom.utils.pairing.ElementWrapper;


public interface BBSSignature {

	public ElementWrapper getT1();
	
	public ElementWrapper getT2();
	
	public ElementWrapper getT3();
	
	public ElementWrapper getC();
	
	public ElementWrapper getSalpha();
	
	public ElementWrapper getSbeta();
	
	public ElementWrapper getSx();
	
	public ElementWrapper getSdelta1();
	
	public ElementWrapper getSdelta2();
	
	
	
	
	
	/*public BigInteger _getT1();
	
	public BigInteger _getT2();
	
	public BigInteger _getT3();
	
	public BigInteger _getC();
	
	public BigInteger _getSalpha();
	
	public BigInteger _getSbeta();
	
	public BigInteger _getSx();
	
	public BigInteger _getSdelta1();
	
	public BigInteger _getSdelta2();*/
	

	
	
	


}