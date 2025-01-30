package cat.uib.secom.crypto.sig.bbs.core.keys;


import org.spongycastle.crypto.CipherParameters;

import cat.uib.secom.utils.pairing.ElementWrapper;

import it.unisa.dia.gas.jpbc.Pairing;





public interface BBSGroupPublicKey {

	public ElementWrapper getG1();

	public ElementWrapper getG2();

	public ElementWrapper getH();

	public ElementWrapper getU();

	public ElementWrapper getV();

	public ElementWrapper getOmega();

	public Pairing getPairing();

	public String getR();

	/**
	 * Return the whole object
	 * */
	public BBSGroupPublicKey getBBSGroupPublicKey();

	public String toString();

	public String readable();

}