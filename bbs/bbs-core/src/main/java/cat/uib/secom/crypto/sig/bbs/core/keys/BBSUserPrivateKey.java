package cat.uib.secom.crypto.sig.bbs.core.keys;


import org.spongycastle.crypto.CipherParameters;

import cat.uib.secom.utils.pairing.ElementWrapper;




public interface BBSUserPrivateKey {

	/**
	 * Return the whole object
	 * */
	public BBSUserPrivateKey getBBSUserPrivateKey();

	public ElementWrapper getA();

	public ElementWrapper getX();

	public String toString();

	public String readable();

}