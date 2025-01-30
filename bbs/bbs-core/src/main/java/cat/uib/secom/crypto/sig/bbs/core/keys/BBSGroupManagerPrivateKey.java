package cat.uib.secom.crypto.sig.bbs.core.keys;

import cat.uib.secom.utils.pairing.ElementWrapper;



public interface BBSGroupManagerPrivateKey {

	public BBSGroupManagerPrivateKey getBBSGroupManagerPrivateKey();

	public ElementWrapper getDelta1();

	public ElementWrapper getDelta2();

	public String toString();

	public String readable();

}