package cat.uib.secom.crypto.sig.bbs.core.keys;

import cat.uib.secom.utils.pairing.ElementWrapper;



public interface BBSGroupManagerPrivateElements {

	public ElementWrapper getGamma();

	public BBSGroupManagerPrivateElements getBBSGroupManagerPrivateElements();

	public String toString();

	public String readable();

}