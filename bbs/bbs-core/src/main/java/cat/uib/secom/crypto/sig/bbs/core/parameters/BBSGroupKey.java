package cat.uib.secom.crypto.sig.bbs.core.parameters;


import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;



public abstract class BBSGroupKey extends AsymmetricKeyParameter implements CipherParameters {


	public BBSGroupKey(boolean isPrivate) {
		super(isPrivate);
	}

}
