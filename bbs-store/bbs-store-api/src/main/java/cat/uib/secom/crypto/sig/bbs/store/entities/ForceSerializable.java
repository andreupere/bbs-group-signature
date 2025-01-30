package cat.uib.secom.crypto.sig.bbs.store.entities;

public interface ForceSerializable {

	
	public ForceSerializable deserialize(String in);
	
	public String serialize();
	
	
}
