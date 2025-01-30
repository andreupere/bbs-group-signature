package cat.uib.secom.crypto.sig.bbs.store.entities;

public interface BBSGroupPublicKey {

	
	public String getG1();
	
	public void setG1(String g1);
	
	
	
	public String getG2();
	
	public void setG2(String g2);
	
	
	
	public String getH();
	
	public void setH(String h);
	
	
	
	public String getU();
	
	public void setU(String u);
	
	
	
	public String getV();
	
	public void setV(String v);
	
	
	
	public String getOmega();
	
	public void setOmega(String omega);
	
	
	
	
//	public String serialize();
//	public BBSGroupPublicKey deserialize(String in);
	
}
