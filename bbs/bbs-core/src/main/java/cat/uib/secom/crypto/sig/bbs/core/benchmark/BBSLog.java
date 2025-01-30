package cat.uib.secom.crypto.sig.bbs.core.benchmark;

public interface BBSLog {
	
	public void verbose(String process, int iteration, String curve, int numberUsers, long time);
	
	public void verbose(String str);
	
	public void error(String str);
	
	public void close();
	
	public void process(int iteration, String curve, int numberUsers, long time, String process);
	
	public void startLog(String str);
	
	//public void sign(int iteration, String curve, int numberUsers, long time);
	
	//public void verify(int iteration, String curve, int numberUsers, long time);
	
	//public void setup(int iteration, String curve, int numberUsers, long time);
	
//	public void startSetup(String str);
//	public void startSign(String str);
//	public void startVerify(String str);


}
