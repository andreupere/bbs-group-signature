package cat.uib.secom.crypto.sig.bbs.core.benchmark;

public class BBSLogConsole implements BBSLog  {

	
	
	public BBSLogConsole() {}
	
	
	
	@Override
	public void verbose(String str) {
		System.out.println(str);
	}
	
	
	
	@Override
	public void error(String str) {
		System.out.println(str);
	}



	@Override
	public void verbose(String process, int iteration, String curve, int numberUsers, long time) {
		System.out.println(process + "\t" + iteration + "\t" + curve + "\t" + numberUsers + "\t" + time);
	}
	
	@Override
	public void close() {
		
	}



	@Override
	public void process(int iteration, String curve, int numberUsers,
			long time, String process) {
		// TODO Auto-generated method stub
		
	}



	@Override
	public void startLog(String str) {
		// TODO Auto-generated method stub
		
	}



	
	
}
