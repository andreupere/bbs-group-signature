package cat.uib.secom.crypto.sig.bbs.core.benchmark;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;



public class BBSLogFile implements BBSLog {
	
	protected FileWriter signfw = null;
	protected BufferedWriter signbw = null;
	
	protected FileWriter verifyfw = null;
	protected BufferedWriter verifybw = null;
	
	protected FileWriter setupfw = null;
	protected BufferedWriter setupbw = null;

	
	
	
	protected FileWriter fw = null;
	protected BufferedWriter bw = null;
	protected File file = null;
	
	
	
	
	public BBSLogFile(String path, String fileName) {
		try {
			File dir = new File(path);
			dir.mkdirs();
			
			File setup = new File(dir, fileName);
			fw = new FileWriter(setup);
			bw = new BufferedWriter(fw);
			
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	
	
	public void verbose(String process, int iteration, String curve, int numberUsers, long time) {
		try {
			bw.append( iteration + "\t" + curve + "\t" + numberUsers + "\t" + time + "\n" );
		} catch (IOException e) {
			e.printStackTrace();
		}
		

	}

	@Override
	public void close() {
		try {
			bw.flush();
			bw.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}

	@Override
	public void error(String arg0) {
		
	}

	@Override
	public void verbose(String str) {
		try {
			bw.append(str);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	
	
	public void startLog(String str) {
		try {
			bw.append(str);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	
	@Override
	public void process(int iteration, String curve, int numberUsers, long time, String process) {
		try {
			bw.append( iteration + "\t" + curve + "\t" + numberUsers + "\t" + time + "\n" );
			System.out.println( process + " " + iteration + "\t" + curve + "\t" + numberUsers + "\t" + time + "\n" );
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}

	/*@Override
	public void setup(int iteration, String curve, int numberUsers, long time) {
		try {
			bw.append( iteration + "\t" + curve + "\t" + numberUsers + "\t" + time + "\n" );
			System.out.println( "setup " + iteration + "\t" + curve + "\t" + numberUsers + "\t" + time + "\n" );
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}

	@Override
	public void sign(int iteration, String curve, int numberUsers, long time) {
		try {
			bw.append( iteration + "\t" + curve + "\t" + numberUsers + "\t" + time + "\n" );
			System.out.println( "sign " + iteration + "\t" + curve + "\t" + numberUsers + "\t" + time + "\n" );
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		
	}*/
	
	

	/*@Override
	public void verify(int iteration, String curve, int numberUsers, long time) {
		try {
			bw.append( iteration + "\t" + curve + "\t" + numberUsers + "\t" + time + "\n" );
			System.out.println("verify " +  iteration + "\t" + curve + "\t" + numberUsers + "\t" + time + "\n" );
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}*/
	
	
//	public void startSign(String str) {
//		try {
//			bw.append(str);
//		} catch (IOException e) {
//			e.printStackTrace();
//		}
//	}
//	
//	public void startVerify(String str) {
//		try {
//			bw.append(str);
//		} catch (IOException e) {
//			e.printStackTrace();
//		}
//	}
//	
//	public void startSetup(String str) {
//		try {
//			bw.append(str);
//		} catch (IOException e) {
//			e.printStackTrace();
//		}
//	}
	
	
}
