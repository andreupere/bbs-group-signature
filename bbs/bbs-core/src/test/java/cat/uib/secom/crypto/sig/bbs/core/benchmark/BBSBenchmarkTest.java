package cat.uib.secom.crypto.sig.bbs.core.benchmark;



import java.text.SimpleDateFormat;

import java.util.Date;

import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import cat.uib.secom.crypto.sig.bbs.core.exception.VerificationFailsException;




public class BBSBenchmarkTest {

	private BBSLog bbsLog, bbsSignLog, bbsVerificationLog, bbsOpenLog;
	private BBSBenchmark bbsBenchmark;
	private static Date date;
	private static SimpleDateFormat sdf;
	private static String path;
	
	// config parameters test
	//private int[] numberUsers = {1, 20, 40, 60, 80, 100};
	private int[] numberUsers = {10, 100, 200, 300, 400, 500};
	//private int[] numberUsers = {300,400};
	//private String[] curveFileNames = {"a_181_603.param", "d840347-175-161.param", "a1.param", "e.param", "f.param"}; //arxius originals
	
	/**
	 * 
	 * arxius adaptats per tenir Dlog security (bits) = 1024 (http://crypto.stanford.edu/pbc/times.html)
	 * (nivell de seguretat de 1024 bits)
	 */
	private String[] curveFileNames = {"type_a_r161_q513.param", "type_a1_2primes_512each.param", "type_d_r161_q175.param", "type_e_r161_q1025.param", "type_f_r162_q162.param"}; 
	//private String[] curveFileNames = {"dtype_q175_r167.param"}; 
	private Integer iterations = 1;
	
	private boolean precomputation = true;
	
	@BeforeClass
	public static void start() {	
		
		date = new Date();
		sdf = new SimpleDateFormat("yyyyMMdd_HHmm");
		path = "benchmark/" + sdf.format(date) + "/";
		
	}
	
	@Ignore("not using")
	@Test
	public void failingtestBBSBenchmarkSetup() {
		
		bbsLog = new BBSLogFile(path, "setup.log");
		bbsLog.startLog("#on " + "java VM" + "\n");
		bbsLog.startLog("#it \t curve \t n \t time (ms) \n");		
		
		bbsBenchmark = new BBSBenchmark(null, curveFileNames, numberUsers, iterations, false);
		bbsBenchmark.benchmarkGroupManagerSetup(bbsLog);
		
		bbsLog.close();
		
	}
	
	@Ignore("not using")
	@Test
	public void testBBSBenchmarkSignVerify() {
		try {
			bbsSignLog = new BBSLogFile(path, "sign.log");
			bbsSignLog.startLog("#on " + "java VM" + " precomputation OFF\n");
			bbsSignLog.startLog("#it \t curve \t n \t time (ms) \n");
			
			bbsVerificationLog = new BBSLogFile(path, "verify.log");
			bbsVerificationLog.startLog("#on " + "java VM" + " precomputation OFF\n");
			bbsVerificationLog.startLog("#it \t curve \t n \t time (ns) \n");
			
			
			bbsBenchmark = new BBSBenchmark(null, curveFileNames, numberUsers, iterations, precomputation);
			bbsBenchmark.benchmarkSignVerify(bbsSignLog, bbsVerificationLog);
			
			bbsSignLog.close();
			bbsVerificationLog.close();
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	@Ignore("not using")
	@Test
	public void testBBSBenchmarkOpen() {
		try {
			bbsOpenLog = new BBSLogFile(path, "open.log");
			bbsOpenLog.startLog("#on " + "java VM" + " precomputation OFF\n");
			bbsOpenLog.startLog("#it \t curve \t n \t time (ms) \n");
			
			bbsBenchmark = new BBSBenchmark(null, curveFileNames, numberUsers, iterations, false);
		
			bbsBenchmark.benchmarkOpen(bbsOpenLog);
			bbsOpenLog.close();
		} catch (VerificationFailsException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		
	}
	
	
	@Ignore("not using")
	@Test
	public void failingtestBBSGroupSignatureElementsLength() {
		try {
			int[] numberUsers = {10};
			String[] curveFileNames = {"type_a_r161_q513.param", "type_a1_2primes_512each.param", "type_d_r161_q175.param", "type_e_r161_q1025.param", "type_f_r162_q162.param", "type_g_r279_q301.param"}; 
			
			bbsBenchmark = new BBSBenchmark(null, curveFileNames, numberUsers, 1, precomputation);
			bbsBenchmark.groupSignatureElementsLength();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
}
