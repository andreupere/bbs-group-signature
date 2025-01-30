package cat.uib.secom.crypto.sig.bbs.android;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;

import cat.uib.secom.crypto.sig.bbs.core.benchmark.BBSBenchmark;
import cat.uib.secom.crypto.sig.bbs.core.benchmark.BBSLog;
import cat.uib.secom.crypto.sig.bbs.core.benchmark.BBSLogFile;
import android.os.Bundle;
import android.os.Environment;
import android.app.Activity;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.support.v4.app.NavUtils;

public class BBSBenchmarkActivity extends GeneralPerformanceActivity {
	
	protected static String TAG = "bbs-performance";
	
	protected static String RELATIVE_PATH = "/bbs_performance/";
	
	protected static String FILE_NAME_SIGN = "sign.csv";
	
	protected static String FILE_NAME_VERIFY = "verify.csv";
	
	protected BBSLog bbsSignLog;
	
	protected BBSLog bbsVerifyLog;
	
	protected BBSBenchmark bbsBenchmark;
	
	
	private String[] curveFileNames = {"type_a_r161_q513.param", "type_a1_2primes_512each.param", "type_d_r161_q175.param", "type_e_r161_q1025.param", "type_f_r162_q162.param"}; 
	
	protected int[] NUMBER_USERS = {10};
	
	protected String device = android.os.Build.MODEL;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_bbsbenchmark);
        
        Date date = new Date();
		SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd");
    	File sdCardPath = Environment.getExternalStorageDirectory();
    	path = sdCardPath.getAbsolutePath() + RELATIVE_PATH + sdf.format(date) + "/";
    	
    	bbsSignLog = new BBSLogFile(path, FILE_NAME_SIGN);
    	bbsVerifyLog = new BBSLogFile(path, FILE_NAME_VERIFY);        

        doBenchmark();
        
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.activity_bbsbenchmark, menu);
        return true;
    }

    /**
     * Signature and verification of Group Signature Performance Test
     * */
	@Override
	protected void doBenchmark() {
		Log.v(TAG, "hola");
		process(false);
		process(true);

	}
	
	protected void process(boolean precomputation) {
		try {
			bbsSignLog.startLog("#on " + device + " precomputation " + precomputation + "\n");
			bbsSignLog.startLog("#signature testing");
			bbsSignLog.startLog("#it \t curve \t n \t time (ns) \n");
			
			bbsVerifyLog.startLog("#on " + device + " precomputation " + precomputation + "\n");
			bbsVerifyLog.startLog("#verification testing");
			bbsVerifyLog.startLog("#it \t curve \t n \t time (ns) \n");
			
			
			bbsBenchmark = new BBSBenchmark(null, curveFileNames, NUMBER_USERS, ITERATIONS, precomputation);
			bbsBenchmark.benchmarkSignVerify(bbsSignLog, bbsVerifyLog);
			
			bbsSignLog.close();
			bbsVerifyLog.close();
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	


    
}
