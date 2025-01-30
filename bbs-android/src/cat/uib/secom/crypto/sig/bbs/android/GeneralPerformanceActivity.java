package cat.uib.secom.crypto.sig.bbs.android;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;

import cat.uib.secom.crypto.sig.bbs.core.benchmark.BBSLog;
import cat.uib.secom.crypto.sig.bbs.core.benchmark.BBSLogFile;
import android.app.Activity;
import android.os.Environment;

public abstract class GeneralPerformanceActivity extends Activity {

	protected BBSLog log;
	
	protected static Integer ITERATIONS = 10;
	
	protected String path;
	
	
	public void prepareTest(String relativePath, String logFileName) {
		Date date = new Date();
		SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd");
    	File sdCardPath = Environment.getExternalStorageDirectory();
    	path = sdCardPath.getAbsolutePath() + relativePath + sdf.format(date) + "/";
    	log = new BBSLogFile(path, logFileName);
	}
	
	protected abstract void doBenchmark();
	
}
