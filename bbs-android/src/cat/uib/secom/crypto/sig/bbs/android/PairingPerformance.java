package cat.uib.secom.crypto.sig.bbs.android;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.CurveParams;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import android.os.Bundle;
import android.app.Activity;
import android.view.Menu;

public class PairingPerformance extends GeneralPerformanceActivity {

	private String[] curveFileNames = {"type_a_r161_q513.param", "type_a1_2primes_512each.param", "type_d_r161_q175.param", "type_e_r161_q1025.param", "type_f_r162_q162.param"}; 
	
	
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_pairing_performance);
        doBenchmark();
        
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.activity_pairing_performance, menu);
        return true;
    }

	@Override
	protected void doBenchmark() {
		for (String curve : curveFileNames) {
			CurveParams cp = new CurveParams();
			cp.load( getClass().getResourceAsStream("/" + curve ) );
			computation(cp);
		}
	}
	
	
	protected void computation(CurveParams cp) {
		System.out.println("curve type: " + cp.getString("type"));
		long mulG1 = 0;
		long mulg1 = 0;
		
		long expG1 = 0;
		long expg1 = 0;
		
		long invG1 = 0;
		long invg1 = 0;
		
		long mulGT = 0;
		long mulgt = 0;
		
		long expGT = 0;
		long expgt = 0;
		
		long invGT = 0;
		long invgt = 0;
		
		long pairingGT = 0;
		long pairinggt = 0;
		
		
		int iterations = 10;
		int it = 0;
		Pairing pairing = PairingFactory.getPairing( cp );
		
		while (it < iterations) {
			System.out.println(it);
			Element g1e = pairing.getG1().newRandomElement();
			Element g2e = pairing.getG2().newRandomElement();
			Element gte = pairing.getGT().newRandomElement();
			Element zpe = pairing.getZr().newRandomElement();
			
			
			// multiplicacio G1
			mulg1 = System.nanoTime();
			g1e.mul(g1e);
			mulg1 = System.nanoTime() - mulg1;
			mulG1 = mulG1 + mulg1;
			
			// exponenciacio G1
			expg1 = System.nanoTime();
			g1e.powZn(zpe);
			expg1 = System.nanoTime() - expg1;
			expG1 = expG1 + expg1;
			
			// inversa G1
			invg1 = System.nanoTime();
			g1e.invert();
			invg1 = System.nanoTime() - invg1;
			invG1 = invG1 + invg1;
			
			// multiplicacio GT
			mulgt = System.nanoTime();
			gte.mul(gte);
			mulgt = System.nanoTime() - mulgt;
			mulGT = mulGT + mulgt;
			
			// exponenciacio GT
			expgt = System.nanoTime();
			gte.powZn(zpe);
			expgt = System.nanoTime() - expgt;
			expGT = expGT + expgt;
			
			// inversa GT
			invgt = System.nanoTime();
			gte.invert();
			invgt = System.nanoTime() - invgt;
			invGT = invGT + invgt;
			
			// pairing GT (G1,G2)
			pairinggt = System.nanoTime();
			pairing.pairing(g1e, g2e);
			pairinggt = System.nanoTime() - pairinggt;
			pairingGT = pairingGT + pairinggt;
			
			it++;
			
		}
		System.out.println("curve type: " + cp.getString("type"));
		System.out.println("mulG1: " + (mulG1/iterations));
		System.out.println("expG1: " + (expG1/iterations));
		System.out.println("invG1: " + (invG1/iterations));
		System.out.println("mulGT: " + (mulGT/iterations));
		System.out.println("expGT: " + (expGT/iterations));
		System.out.println("invGT: " + (invGT/iterations));
		System.out.println("paiGT: " + (pairingGT/iterations));
	}
	
	
}
