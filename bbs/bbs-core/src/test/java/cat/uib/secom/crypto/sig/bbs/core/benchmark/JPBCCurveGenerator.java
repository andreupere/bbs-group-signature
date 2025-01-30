package cat.uib.secom.crypto.sig.bbs.core.benchmark;

import java.math.BigInteger;

import java.util.Random;

import org.junit.Ignore;
import org.junit.Test;

import junit.framework.TestCase;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.e.TypeECurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.f.TypeFCurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.CurveParams;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
//import it.unisa.dia.gas.plaf.jpbc.pbc.curve.PBCTypeGCurveGenerator;
import it.unisa.dia.gas.jpbc.*;


public class JPBCCurveGenerator {
	
	private CurveParameters cpA;
	private CurveParameters cpA1;
	private CurveParameters cpE;
	private CurveParameters cpF;

	
	@Ignore("not using")
	@Test
	public void typeA() {
		//int rBits = 512;
		//int qBits = 512;
		int rBits = 160;
		int qBits = 512;
		CurveGenerator curveGenerator = new TypeACurveGenerator(rBits, qBits);
		cpA = curveGenerator.generate();
		System.out.println("\n\n############ TYPE A ############");
		computation(cpA);
	}
	
	@Ignore("not using")
	@Test
	public void typeA1() {
		// Init the generator...
		int nPrimes = 2;
		int lengthPrimes = 256;
		//int lengthPrimes = 159;
		//int lengthPrimes = 511;
		CurveGenerator curveGenerator = new TypeA1CurveGenerator(nPrimes, lengthPrimes);
		cpA1 = curveGenerator.generate();
		System.out.println("\n\n############ TYPE A1 ############");
		computation(cpA1);
		
	}
	
	// TypeD needs PBC wrapper
//	public void testTypeD() {
//		int discriminant = 9563;
//		CurveGenerator curveGenerator = new PBCTypeDCurveGenerator(discriminant);
//	}
	
	@Ignore("not using")
	@Test
	public void typeE() {
		int rBits = 160;
		int qBits = 1024;
		CurveGenerator curveGenerator = new TypeECurveGenerator(rBits, qBits);
		cpE = curveGenerator.generate();
		System.out.println("\n\n############ TYPE E ############");
		computation(cpE);
	}
	
	
	@Ignore("not using")
	@Test
	public void typeF() {
		//int rBits = 87;
		int rBits = 160;
		CurveGenerator curveGenerator = new TypeFCurveGenerator(rBits);
		cpF = curveGenerator.generate();
		System.out.println("\n\n############ TYPE F ############");
		computation(cpF);
	}
	
	
	@Ignore("not using")
	@Test
	public void typeG() {
		// only with PBC wrapper
		@SuppressWarnings("unused")
		int discriminant = 35707;
		//CurveGenerator curveGenerator = new PBCTypeGCurveGenerator(discriminant);
		//cpG = curveGenerator.generate();
		//System.out.println("\n\n############ TYPE G ############");
		//computation(cpG);
	}
	
	
	@Test
	public void curveFiles() {
		String[] curveFileNames = {"type_a_r161_q513.param", "type_a1_2primes_512each.param", "type_d_r161_q175.param", "type_e_r161_q1025.param", "type_f_r162_q162.param"}; 
		
		for (String curve : curveFileNames) {
			CurveParams cp = new CurveParams();
			cp.load( getClass().getResourceAsStream("/" + curve ) );
			computation(cp);
		}
	}
	
	@Ignore("not using")
	@Test
	public void computation(CurveParameters cp) {
		
		
		Pairing pairing = PairingFactory.getPairing( cp );
		
		System.out.println(cp);
		System.out.println("pairing type? " + pairing.getClass());
		
		
		Element e1 = pairing.getG1().newRandomElement();
		Element e2 = pairing.getG2().newRandomElement();
		Element z1 = pairing.getZr().newRandomElement();
		Element gt = pairing.getGT().newRandomElement();
		System.out.println("g1 element length (bits):" + e1.getLengthInBytes()*8);
		System.out.println("g2 element length (bits):" + e2.getLengthInBytes()*8);
		System.out.println("z1 element length (bits):" + z1.getLengthInBytes()*8);
		System.out.println("z1 order " + z1.getField().getOrder());
		System.out.println("gt element length (bits):" + gt.getLengthInBytes()*8);
		
		System.out.println("g1 order length (bits):" + e1.getField().getOrder().bitLength());
		System.out.println("g2 order length (bits):" + e2.getField().getOrder().bitLength());
		System.out.println("z1 order length (bits):" + z1.getField().getOrder().bitLength());
		System.out.println("gt order length (bits):" + gt.getField().getOrder().bitLength());
		
		
		
//		Element a = pairing.getZr().newRandomElement();
//		System.out.println( a + " length: " + a.getLengthInBytes() );
//		
//		a = pairing.getZr().newRandomElement();
//		System.out.println( a + " length: " + a.getLengthInBytes() );
//		
//		a = pairing.getZr().newRandomElement();
//		System.out.println( a + " length: " + a.getLengthInBytes() );
//		
//		a = pairing.getZr().newRandomElement();
//		System.out.println( a + " length: " + a.getLengthInBytes() );
//		
//		//TypeEPairing pa = (TypeEPairing)pairing;
//		
//		
//		
//		long before = System.currentTimeMillis();
//		Element p1 = pairing.pairing(e1, e2);
//		long after = System.currentTimeMillis();
//		
//		long time = after - before;
//		System.out.println("pairing calculation=" + time + " ms");
//		
//		Element zn = pairing.getZr().newRandomElement();
//		before = System.currentTimeMillis();
//		e1.powZn(zn);
//		after = System.currentTimeMillis();
//		time = after - before;
//		
//		System.out.println("exponentiation calculation=" + time + "ms ; (zn " + zn.getLengthInBytes()*8 +"bits)");
//		
//		before = System.currentTimeMillis();
//		e1.mulZn(zn);
//		after = System.currentTimeMillis();
//		
//		time = after - before;
//		System.out.println("multiplication calculation=" + time + "ms ; (zn " + zn.getLengthInBytes()*8 +"bits)");
//		
		
//		BigInteger b1 = new BigInteger("2487563201");
//		BigInteger exp = new BigInteger("1244841510000252350013699241122000145221002554852236845001015248569740125247410369854785210259637410258930014785");
//		BigInteger mod = new BigInteger("98745256325474521475896541841212412015120001275212526506596500445604606045645405045054054545485857435965231231574564156796234154614857404744890906");
//		
//		before = System.currentTimeMillis();
//		b1.modPow(exp, mod);
//		after = System.currentTimeMillis();
//		time = after - before;
//		
//		System.out.println("b1.length=" + b1.bitCount() + "bits");
//		System.out.println("exp.length=" + exp.bitCount() + "bits");
//		System.out.println("mod.length=" + mod.bitCount() + "bits");
//		System.out.println("exponentiation calculation=" + time + "ms");
		
		System.out.println("\n\n\n\n");
	}
	
	/**
	 * @deprecated
	 * */
	@Ignore("not using")
	@Test
	public void expBigInteger() {
		BigInteger b1 = new BigInteger("24875631248756312448415100006992411220001452210025548522848456046840456048424875631244841510000699241122000145221002554852284845604684045604842448415100006992424875631244841510000699241122000145221002554852284845604684045604841122000145221002554852284845604684045604840248756312487563124484151000069924112200014522100255485228484560468404560484244841510000699241122000145221002554852284845604684045604840484804045454540440840465210456406404645640400484845456450454005560540564564040564545600054050454540504504504540121510101368450010152485697401248756312448415100006992411222487563124484151000069924112200014522100255485228484560468404560484000145221002554852284845604684045604842501");
		BigInteger exp170 = new BigInteger("1244841510000699241122000145221002554852236845001015248569740125247410369854785210259637410258930014785");
		BigInteger exp1024 = new BigInteger("41121545154540440840465210456406404645640400484845456450454056054056456404056454560005405045454050450450454012151010156156408484560468404560484004848040454504406450484564564080454540002327800325652200014400022351020154840618080000000040541545640400044545484044840840404044084404554044884840454654411215451545404408404604564064046456404004848454564504540560540564564040564545600054050454540504504504540121510101561564084845604684045604840048480404545044064504845441000125464564080454545102015484061808015415151521545154841054545044854054684604000004561650040541545640400044545484044840840404044084404554044884840454654");
		BigInteger exp1400 = new BigInteger("41121545154540440840465210456406404645640400484845456450454056054056456404056454560005405045454050450450454012151010156156408484560468404560484004848040454545404408404652104564064046456404004848454564504540054056456456204056454560005405045454050450450454012151010156112225523564084845604684050440645048456456408045454000232780032565220001440002235102015484061808000000004054154564040004454548404484084040404408440455404488484045465441121545154540440840460456406404645640400484845456450454056054056456404056454560005405045454050450450454012151010156156408484560468404560484004848040454504406450484544100012546456408045454510201548406180801541515152154515484105454504485405468460400121511341540545640540540854545645044545484231512156486721000104500052585420025210000004561650040541545640400044545484044840840404044084404554044884840454654");
		BigInteger mod = new BigInteger("0454015101015612487563124484151000069924112200014522100255485228484560468404560484564084845604684045604840048480404545454044084046521045640640464564040048484545645045400556054056456404056454560005405045454050450450454012151010156156408484560468404560484004848040454545404408404652104564064046456404004848454564504540054056456456204056454560005405045454050450450454012151010156112225523564084845604684050440645048456456408045454000232780032565220001440002235102015484061808000000004054154564040004454548404484084040404408440455404488484045465441121545154540440840460456406404645640400484845456450454056054056456404056454560005405045454050450450454012151010156156408484560468404560484004848040454504406450484544100012546456408045454510201548406180801541515152154515484105454504485405468460400121511341540545640540540854545645044545484231512156486721000104500052585420025210000004561650040541545640400044545484044840840404044084404554044884840454654");
		
		
		long before = System.currentTimeMillis();
		b1.modPow(exp170, mod);
		long after = System.currentTimeMillis();
		long time = after - before;
		
		System.out.println("b1.length=" + b1.bitCount() + "bits");
		System.out.println("b1.length=" + b1.bitLength() + "bits");
		
		System.out.println("exp.length (170)=" + exp170.bitCount() + "bits");
		System.out.println("exponentiation calculation =" + time + "ms");
		
		before = System.currentTimeMillis();
		b1.modPow(exp1024, mod);
		after = System.currentTimeMillis();
		time = after - before;
		
		System.out.println("exp.length (1024)=" + exp1024.bitCount() + "bits");
		System.out.println("exponentiation calculation =" + time + "ms");
		
		
		before = System.currentTimeMillis();
		b1.modPow(exp1400, mod);
		after = System.currentTimeMillis();
		time = after - before;
		
		System.out.println("exp.length (1400)=" + exp1400.bitCount() + "bits");
		System.out.println("exponentiation calculation =" + time + "ms");
		
		System.out.println("mod.length=" + mod.bitCount() + "bits");
		
		
		
	}
	
	@Ignore("not using")
	@Test
	public void gen() {
		try {
			
			BigInteger b = new BigInteger(1024, new Random());
			BigInteger m = new BigInteger(2048, new Random());
			BigInteger s170 = new BigInteger(170, new Random());
			BigInteger l1024 = new BigInteger(1024, new Random());
			BigInteger l1344 = new BigInteger(1344, new Random());
			BigInteger l2048 = new BigInteger(2048, new Random());
			
			long before = System.nanoTime();
			b.modPow(s170, m);
			long after = System.nanoTime();
			long exp1 = after - before;
			System.out.println("exponentiation calculation =" + exp1 + "ns (" + s170.bitLength() + ")");
			
			
			before = System.nanoTime();
			b.multiply(s170);
			after = System.nanoTime();
			long mul1 = after - before;
			System.out.println("multiply calculation=" + mul1 + "ns (" + (exp1/mul1) + ") (" + (exp1/mul1)/s170.bitLength() + ")");
			
			
			
			
			before = System.nanoTime();
			b.modPow(s170, m);
			after = System.nanoTime();
			exp1 = after - before;
			System.out.println("exponentiation calculation =" + exp1 + "ns (" + s170.bitLength() + ")");
			
			
			before = System.nanoTime();
			b.multiply(s170);
			after = System.nanoTime();
			mul1 = after - before;
			System.out.println("multiply calculation=" + mul1 + "ns (" + (exp1/mul1) + ") (" + (exp1/mul1)/s170.bitLength() + ")");
			
			
			
			
			
			before = System.nanoTime();
			b.modPow(l1024, m);
			after = System.nanoTime();
			long exp2 = after - before;
			System.out.println("exponentiation calculation =" + exp2 + "ns (" + l1024.bitLength() + ")");
			
			before = System.nanoTime();
			b.multiply(l1024);
			after = System.nanoTime();
			long mul2 = after - before;
			System.out.println("multiply calculation=" + mul2 + "ns (" + (exp2/mul2) + ") (" + (exp2/mul2)/l1024.bitLength() + ")");
			
			
			
			
			before = System.nanoTime();
			b.modPow(l1344, m);
			after = System.nanoTime();
			long exp3 = after - before;
			System.out.println("exponentiation calculation =" + exp3 + "ns (" + l1344.bitLength() + ")");
			
			
			before = System.nanoTime();
			b.multiply(l1344);
			after = System.nanoTime();
			long mul3 = after - before;
			System.out.println("multiply calculation=" + mul3 + "ns (" + (exp3/mul3) + ") (" + (exp3/mul3)/l1344.bitLength() + ")");
			
			
			
			
			before = System.nanoTime();
			b.modPow(l2048, m);
			after = System.nanoTime();
			long exp4 = after - before;
			System.out.println("exponentiation calculation =" + exp4 + "ns (" + l2048.bitLength() + ")");
			
			before = System.nanoTime();
			b.multiply(l2048);
			after = System.nanoTime();
			long mul4 = after - before;
			System.out.println("multiply calculation=" + mul4 + "ns (" + (exp4/mul4) + ") (" + (exp4/mul4)/l2048.bitLength() + ")");
			
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
	
	
	
	
}
