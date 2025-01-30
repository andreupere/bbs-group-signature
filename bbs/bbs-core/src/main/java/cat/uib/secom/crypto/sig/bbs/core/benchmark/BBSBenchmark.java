package cat.uib.secom.crypto.sig.bbs.core.benchmark;


import it.unisa.dia.gas.jpbc.Pairing;
import cat.uib.secom.crypto.sig.bbs.core.accessors.enhanced.GroupManagerAccessor;
import cat.uib.secom.crypto.sig.bbs.core.accessors.enhanced.SignerAccessor;
import cat.uib.secom.crypto.sig.bbs.core.accessors.enhanced.VerifierAccessor;
import cat.uib.secom.crypto.sig.bbs.core.engines.BBSEngine;
import cat.uib.secom.crypto.sig.bbs.core.engines.BBSEnginePrecomputation;
import cat.uib.secom.crypto.sig.bbs.core.exception.VerificationFailsException;
import cat.uib.secom.crypto.sig.bbs.core.signature.BBSSignature;

public class BBSBenchmark {
	
	private static String[] CURVE_FILE_NAMES = {"a_181_603.param",
										        //"d159.properties",
										        "d840347-175-161.param"};

	private static int[] NUMBER_USERS = {1, 20, 40, 60, 80, 100};
	
	private int maxIterations = 1;

	private String message = "Hello BBS Signature scheme";
	private int signerID = 1;
	private int verifierID = 1;
	
	//private int numberUsers = 5;
	
	private GroupManagerAccessor groupManager;
	private SignerAccessor signer;
	private VerifierAccessor verifier;
	private BBSSignature signature;
	
	private BBSLog bbsLog;
	
	
	private String[] curveFileNamesVector = CURVE_FILE_NAMES;
	private int[] numberUsersVector = NUMBER_USERS;
	private boolean precomputation = false;
	
	
	public BBSBenchmark(BBSLog bbsLog) {
		this.bbsLog = bbsLog;
	}
	
	public BBSBenchmark(BBSLog bbsLog, String[] curveFileNames, int[] numberUsers, int maxIterations, boolean precomputation) {
		this.bbsLog = bbsLog;
		this.curveFileNamesVector = curveFileNames;
		this.numberUsersVector = numberUsers;
		this.maxIterations = maxIterations;
		this.precomputation = precomputation;
	}
	
	
	public void benchmarkGroupManagerSetup(BBSLog bbsSetupLog) {
		
       
		// benchmark fields
		long start = 0;
		long end = 0;
		long total = 0;
		long partial = 0;
		long average = 0;
		int i = 1;
		
		
		
		// group manager setup bechmark
		for (String curve : curveFileNamesVector) {			
			for (int numberUsers : numberUsersVector ) {
				groupManager = new GroupManagerAccessor(numberUsers, curve);
				while (i <= maxIterations) {
			        start = System.currentTimeMillis();
					groupManager.setup();
					partial = System.currentTimeMillis() - start;
					
					Pairing pairing = groupManager.getBBSParameters().getPairing();
					
					//if (curve.indexOf("dtype") != -1 || curve.indexOf("a1type") != -1)
						//System.out.println(groupManager.getBBSParameters().getCurveParams().getBigInteger("n").bitLength());
					//else if (curve.indexOf("atype") != -1 || curve.indexOf("ftype") != -1)
						//System.out.println(groupManager.getBBSParameters().getCurveParams().getBigInteger("r").bitLength());
					
					
					//System.out.println("curve=" + curve + "\n" +
					//				   "order=" + pairing.getG1().getOrder().bitLength() + " " + pairing.getG2().getOrder().bitLength() + "\n" +
					//				   "g1 length(bits)=" + pairing.getG1().newRandomElement().getLengthInBytes()*8 + "\n" +
					//				   "g2 length(bits)=" + pairing.getG2().newRandomElement().getLengthInBytes()*8 + "\n" +
					//				   "zn length(bits)=" + pairing.getZr().newRandomElement().getLengthInBytes()*8);
					
					bbsSetupLog.process( i, curve, numberUsers, partial, "setup");
					
					total = total + partial;
					i++;
				}
				average = total / maxIterations;
				//bbsLog.verbose("Average time (curve: " + curve +", n: " + numberUsers + "): " + average + " ms" );
				start = 0;
				end = 0;
				total = 0;
				partial = 0;
				i = 1;
			}
		}
	}
	
	
	public void benchmarkSignVerify( BBSLog bbsSignLog, BBSLog bbsVerificationLog ) throws Exception {
		
		// benchmark fields
		long startSign = 0;
		long partialSign = 0;
		
		long startVerify = 0;
		long partialVerify = 0;
		
		long totalSign = 0;
		long totalVerify = 0;
		long averageSign = 0;
		long averageVerify = 0;
		int i = 1;

		
		for (String curve : curveFileNamesVector) {
			for (int numberUsers : numberUsersVector ) {
				groupManager = new GroupManagerAccessor(numberUsers, curve);
				groupManager.setup();
				while (i <= maxIterations) {
					/// start sign benchmark
					if (!precomputation)
						signer = new SignerAccessor( new BBSEngine(groupManager.getGroupPublicKey(),
															       groupManager.getUserPrivateKey(signerID)) );
					else
						signer = new SignerAccessor( new BBSEnginePrecomputation(groupManager.getGroupPublicKey(),
																				 groupManager.getUserPrivateKey(signerID),
																				 BBSEnginePrecomputation.SIGNER));
					
					startSign = System.nanoTime();
					signature = signer.sign(message);
					partialSign = System.nanoTime() - startSign;
					
					
					bbsSignLog.process(i, curve, numberUsers, partialSign, "sign");
					
					totalSign = totalSign + partialSign;
					// end sign benchmark
					
					// start verify benchmark
					if (!precomputation)
						verifier = new VerifierAccessor( new BBSEngine( groupManager.getGroupPublicKey(),
																		groupManager.getUserPrivateKey(signerID)) );
					else
						verifier = new VerifierAccessor( new BBSEnginePrecomputation( groupManager.getGroupPublicKey(),
																					  groupManager.getUserPrivateKey(signerID),
																					  BBSEnginePrecomputation.VERIFIER) );
					
					startVerify = System.nanoTime();
					boolean result = verifier.verify( signature, message );

					partialVerify = System.nanoTime() - startVerify;
					
					bbsVerificationLog.process( i, curve, numberUsers, partialVerify, "verify");
					
					totalVerify = totalVerify + partialVerify;
					// end verify benchmark
					
					i++;
				}
				averageSign = totalSign / maxIterations;
				//bbsLog.verbose("Sign Average time (curve: " + curve +", n: " + numberUsers + "): " + averageSign + " ms" );
				
				averageVerify = totalVerify / maxIterations;
				//bbsLog.verbose("Verify Average time (curve: " + curve +", n: " + numberUsers + "): " + averageVerify + " ms" );
				
				startSign = 0;
				totalSign = 0;
				partialSign = 0;
				startVerify = 0;
				totalVerify = 0;
				partialVerify = 0;
				i = 1;
			}
		}
		
		
		
	}
	
	
	public void benchmarkOpen( BBSLog bbsOpenLog ) throws Exception {
		long start = 0;
		long end = 0;
		int i = 1;
		
		for (String curve: curveFileNamesVector) {
			for (int numberUsers : numberUsersVector) {
				groupManager = new GroupManagerAccessor(numberUsers, curve);
				groupManager.setup();
				while (i <= maxIterations) {
					signer = new SignerAccessor( new BBSEngine( groupManager.getGroupPublicKey(),
							   									groupManager.getUserPrivateKey(signerID)) );
					
					signature = signer.sign( message );
					
					start = System.nanoTime();
					Integer identity = groupManager.getIdentity(message, signature, groupManager.getGroupPublicKey());
					end = System.nanoTime();
				
					
					bbsOpenLog.process(i, curve, numberUsers, (end-start), "open");
					i++;
				}
				start = 0;
				end = 0;
				i = 1;
			}
		}
		
		
	}
	
	
	public void groupSignatureElementsLength() throws Exception {
		
		for (String curve : curveFileNamesVector) {			
			for (int numberUsers : numberUsersVector ) {
				groupManager = new GroupManagerAccessor(numberUsers, curve);
				groupManager.setup();
				
				
				signer = new SignerAccessor( new BBSEngine( groupManager.getGroupPublicKey(),
															groupManager.getUserPrivateKey(signerID)) );
				
				signature = signer.sign( message );
				
				System.out.println("\n\n ************************************************* ");
				System.out.println("curve="+ curve + " numberUsers=" + numberUsers);
				
				
				System.out.println("g1 order: " + groupManager.getBBSParameters().getPairing().getG1().getOrder().bitLength());
				System.out.println("g2 order: " + groupManager.getBBSParameters().getPairing().getG2().getOrder().bitLength());
				System.out.println("zp order: " + groupManager.getBBSParameters().getPairing().getZr().getOrder().bitLength());
				System.out.println("gt order: " + groupManager.getBBSParameters().getPairing().getGT().getOrder().bitLength());
				
				System.out.println("g1 element: " + groupManager.getBBSParameters().getPairing().getG1().newRandomElement().getLengthInBytes()*8);
				System.out.println("g2 element: " + groupManager.getBBSParameters().getPairing().getG2().newRandomElement().getLengthInBytes()*8);
				System.out.println("zp element: " + groupManager.getBBSParameters().getPairing().getZr().newRandomElement().getLengthInBytes()*8);
				System.out.println("gt element: " + groupManager.getBBSParameters().getPairing().getGT().newRandomElement().getLengthInBytes()*8);
				
				System.out.println(groupManager.getBBSParameters().getPairing().getZr().newRandomElement().getLengthInBytes()*8);
				System.out.println(groupManager.getBBSParameters().getPairing().getZr().getLengthInBytes()*8);
				System.out.println(groupManager.getBBSParameters().getPairing().getZr().getOrder().bitLength());
				
				
				System.out.println("***** signature length (bits) *****");
				System.out.println("T1 \t" + signature.getT1().getElement().getLengthInBytes()*8 );
				System.out.println("T2 \t" + signature.getT2().getElement().getLengthInBytes()*8 );
				System.out.println("T3 \t" + signature.getT3().getElement().getLengthInBytes()*8 );
				System.out.println("c \t" + signature.getC().getElement().getLengthInBytes()*8 );
				System.out.println("sx \t" + signature.getSx().getElement().getLengthInBytes()*8 );
				System.out.println("salpha \t" + signature.getSalpha().getElement().getLengthInBytes()*8 );
				System.out.println("sbeta \t" + signature.getSbeta().getElement().getLengthInBytes()*8 );
				System.out.println("sdelta1 \t" + signature.getSdelta1().getElement().getLengthInBytes()*8 );
				System.out.println("sdelta2 \t" + signature.getSdelta2().getElement().getLengthInBytes()*8 );
				
				
				
				System.out.println("***** group public key length (bits) *****");
				System.out.println("g1 \t" + groupManager.getGroupPublicKey().getG1().getElement().getLengthInBytes()*8);
				System.out.println("g2 \t" + groupManager.getGroupPublicKey().getG2().getElement().getLengthInBytes()*8);
				System.out.println("h \t" + groupManager.getGroupPublicKey().getH().getElement().getLengthInBytes()*8);
				System.out.println("omega \t" + groupManager.getGroupPublicKey().getOmega().getElement().getLengthInBytes()*8);
				System.out.println("u \t" + groupManager.getGroupPublicKey().getU().getElement().getLengthInBytes()*8);
				System.out.println("v \t" + groupManager.getGroupPublicKey().getV().getElement().getLengthInBytes()*8);
				
				
				System.out.println("***** user private key length (bits) *****");
				System.out.println("x \t" + groupManager.getUserPrivateKey(signerID).getX().getElement().getLengthInBytes()*8);
				System.out.println("a \t" + groupManager.getUserPrivateKey(signerID).getA().getElement().getLengthInBytes()*8);
				
				
				System.out.println("***** group manager private key length (bits) *****");
				System.out.println("delta1 \t" + groupManager.getGroupManagerPrivateKey().getDelta1().getElement().getLengthInBytes()*8);
				System.out.println("delta2 \t" + groupManager.getGroupManagerPrivateKey().getDelta2().getElement().getLengthInBytes()*8);
				
			}
		}
		
		
	}
	
	
}
