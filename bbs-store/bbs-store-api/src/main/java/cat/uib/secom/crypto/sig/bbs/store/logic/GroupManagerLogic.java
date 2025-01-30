package cat.uib.secom.crypto.sig.bbs.store.logic;

import cat.uib.secom.crypto.sig.bbs.core.accessors.enhanced.GroupManagerAccessor;

public class GroupManagerLogic {

	
	public static GroupManagerAccessor initGroup(Integer numberUsers, String curveFileName, byte[] g1) {
		
		GroupManagerAccessor gma = new GroupManagerAccessor(numberUsers, curveFileName);
		// group manager setup (init parameters, load curve, key generation)
		gma.setup(g1);
		// return group manager accessor object
		return gma;
	}
	
	
	
	public static GroupManagerAccessor initGroup(Integer numberUsers, String curveFileName) {
		
		GroupManagerAccessor gma = new GroupManagerAccessor(numberUsers, curveFileName);
		// group manager setup (init parameters, load curve, key generation)
		gma.setup();
		// return group manager accessor object
		return gma;
	}
	
	
	
	
	
	
}
