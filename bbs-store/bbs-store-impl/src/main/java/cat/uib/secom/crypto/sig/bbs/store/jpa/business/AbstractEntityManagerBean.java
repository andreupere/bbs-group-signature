package cat.uib.secom.crypto.sig.bbs.store.jpa.business;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.EntityTransaction;
import javax.persistence.Persistence;


import cat.uib.secom.crypto.sig.bbs.core.parameters.BBSParameters;



public abstract class AbstractEntityManagerBean {

	private EntityManagerFactory entityManagerFactory;
	private EntityManager entityManager;
	private EntityTransaction entityTransaction;

	private BBSParameters bbsParameters;
	private String curveFileName;

	public AbstractEntityManagerBean(String persistenceUnitName) {
		entityManagerFactory = Persistence.createEntityManagerFactory(persistenceUnitName);
		entityManager = entityManagerFactory.createEntityManager();
	}

	
	protected void preparePersistence() {
		this.openEntityManager();
		this.beginTransaction();
	}
	
	protected void closePersistence() {
		this.closeEntityManager();
	}
	

	private void openEntityManager() {
		if ( !entityManager.isOpen() )
			entityManager = entityManagerFactory.createEntityManager();
	}
	

	private void beginTransaction() {
		setEntityTransaction( getEntityManager().getTransaction() );
		if ( !entityTransaction.isActive()) 
			getEntityTransaction().begin();
	}
	

	private void closeEntityManager() {
		if ( entityManager.isOpen() )
			entityManager.close();
		if ( entityManagerFactory.isOpen() )
			entityManagerFactory.close();
	}
	
	
	public BBSParameters loadCurveParameters(byte[] g1, byte[] g2) throws Exception {
		if (bbsParameters == null) {
			bbsParameters = new BBSParameters(this.curveFileName);
			if (g1 == null || g2 == null) 
				throw new Exception("g1 and g2 must be filled");
			bbsParameters.generate(g1, g2);
		}
		
		return bbsParameters;
	}
	
	
	
	/****************************** PUBLIC GETS AND SETS *********************************************/
	
	public EntityManagerFactory getEntityManagerFactory() {
		return entityManagerFactory;
	}
	public EntityManager getEntityManager() {
		return entityManager;
	}


	public EntityTransaction getEntityTransaction() {
		return entityTransaction;
	}
	public void setEntityManagerFactory(EntityManagerFactory entityManagerFactory) {
		this.entityManagerFactory = entityManagerFactory;
	}


	public void setEntityManager(EntityManager entityManager) {
		this.entityManager = entityManager;
	}
	public void setEntityTransaction(EntityTransaction entityTransaction) {
		this.entityTransaction = entityTransaction;
	}




	public String getCurveFileName() {
		return curveFileName;
	}




	public void setCurveFileName(String curveFileName) {
		this.curveFileName = curveFileName;
	}
	
	/**************************** END PUBLIC GETS AND SETS********************************************/
}
