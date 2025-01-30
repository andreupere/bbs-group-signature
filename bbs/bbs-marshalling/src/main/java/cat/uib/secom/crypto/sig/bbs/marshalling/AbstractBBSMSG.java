package cat.uib.secom.crypto.sig.bbs.marshalling;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;

import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.util.ASN1Dump;
import org.simpleframework.xml.Serializer;
import org.simpleframework.xml.core.Persister;



import cat.uib.secom.crypto.sig.bbs.core.parameters.BBSParameters;
import cat.uib.secom.crypto.sig.bbs.marshalling.utils.Constants;
import cat.uib.secom.utils.strings.MSGFormatConstants;


/**
 * @author Andreu Pere
 * 
 * Abstract class that helps to describe all the XML messages related to the BBS group signature scheme
 * */
public abstract class AbstractBBSMSG {
	
	
	@SuppressWarnings("unused")
	private Class<?> _cl;
	
	protected Serializer serializer;
	
	protected StringWriter buffer;
	

	protected MSGFormatConstants msgFormat;
	
	protected ByteArrayOutputStream baos;

	protected ASN1Sequence asn1Object;
	
	/**
	 * Where the child XML message is stored 
	 * */
	//protected AbstractBBSMSG abstractMSG;
	
	// where asn object is stored
	protected ASN1Object asnObj;
	
	/**
	 * Initializes with the type of child message
	 * */
	public AbstractBBSMSG(Class<?> cl) {
		this._cl = cl;
		this.serializer = new Persister();
	}
	
	
//	protected abstract void setAbstractMSG(AbstractBBSMSG abm);
//	
//	protected abstract AbstractBBSMSG getAbstractMSG();
	
	
	/**
	 * This should be implemented by child XML messages.
	 * Its aim is to transform the representation of the object into 
	 * hexadecimal strings
	 * 
	 * @return the proper object in a hexadecimal string representation
	 * */
	protected abstract Object toHexStrings();
	
	/**
	 * This should be implemented by child XML messages.
	 * Its aim is to transform the child XML messages from hexadecimal string representation
	 * to the concrete representation of this object
	 * 
	 * @param BBSParameters in order to do EC operations (pairings)
	 * 
	 * @return the proper object in its concrete representation
	 * */
	protected abstract Object fromHexStrings(AbstractBBSMSG bbsMSG, BBSParameters bbsParameters) throws Exception;
	
	
	
	

	public void printASN1() {
		System.out.println( dump() ); 
	}
	
	public String dump() {
		return ASN1Dump.dumpAsString(asn1Object);
	}
	
	
	protected abstract byte[] encodeASN1ToByteArray();
	
	protected abstract Object decodeASN1FromByteArray(byte[] b);
	
	
	
	
	
//	/**
//	 * Internally transforms object with hexadecimal string representation into the proper
//	 * object. 
//	 * 
//	 * @param input as the string to be transformed
//	 * @param bbsParameters as the object from pairing operations can be done
//	 * 
//	 * @return Object as the rebuilt object from the hexadecimal string representation
//	 * */
//	@Deprecated
//	public Object toObject(String input, BBSParameters bbsParameters) throws Exception {
//		
//		abstractMSG = (AbstractBBSMSG) serializer.read(this.getClass(), input);
//
//		
//		return this.fromHexStrings(this, bbsParameters);		
//	}
//	
//	
//	/**
//	 * Internally transforms object read from a Reader with hexadecimal string representation
//	 * into the proper object.
//	 * 
//	 * @param input as the {@Reader} object where string object should be read and transformed
//	 * @param bbsParameters as the object from pairing operations can be done
//	 * 
//	 * @see {@toObject(String input, BBSParameters bbsParameters)}
//	 * */
//	@Deprecated
//	public Object toObject(Reader input, BBSParameters bbsParameters) throws Exception {
//		
//		abstractMSG = (AbstractBBSMSG) serializer.read(this.getClass(), input);
//		
//		return this.fromHexStrings(this, bbsParameters);
//	}
//	
	
	protected Object toObject(BBSParameters bbsParameters) throws Exception {
		//abstractMSG = this;
		return this.fromHexStrings(this, bbsParameters);
	}
	

	
	
	public byte[] serialize(MSGFormatConstants msgFormat) throws Exception {
		this.msgFormat = msgFormat;
		return this.serialize();
	}
	
	public void serialize(Writer out, MSGFormatConstants msgFormat) throws Exception {
		this.msgFormat = msgFormat;
		this.serialize(out); 
	}
	
	
	public Object deSerialize(Reader reader, MSGFormatConstants msgFormat) throws Exception { 
		if (msgFormat.equals(MSGFormatConstants.XML)) {
			return decodeXMLFromReader(reader);
		}
		else if (msgFormat.equals(MSGFormatConstants.ASN1)) {
			throw new Exception("not yet implemented");
		}
		else
			throw new Exception();
	}
	
	public Object deSerialize(byte[] b, MSGFormatConstants msgFormat) throws Exception {
		if (msgFormat.equals(MSGFormatConstants.XML)) {
			return decodeXMLFromByteArray(b);
			//abstractMSG = (AbstractBBSMSG) decodeXML(b);
			//return this.fromHexStrings(bbsParameters);
		}
		else if (msgFormat.equals(MSGFormatConstants.ASN1)) {
			return decodeASN1FromByteArray(b);
			//abstractMSG = (AbstractBBSMSG) decodeASN1(b);
			//return this.fromHexStrings(bbsParameters);
		}
		else
			throw new Exception();
	}
	
	
	
	protected byte[] serialize() throws Exception {
		if (msgFormat.equals(MSGFormatConstants.XML))
			return encodeXMLToByteArray().toByteArray();
		else if (msgFormat.equals(MSGFormatConstants.ASN1))
			return encodeASN1ToByteArray();
		else
			throw new Exception("MSG format (ASN1 or XML) not set in common.cfg");
	}
	
	protected void serialize(Writer out) throws Exception {
		if (msgFormat.equals( MSGFormatConstants.XML ))
			this.encodeXMLToWriter(out);
		else if (msgFormat.equals( MSGFormatConstants.ASN1 ))
			throw new Exception("not yet implemented");
		else
			throw new Exception("MSG format should be (ASN1 or XML)");
	}
	
	
	
	private ByteArrayOutputStream encodeXMLToByteArray() throws Exception {
		//this.toHexStrings();
		baos = new ByteArrayOutputStream();
		serializer.write(this, baos);
		return baos;
	}
	
	private void encodeXMLToWriter(Writer out) throws Exception {
		//this.toHexStrings();
		serializer.write(this, out);
	}
	
	private Object decodeXMLFromByteArray(byte[] b) throws Exception {
		ByteArrayInputStream bais = new ByteArrayInputStream(b);
		return serializer.read(this.getClass(), bais);
	}
	
	private Object decodeXMLFromReader(Reader reader) throws Exception {
		return serializer.read(this.getClass(), reader);
	}
	
	
	
	
	
	

	
	
//	/**
//	 * Save XML in file
//	 * */
//	@Deprecated
//	public void toXML(File file) throws Exception {
//		abstractMSG = this;
//		this.toHexStrings();
//		serializer.write(this, file);
//	}
//	
	
	/**
	 * Internally transforms the object into the according hexadecimal string representation
	 * and uses SimpleXML to write it to a string buffer. 
	 * 
	 * @return String object with the hexadecimal string representation of the object
	 * */
	@Deprecated
	public String toXML() throws Exception {
		buffer = new StringWriter();
		
		this.toHexStrings();
		serializer.write(this, buffer);
		
		return buffer.toString();
	}
	
	
	

}
