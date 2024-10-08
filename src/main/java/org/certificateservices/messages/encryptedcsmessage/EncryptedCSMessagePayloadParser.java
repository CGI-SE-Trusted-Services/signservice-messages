/************************************************************************
*                                                                       *
*  Certificate Service - Messages                                       *
*                                                                       *
*  This software is free software; you can redistribute it and/or       *
*  modify it under the terms of the GNU Lesser General Public License   *
*  License as published by the Free Software Foundation; either         *
*  version 3   of the License, or any later version.                    *
*                                                                       *
*  See terms of license at gnu.org.                                     *
*                                                                       *
*************************************************************************/
package org.certificateservices.messages.encryptedcsmessage;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Properties;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.MessageSecurityProvider;
import org.certificateservices.messages.NoDecryptionKeyFoundException;
import org.certificateservices.messages.csmessages.BasePayloadParser;
import org.certificateservices.messages.csmessages.DefaultCSMessageParser;
import org.certificateservices.messages.csmessages.XSDLSInput;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.Credential;
import org.certificateservices.messages.csmessages.jaxb.RequestStatus;
import org.certificateservices.messages.encryptedcsmessage.jaxb.EncryptedCSMessageType;
import org.certificateservices.messages.encryptedcsmessage.jaxb.ObjectFactory;
import org.certificateservices.messages.utils.*;
import org.certificateservices.messages.utils.XMLEncrypter.DecryptedXMLConverter;
import org.certificateservices.messages.xenc.jaxb.EncryptedDataType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;
import org.xml.sax.SAXException;

/**
 * Encryption CS Message Payload Parser generates encrypted and enveloped CSMessages and isn't a payload inside the CSMessage as other payload parsers generate.
 * <p>
 * To generate an Encrypted CS Message use the method: genEncryptedCSMessage().
 * <p>
 * To parse a message that might be encrypted use the parseMessage() method.
 * 
 * @author Philip Vendil
 *
 */
public class EncryptedCSMessagePayloadParser extends BasePayloadParser {

	public static String NAMESPACE = "http://certificateservices.org/xsd/encrypted_csmessages2_0";
	
	private static final String XSD_SCHEMA_2_0_RESOURCE_LOCATION = "/encrypted_csmessages_schema2_0.xsd";
	
	private static final String[] SUPPORTED_ASSERTION_VERSIONS = {"2.0"};
	
	private static final String DEFAULT_ASSERTION_VERSION = "2.0";
	
	private XMLEncrypter xmlEncrypter;
	private SystemTime systemTime = new DefaultSystemTime();
	private EncryptedCSMessageXMLConverter xmlConverter = new EncryptedCSMessageXMLConverter();
	
	ObjectFactory of = new ObjectFactory();
	org.certificateservices.messages.csmessages.jaxb.ObjectFactory csMessageOf = new org.certificateservices.messages.csmessages.jaxb.ObjectFactory();

	private Transformer transformer;
	
	@Override
	public void init(Properties config, MessageSecurityProvider secProv)
			throws MessageProcessingException {
		super.init(config, secProv);

		try {
			xmlEncrypter = new XMLEncrypter(secProv, getDocumentBuilder(), getMarshaller(), getUnmarshaller());
			
		} catch (Exception e) {
			throw new MessageProcessingException("Error initializing JAXB in AssertionPayloadParser: " + e.getMessage(),e);
		}
		
		TransformerFactory tf = TransformerFactory.newInstance();
		try {
			transformer = tf.newTransformer();
		} catch (TransformerConfigurationException e) {
			throw new MessageProcessingException("Error instanciating Transformer for XMLSigner: " + e.getMessage(),e);
		}
	}
	
	/**
	 * @see org.certificateservices.messages.csmessages.PayloadParser#getNameSpace()
	 */
	public String getNameSpace() {
		return NAMESPACE;
	}

	/**
	 * @see org.certificateservices.messages.csmessages.PayloadParser#getJAXBPackage()
	 */
	public String getJAXBPackage() {
		// Return null because this is actually an enveloped CSMessage and not and a pay load inside a CS Message.
		return null;
	}

	/**
	 * @see org.certificateservices.messages.csmessages.PayloadParser#getSchemaAsInputStream(java.lang.String)
	 */
	public InputStream getSchemaAsInputStream(String payLoadVersion)
			throws MessageContentException, MessageProcessingException {
		// Return null because this is actually an enveloped CSMessage and not and a pay load inside a CS Message.
		return null;
	}

	/**
	 * @see org.certificateservices.messages.csmessages.BasePayloadParser#getSupportedVersions()
	 */
	@Override
	protected String[] getSupportedVersions() {
		return SUPPORTED_ASSERTION_VERSIONS;
	}

	/**
	 * @see org.certificateservices.messages.csmessages.BasePayloadParser#getDefaultPayloadVersion()
	 */
	@Override
	protected String getDefaultPayloadVersion() {
		return DEFAULT_ASSERTION_VERSION;
	}
	
	/**
	 * Method to generate an encrypted CS Message of a regular CS Message using the default encrypted cs message protocol version.
	 * 
	 * @param message the message to encrypt
	 * @param receipients the recipients of the encrypted message.
	 * @return an Encrypted CS Message.
	 * @throws MessageContentException if message content was faulty.
	 * @throws MessageProcessingException if internal error occurred encrypting the CS Message.
	 */
	public byte[] genEncryptedCSMessage(byte[] message,  List<X509Certificate> receipients) throws MessageContentException, MessageProcessingException{
		return genEncryptedCSMessage(message, DEFAULT_ASSERTION_VERSION, receipients);
	}
	
	/**
	 * Method to generate an encrypted CS Message of a regular CS Message.
	 * 
	 * @param message the message to encrypt
	 * @param version the version of the encrypted CS message specification
	 * @param receipients the recipients of the encrypted message.
	 * @return an Encrypted CS Message.
	 * @throws MessageContentException if message content was faulty.
	 * @throws MessageProcessingException if internal error occurred encrypting the CS Message.
	 */
	public byte[] genEncryptedCSMessage(byte[] message, String version, List<X509Certificate> receipients) throws MessageContentException, MessageProcessingException{
		try {
			Document doc = getDocumentBuilder().parse(new ByteArrayInputStream(message));
			
			String id = MessageGenerateUtils.generateRandomUUID();			
			EncryptedCSMessageType type = of.createEncryptedCSMessageType();
			type.setID(id);
			type.setVersion(version);
			type.setTimeStamp(MessageGenerateUtils.dateToXMLGregorianCalendar(systemTime.getSystemTime()));
			
			@SuppressWarnings("unchecked")
			JAXBElement<EncryptedDataType> encryptedData = (JAXBElement<EncryptedDataType>) getUnmarshaller().unmarshal(xmlEncrypter.encryptElement(doc, receipients, true));
			type.setEncryptedData(encryptedData.getValue());
			
			return marshall(of.createEncryptedCSMessage(type));
		} catch (JAXBException e) {
			throw new MessageContentException("Error encrypting CS Message: " + e.getMessage(),e);
		} catch (SAXException e) {
			throw new MessageContentException("Error encrypting CS Message: " + e.getMessage(),e);
		} catch (ParserConfigurationException e) {
			throw new MessageProcessingException("Error encrypting CS Message: " + e.getMessage(),e);
		} catch (IOException e) {
			throw new MessageContentException("Error encrypting CS Message: " + e.getMessage(),e);
		}
		
	}

	/**
	 * Method to parse an encrypted CS Message or a plaintext CS message into a (non-encrypted) CS Message.
	 * 
	 * @param messageData this can be an encrypted CS Message or a plaintext cs message.
	 * @return an decrypted CS Message
	 * @throws MessageContentException if message content was faulty or decryption key wasn't found
	 * @throws MessageProcessingException if internal error occurred encrypting the CS Message.
	 */
	@Override
	public CSMessage parseMessage(byte[] messageData)
			throws MessageContentException, MessageProcessingException {
		try {
			Document doc = getDocumentBuilder().parse(new ByteArrayInputStream(messageData));
			Element rootElement = doc.getDocumentElement();
			if(rootElement.getLocalName().equals(ObjectFactory._EncryptedCSMessage_QNAME.getLocalPart()) &&
			   rootElement.getNamespaceURI().equals(NAMESPACE)){
				doc = xmlEncrypter.decryptDoc(doc, xmlConverter);				
			}
			
			return getCSMessageParser().parseMessage(doc);
			
		} catch (SAXException e) {
			throw new MessageContentException("Error parsing message: " + e.getMessage(), e);
		} catch (IOException e) {
			throw new MessageContentException("Error parsing message: " + e.getMessage(), e);
		} catch (ParserConfigurationException e) {
			throw new MessageProcessingException("Error parsing configuration error when parsing message: " + e.getMessage(), e);
		} catch (NoDecryptionKeyFoundException e) {
			throw new MessageContentException("Error no related decryption key found for message: " + e.getMessage(), e);
		}
	}
	
	/**
	 * Message that checks if message is encrypted and returns the related Document object if it is, otherwise null.
	 * @param messageData the message data to check if it was encrypted
	 * @return the encrypted Document of the encrypted doc or null if document isn't encrypted document.
	 * @throws MessageContentException if message content was faulty or decryption key wasn't found
	 * @throws MessageProcessingException if internal error occurred encrypting the CS Message.
	 */
	public Document isEncryptedCSMessage(byte[] messageData) throws MessageContentException, MessageProcessingException{
		try {
			Document retval = null;
			Document doc = getDocumentBuilder().parse(new ByteArrayInputStream(messageData));
			Element rootElement = doc.getDocumentElement();
			if(rootElement.getLocalName().equals(ObjectFactory._EncryptedCSMessage_QNAME.getLocalPart()) &&
			   rootElement.getNamespaceURI().equals(NAMESPACE)){
				retval = doc;
			}
			
			return retval;
			
		} catch (SAXException e) {
			throw new MessageContentException("Error parsing message: " + e.getMessage(), e);
		} catch (IOException e) {
			throw new MessageContentException("Error parsing message: " + e.getMessage(), e);
		} catch (ParserConfigurationException e) {
			throw new MessageProcessingException("Error parsing configuration error when parsing message: " + e.getMessage(), e);
		} 
	}
	/**
	 * Method that decrypts a EncryptedCSMessage Document and returns the plain text data.
	 * 
	 * @param doc Document encrypted CS message data.
	 * @return an decrypted CS Message data
	 * @throws MessageContentException if message content was faulty or decryption key wasn't found
	 * @throws MessageProcessingException if internal error occurred encrypting the CS Message.
	 */
	public byte[] decryptDoc(Document doc)
			throws MessageContentException, MessageProcessingException {
		try {
			doc = xmlEncrypter.decryptDoc(doc, xmlConverter);

			StringWriter writer = new StringWriter();
			transformer.transform(new DOMSource(doc), new StreamResult(writer));
			String output = writer.getBuffer().toString();	
			return output.getBytes("UTF-8");			
		} catch (IOException e) {
			throw new MessageContentException("Error parsing message: " + e.getMessage(), e);
		} catch (NoDecryptionKeyFoundException e) {
			throw new MessageContentException("Error no related decryption key found for message: " + e.getMessage(), e);
		} catch (TransformerException e) {
			throw new MessageContentException("Error converting Doc into XML String: " + e.getMessage(), e);
		}
	}

	/**
	 * Help method to marshall a message without signing it.
	 * @param message the message to marshall into a XML byte array.
	 * @return the marshalled byte array 
	 * @throws MessageProcessingException if problem occurred marshalling the message.
	 */
	private byte[] marshall(JAXBElement<?> message) throws MessageProcessingException{
		try{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		getMarshaller().marshal(message, baos);
		return baos.toByteArray();
		}catch(Exception e){
			throw new MessageProcessingException("Error occurred marshalling assertion object: " + e.getMessage(),e );
		}
	}
	
	@Override
	public Object getPayload(CSMessage csMessage)
			throws MessageContentException {
		throw new IllegalStateException("Error EncryptedCSMessagePayloadParser doesn't support metod getPayload");
	}
	
	@Override
	public RequestStatus getResponseStatus(CSMessage csMessage)
			throws MessageContentException {
		throw new IllegalStateException("Error EncryptedCSMessagePayloadParser doesn't support metod getPayload");
	}


	@Override
	public byte[] generateGetApprovalRequest(String requestId,
			String destinationId, String organisation, byte[] requestMessage,
			Credential originator, List<Object> assertions)
			throws MessageContentException, MessageProcessingException {
		throw new IllegalStateException("Error EncryptedCSMessagePayloadParser doesn't support metod getPayload");
	}

	@Override
	public byte[] generateIsApprovedRequest(String requestId,
			String destinationId, String organisation, String approvalId,
			Credential originator, List<Object> assertions)
			throws MessageContentException, MessageProcessingException {
		throw new IllegalStateException("Error EncryptedCSMessagePayloadParser doesn't support metod getPayload");
	}

	private DocumentBuilder getDocumentBuilder() throws ParserConfigurationException {
		return XMLUtils.createDocumentBuilderFactory().newDocumentBuilder();
	}
	
	Marshaller getMarshaller() throws JAXBException{
		Marshaller marshaller = getJAXBContext().createMarshaller();
		marshaller.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
		return marshaller;
	}
	
	Unmarshaller getUnmarshaller() throws JAXBException, SAXException{
		Unmarshaller unmarshaller = getJAXBContext().createUnmarshaller();
		unmarshaller.setSchema(getSchema());
		return unmarshaller;
	}
	
	private JAXBContext jaxbContext = null;

	/**
     * Help method maintaining the Assertion JAXB Context.
     */
    private JAXBContext getJAXBContext() throws JAXBException{
    	if(jaxbContext== null){
    		String jaxbClassPath = "org.certificateservices.messages.encryptedcsmessage.jaxb:org.certificateservices.messages.xenc.jaxb:org.certificateservices.messages.xmldsig.jaxb";
    			    		
    		jaxbContext = JAXBContext.newInstance(jaxbClassPath);
    		
    	}
    	return jaxbContext;
    }

	private Schema schema = null;
	private Schema getSchema() throws SAXException {
		if(schema == null){
			schema = generateSchema();
		}
		return schema;
	}

    private Schema generateSchema() throws SAXException{
    	SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);

    	schemaFactory.setResourceResolver(new EncryptionParserLSResourceResolver());

        Source[] sources = new Source[3];
        sources[0] = new StreamSource(getClass().getResourceAsStream(DefaultCSMessageParser.XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION));
        sources[1] = new StreamSource(getClass().getResourceAsStream(DefaultCSMessageParser.XMLENC_XSD_SCHEMA_RESOURCE_LOCATION));
        sources[2] = new StreamSource(getClass().getResourceAsStream(XSD_SCHEMA_2_0_RESOURCE_LOCATION));

        Schema schema = schemaFactory.newSchema(sources);

        return schema;
    }
    
    /**
     * Converter that replaces all decrypted EncryptedAssertions with Assertions
     */
    public class EncryptedCSMessageXMLConverter implements DecryptedXMLConverter{

		public Document convert(Document doc) throws MessageContentException {
			NodeList nodeList = doc.getElementsByTagNameNS(DefaultCSMessageParser.CSMESSAGE_NAMESPACE, "CSMessage");
			for(int i =0; i < nodeList.getLength(); i++){
				Element attribute= (Element) nodeList.item(i);
				Element parent = (Element) attribute.getParentNode();
				if(parent.getLocalName().equals(ObjectFactory._EncryptedCSMessage_QNAME.getLocalPart()) && parent.getNamespaceURI().equals(NAMESPACE)){
					parent.getParentNode().replaceChild(attribute, parent);
				}
				
			}

			return doc;
		}
		
	}

    public class EncryptionParserLSResourceResolver implements  LSResourceResolver {
		
		public LSInput resolveResource(String type, String namespaceURI,
				String publicId, String systemId, String baseURI) {
			try {
				if(systemId != null && systemId.equals("http://www.w3.org/2001/XMLSchema.dtd")){
					return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream("/XMLSchema.dtd"));
				}
				if(systemId != null && systemId.equals("datatypes.dtd")){
					return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream("/datatypes.dtd"));
				}
				if(namespaceURI != null){
					if(namespaceURI.equals(DefaultCSMessageParser.XMLDSIG_NAMESPACE)){
						return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream(DefaultCSMessageParser.XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION));
					}
					if(namespaceURI.equals(DefaultCSMessageParser.XMLENC_NAMESPACE)){
						return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream(DefaultCSMessageParser.XMLENC_XSD_SCHEMA_RESOURCE_LOCATION));
					}
					if(namespaceURI.equals(NAMESPACE)){
						return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream(EncryptedCSMessagePayloadParser.XSD_SCHEMA_2_0_RESOURCE_LOCATION));
					}
				}
			} catch (MessageProcessingException e) {
				throw new IllegalStateException("Error couldn't read XSD from class path: " + e.getMessage(), e);
			}
			return null;
		}
	}
    
}
