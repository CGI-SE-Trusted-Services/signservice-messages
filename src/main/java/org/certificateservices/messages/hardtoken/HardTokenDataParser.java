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
package org.certificateservices.messages.hardtoken;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
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
import org.certificateservices.messages.csmessages.DefaultCSMessageParser;
import org.certificateservices.messages.csmessages.XSDLSInput;
import org.certificateservices.messages.hardtoken.jaxb.HardTokenData;
import org.certificateservices.messages.hardtoken.jaxb.ObjectFactory;
import org.certificateservices.messages.hardtoken.jaxb.PINData;
import org.certificateservices.messages.utils.MessageGenerateUtils;
import org.certificateservices.messages.utils.XMLEncrypter;
import org.w3c.dom.Document;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;
import org.xml.sax.SAXException;

/**
 * Class to generate and parse Hard Token Data Structures.
 * <b>
 * It has also methods to create encrypted binary data defined in
 * the credential managment protocol 2.0 specification.
 * 
 * @author Philip Vendil
 *
 */
public class HardTokenDataParser {
	
	public static String NAMESPACE = "http://certificateservices.org/xsd/hardtoken";
	
	public static String DEFAULT_VERSION = "2.0";
	
	private static final String HARDTOKEN_XSD_SCHEMA_RESOURCE_LOCATION = "/hardtoken_schema.xsd";
	
	private ObjectFactory of = new ObjectFactory();
	
	private XMLEncrypter xmlEncrypter;
	
	/**
	 * Constructor for Hard Token Data Parser, this is the default method to create a parser, it should
	 * not be fetched by the PayloadParserRegistry since this is not a CSMessagePayload.
	 * 
	 * @param securityProvider the security provider to use for encrypting and decrypting messages.
	 * @throws MessageProcessingException if internal problems occurred initializing the parser.
	 */
	public HardTokenDataParser(MessageSecurityProvider securityProvider) throws MessageProcessingException{
		
		try {
			xmlEncrypter = new XMLEncrypter(securityProvider, getDocumentBuilder(), getMarshaller(), getUnmarshaller());
		} catch (Exception e) {
			throw new MessageProcessingException("Error initializing HardTokenDataParser: " + e.getMessage(),e);
		}
	}

	/**
	 * Method to parse a unencrypted hard token data.
	 * 
	 * @param data a serialized hard token data XML structure.
	 * @return a unmarshalled HardTokenData.
	 * @throws MessageContentException if xml data was invalid
	 * @throws MessageProcessingException if internal problems occurred unmarshalling the data.
	 */
	public HardTokenData parse(byte[] data) throws MessageContentException, MessageProcessingException{
		Document doc;
		try {
			doc = getDocumentBuilder().parse(new ByteArrayInputStream(data));
			return (HardTokenData) getUnmarshaller().unmarshal(doc);
		} catch (SAXException e) {
			throw new MessageContentException("Message content error when parsing hard token data: " + e.getMessage(), e);
		} catch (IOException e) {
			throw new MessageContentException("Message content error when parsing hard token data: " + e.getMessage(), e);
		}catch (JAXBException e) {
			throw new MessageContentException("Message content error when parsing hard token data: " + e.getMessage(), e);
		} catch (ParserConfigurationException e) {
			throw new MessageProcessingException("Internal error when parsing hard token data: " + e.getMessage(), e);
		} 
	}
	
	/**
	 * Method to decrypt and unmarshall a hard token data.
	 * <p>
	 * The encrypted data should be a XML Encryption (http://www.w3.org/2001/04/xmlenc#) EncryptedData element..
	 * @param encryptedData the encrypted XML data.
	 * @return an unmarshalled HardTokenData
	 * @throws MessageContentException if xml data was invalid.
	 * @throws MessageProcessingException if internal problems occurred unmarshalling or decrypting the data.
	 * @throws NoDecryptionKeyFoundException if decryption key couldn't be found in security provider.
	 */
	public HardTokenData decryptAndParse(byte[] encryptedData) throws MessageContentException, MessageProcessingException, NoDecryptionKeyFoundException{
		
		try {
			Document doc = getDocumentBuilder().parse(new ByteArrayInputStream(encryptedData));
			
			return (HardTokenData) xmlEncrypter.decryptDocument(doc);
	
		} catch (ParserConfigurationException e) {
			throw new MessageProcessingException("Internal error parsing encrypted hard token data: " + e.getMessage(),e);
		} catch (SAXException e) {
			throw new MessageContentException("Internal content encrypted hard token data: " + e.getMessage(),e);
		} catch (IOException e) {
			throw new MessageContentException("Internal content encrypted hard token data: " + e.getMessage(),e);
		}
	}
	
	/**
	 * Method to create a basic Hard Token Data without any key recovery functionality.
	 * <p>
	 * All parameters must be set. 
	 *
	 * @param tokenType the token type of the token
	 * @param tokenClass the token class, i.e ordinary. temporary etc.
	 * @param serialNumber the serial number of the hard token
	 * @param supportsRemoteUnblock if token supports remote unblock.
	 * @param createTime the create time of the hard token data
	 * @param modifyTime the modify time of the hard token data
	 * @param pins a List of PinDatas to set, min size 1
	 * @return a newly generated hard token data.
	 * @throws MessageProcessingException if date convertion fails.
	 */
	public HardTokenData genHardTokenData(String tokenType, String tokenClass, String serialNumber, boolean supportsRemoteUnblock,Date createTime, Date modifyTime, List<PINData> pins) throws MessageProcessingException{
		HardTokenData htd = of.createHardTokenData();
		htd.setVersion(DEFAULT_VERSION);
		htd.setTokenType(tokenType);
		htd.setTokenClass(tokenClass);
		htd.setSerialNumber(serialNumber);
		htd.setCreateTime(MessageGenerateUtils.dateToXMLGregorianCalendar(createTime));
		htd.setModifyTime(MessageGenerateUtils.dateToXMLGregorianCalendar(modifyTime));
		htd.setSupportsRemoteUnblock(supportsRemoteUnblock);
		
		htd.setPinDatas(of.createHardTokenDataPinDatas());
		for(PINData pin : pins){
			htd.getPinDatas().getPin().add(pin);
		}
		
		return htd;
	}
	
	/**
	 * Method to serialize a hard token data to a byte array.
	 * 
	 * @param hardTokenData the hard token data to serialize
	 * @return a serialized version of the hard token data.
	 * @throws MessageContentException if hard token data contained invalid content.
	 * @throws MessageProcessingException if internal problems occurred marshalling the data.
	 */
	public byte[] marshall(HardTokenData hardTokenData) throws MessageContentException, MessageProcessingException{
		Document doc;
		try {
			doc = getDocumentBuilder().newDocument();

			getMarshaller().marshal(hardTokenData, doc);
			StringWriter writer = new StringWriter();
			getTransformer().transform(new DOMSource(doc), new StreamResult(writer));
			String output = writer.getBuffer().toString();	
			return output.getBytes("UTF-8");
		} catch (JAXBException e) {
			throw new MessageContentException("Message content error when generating hard token data: " + e.getMessage(), e);
		} catch (TransformerException e) {
			throw new MessageProcessingException("Internal error when generating hard token data: " + e.getMessage(), e);
		} catch (UnsupportedEncodingException e) {
			throw new MessageProcessingException("Internal error when generating hard token data: " + e.getMessage(), e);
		}catch (ParserConfigurationException e) {
			throw new MessageProcessingException("Internal error when generating hard token data: " + e.getMessage(), e);
		} 
	}
	
	/**
	 * Method to serialize and encrypt a hard token data to a given reciepient.
	 * <p>
	 * The data will first be transformed into a encrypted data.
	 * 
	 * @param hardTokenData the hard token data to serialize
	 * @return a serialized version of the hard token data.
	 * @throws MessageContentException if hard token data contained invalid content.
	 * @throws MessageProcessingException if internal problems occurred marshalling the data.
	 */
	public byte[] encryptAndMarshall(HardTokenData hardTokenData, List<X509Certificate> receipients) throws MessageContentException, MessageProcessingException{
		Document doc;
		try {
			doc = getDocumentBuilder().newDocument();
			getMarshaller().marshal(hardTokenData, doc);
			
			Document encDoc = xmlEncrypter.encryptElement(doc, receipients, false);
			StringWriter writer = new StringWriter();
			getTransformer().transform(new DOMSource(encDoc), new StreamResult(writer));
			String output = writer.getBuffer().toString();	
			return output.getBytes("UTF-8");
		} catch (JAXBException e) {
			throw new MessageContentException("Message content error when generating hard token data: " + e.getMessage(), e);
		} catch (TransformerException e) {
			throw new MessageProcessingException("Internal error when generating hard token data: " + e.getMessage(), e);
		} catch (UnsupportedEncodingException e) {
			throw new MessageProcessingException("Internal error when generating hard token data: " + e.getMessage(), e);
		}catch (ParserConfigurationException e) {
			throw new MessageProcessingException("Internal error when generating hard token data: " + e.getMessage(), e);
		} 
	}

	private DocumentBuilder getDocumentBuilder() throws ParserConfigurationException {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);

		return dbf.newDocumentBuilder();
	}
	
	private Marshaller marshaller = null;
	Marshaller getMarshaller() throws JAXBException{
		if(marshaller == null){
			marshaller = getJAXBContext().createMarshaller();
			marshaller.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
		}
		return marshaller;
	}
	
	private Unmarshaller unmarshaller = null;
	Unmarshaller getUnmarshaller() throws JAXBException, SAXException{
		if(unmarshaller == null){
			unmarshaller = getJAXBContext().createUnmarshaller();
			unmarshaller.setSchema(generateSchema());
		}
		return unmarshaller;
	}
	
	private JAXBContext jaxbContext = null;
    /**
     * Help method maintaining the Assertion JAXB Context.
     */
    private JAXBContext getJAXBContext() throws JAXBException{
    	if(jaxbContext== null){
    		String jaxbClassPath = "org.certificateservices.messages.hardtoken.jaxb:org.certificateservices.messages.xenc.jaxb:org.certificateservices.messages.xmldsig.jaxb";
    			    		
    		jaxbContext = JAXBContext.newInstance(jaxbClassPath);
    		
    	}
    	return jaxbContext;
    }
    

    private Schema generateSchema() throws SAXException{
    	SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
    	
    	schemaFactory.setResourceResolver(new HardTokenParserLSResourceResolver());
		
        Source[] sources = new Source[3];
        sources[0] = new StreamSource(getClass().getResourceAsStream(DefaultCSMessageParser.XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION));
        sources[1] = new StreamSource(getClass().getResourceAsStream(DefaultCSMessageParser.XMLENC_XSD_SCHEMA_RESOURCE_LOCATION));
        sources[2] = new StreamSource(getClass().getResourceAsStream(HARDTOKEN_XSD_SCHEMA_RESOURCE_LOCATION));
        
        
        Schema schema = schemaFactory.newSchema(sources);       
        
        return schema;
    }
    

    private Transformer transformer = null;
    private Transformer getTransformer() throws MessageProcessingException{
    	if(transformer == null){
    		try {
    			TransformerFactory tf = TransformerFactory.newInstance();
    			transformer = tf.newTransformer();
    		} catch (TransformerConfigurationException e) {
    			throw new MessageProcessingException("Error instanciating Transformer for XMLSigner: " + e.getMessage(),e);
    		}
    	}
    	return transformer;
    }
    
    public class HardTokenParserLSResourceResolver implements  LSResourceResolver {
		
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
						return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream(HARDTOKEN_XSD_SCHEMA_RESOURCE_LOCATION));
					}
				}
			} catch (MessageProcessingException e) {
				throw new IllegalStateException("Error couldn't read XSD from class path: " + e.getMessage(), e);
			}
			return null;
		}
	}

	
}
