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
package org.signatureservice.messages.sensitivekeys;

import org.signatureservice.messages.MessageContentException;
import org.signatureservice.messages.MessageProcessingException;
import org.signatureservice.messages.MessageSecurityProvider;
import org.signatureservice.messages.NoDecryptionKeyFoundException;
import org.signatureservice.messages.csmessages.DefaultCSMessageParser;
import org.signatureservice.messages.csmessages.XSDLSInput;
import org.signatureservice.messages.sensitivekeys.jaxb.AsymmetricKey;
import org.signatureservice.messages.sensitivekeys.jaxb.EncodedKey;
import org.signatureservice.messages.sensitivekeys.jaxb.KeyData;
import org.signatureservice.messages.sensitivekeys.jaxb.ObjectFactory;
import org.signatureservice.messages.utils.XMLEncrypter;
import org.signatureservice.messages.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;
import org.xml.sax.SAXException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Class to generate and parse Sensitive Keys Structures.
 * <b>
 * It has also methods to create encrypted binary data defined in
 * the credential managment protocol 2.0 specification.
 * 
 * @author Philip Vendil
 *
 */
public class SensitiveKeysParser {

	public static String NAMESPACE = "http://certificateservices.org/xsd/sensitivekeys";

	public static String DEFAULT_VERSION = "2.0";

	public static final String SENSITIVE_KEYS_XSD_SCHEMA_RESOURCE_LOCATION = "/sensitivekeys_schema2_0.xsd";

	private ObjectFactory of = new ObjectFactory();

	private XMLEncrypter xmlEncrypter;

	private Map<String,KeyFactory> keyFactoryMap = new HashMap<String, KeyFactory>();

	/**
	 * Constructor for Sensitive Keys Parser, this is the default method to create a parser, it should
	 * not be fetched by the PayloadParserRegistry since this is not a CSMessagePayload.
	 *
	 * @param securityProvider the security provider to use for encrypting and decrypting messages.
	 * @throws MessageProcessingException if internal problems occurred initializing the parser.
	 */
	public SensitiveKeysParser(MessageSecurityProvider securityProvider) throws MessageProcessingException{
		
		try {
			xmlEncrypter = new XMLEncrypter(securityProvider, getDocumentBuilder(), getMarshaller(), getUnmarshaller());
		} catch (Exception e) {
			throw new MessageProcessingException("Error initializing SensitiveKeysParser: " + e.getMessage(),e);
		}
	}

	/**
	 * Method to parse a unencrypted sensitive key data.
	 * 
	 * @param data a serialized sensitive key XML structure.
	 * @return a unmarshalled KeyData.
	 * @throws MessageContentException if xml data was invalid
	 * @throws MessageProcessingException if internal problems occurred unmarshalling the data.
	 */
	public KeyData parse(byte[] data) throws MessageContentException, MessageProcessingException{
		Document doc;
		try {
			doc = getDocumentBuilder().parse(new ByteArrayInputStream(data));
			return (KeyData) getUnmarshaller().unmarshal(doc);
		} catch (SAXException e) {
			throw new MessageContentException("Message content error when parsing sensitive key data: " + e.getMessage(), e);
		} catch (IOException e) {
			throw new MessageContentException("Message content error when parsing sensitive key data: " + e.getMessage(), e);
		}catch (JAXBException e) {
			throw new MessageContentException("Message content error when parsing sensitive key data: " + e.getMessage(), e);
		} catch (ParserConfigurationException e) {
			throw new MessageProcessingException("Internal error when parsing sensitive key data: " + e.getMessage(), e);
		} 
	}
	
	/**
	 * Method to decrypt and unmarshall a sensitive key data.
	 * <p>
	 * The encrypted data should be a XML Encryption (http://www.w3.org/2001/04/xmlenc#) EncryptedData element..
	 * @param encryptedData the encrypted XML data.
	 * @return an unmarshalled HardTokenData
	 * @throws MessageContentException if xml data was invalid.
	 * @throws MessageProcessingException if internal problems occurred unmarshalling or decrypting the data.
	 * @throws NoDecryptionKeyFoundException if decryption key couldn't be found in security provider.
	 */
	public KeyData decryptAndParse(byte[] encryptedData) throws MessageContentException, MessageProcessingException, NoDecryptionKeyFoundException{
		
		try {
			Document doc = getDocumentBuilder().parse(new ByteArrayInputStream(encryptedData));
			
			return (KeyData) xmlEncrypter.decryptDocument(doc);
	
		} catch (ParserConfigurationException e) {
			throw new MessageProcessingException("Internal error parsing encrypted sensitive key data: " + e.getMessage(),e);
		} catch (SAXException e) {
			throw new MessageContentException("Internal content encrypted sensitive key data: " + e.getMessage(),e);
		} catch (IOException e) {
			throw new MessageContentException("Internal content encrypted sensitive key data: " + e.getMessage(),e);
		}
	}

	/**
	 * Method to convert an asymmetric key pair.
	 *
	 * @param asymmetricKey the java.security.KeyPair to convert, never null-
	 * @return a newly generated key data.
     */
	public KeyData genKeyData(KeyPair asymmetricKey){
		return genKeyData(encodeKey(asymmetricKey.getPublic()),encodeKey(asymmetricKey.getPrivate()));
	}

	/**
	 * Method to create a key data for a asymmetric key.
	 *
	 * @param publicKey the public key of key pair to use, not null.
	 * @param privateKey the private key of key pair to use, not null.
	 * @return a newly generated key data.
	 */
	public KeyData genKeyData(EncodedKey publicKey, EncodedKey privateKey) {
		KeyData kd = of.createKeyData();
		kd.setVersion(DEFAULT_VERSION);

		AsymmetricKey ak = of.createAsymmetricKey();
		ak.setPublicKey(publicKey);
		ak.setPrivateKey(privateKey);

		kd.setAsymmetricKey(ak);

		return kd;
	}


	/**
	 * Method to create a key data for a symmetric java.security.Key.
	 *
	 * @param symmetricKey the symmetric key to use, not null.
	 * @return a newly generated key data.
	 * @throws MessageProcessingException if date convertion fails.
	 */
	public KeyData genKeyData(Key symmetricKey) {
		return genKeyData(encodeKey(symmetricKey));
	}

	/**
	 * Method to create a key data for a symmetric key.
	 *
	 * @param symmetricKey the symmetric key to use, not null.
	 * @return a newly generated key data.
	 * @throws MessageProcessingException if date convertion fails.
	 */
	public KeyData genKeyData(EncodedKey symmetricKey){
		KeyData kd = of.createKeyData();
		kd.setVersion(DEFAULT_VERSION);
		kd.setSymmetricKey(symmetricKey);

		return kd;
	}

	/**
	 * Method to recreate the java.security symmetric key from a key data.
	 *
	 * @param keyData the key data that must contain a symmetric key element.
	 * @return a secret key.
	 * @throws MessageContentException if key data didn't contain any valid secret key.
     */
	public SecretKey getSymmetricKey(KeyData keyData) throws MessageContentException{
		if(keyData.getSymmetricKey() == null){
			throw new MessageContentException("Error extracting symmetric key from key data, no symmetric key data found.");
		}

		return new SecretKeySpec(keyData.getSymmetricKey().getData(),keyData.getSymmetricKey().getAlgorithm());
	}

	/**
	 * Method to recreate the java.security asymmetric key from a key data.
	 *
	 * @param keyData the key data that must contain a asymmetric key element.
	 * @return a reconstructed key pair..
	 * @throws MessageContentException if key data didn't contain any valid key pair or had unsupported algorithms.
	 */
	public KeyPair getAssymmetricKey(KeyData keyData) throws MessageContentException{
		if(keyData.getAsymmetricKey() == null){
			throw new MessageContentException("Error extracting asymmetric key from key data, no asymmetric key data found.");
		}
		try {
			PublicKey publicKey = null;
			EncodedKey pubKeyEncoded = keyData.getAsymmetricKey().getPublicKey();
			KeyFactory keyFactory = getKeyFactory(pubKeyEncoded.getAlgorithm());
			if(pubKeyEncoded.getFormat().equals("X.509")){
				publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(pubKeyEncoded.getData()));
			}
			PrivateKey privateKey = null;
			EncodedKey privateKeyEncoded = keyData.getAsymmetricKey().getPrivateKey();
			if(privateKeyEncoded.getFormat().equals("PKCS#8")){
				privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyEncoded.getData()));
			}

			if(publicKey != null && privateKey != null){
				return new KeyPair(publicKey,privateKey);
			}
			throw new MessageContentException("Invalid key specification, unsupported encoding format for assymetric key, public key: " + pubKeyEncoded.getFormat() + ", private key: " + privateKeyEncoded.getFormat() );

		} catch (InvalidKeySpecException e) {
			throw new MessageContentException("Invalid key specification in KeyData XML: " + e.getMessage(), e);
		}
	}

	protected EncodedKey encodeKey(Key key){
		EncodedKey ek = of.createEncodedKey();
		ek.setAlgorithm(key.getAlgorithm());
		ek.setFormat(key.getFormat());
		ek.setData(key.getEncoded());
		return ek;
	}
	
	/**
	 * Method to serialize a sensitive key data to a byte array.
	 * 
	 * @param key the sensitive key data to serialize
	 * @return a serialized version of the sensitive key data.
	 * @throws MessageContentException if hard token data contained invalid content.
	 * @throws MessageProcessingException if internal problems occurred marshalling the data.
	 */
	public byte[] marshall(KeyData key) throws MessageContentException, MessageProcessingException{
		Document doc;
		try {
			doc = getDocumentBuilder().newDocument();

			getMarshaller().marshal(key, doc);
			StringWriter writer = new StringWriter();
			getTransformer().transform(new DOMSource(doc), new StreamResult(writer));
			String output = writer.getBuffer().toString();	
			return output.getBytes("UTF-8");
		} catch (JAXBException e) {
			throw new MessageContentException("Message content error when generating sensitive key data: " + e.getMessage(), e);
		} catch (TransformerException e) {
			throw new MessageProcessingException("Internal error when generating sensitive key data: " + e.getMessage(), e);
		} catch (UnsupportedEncodingException e) {
			throw new MessageProcessingException("Internal error when generating sensitive key data: " + e.getMessage(), e);
		}catch (ParserConfigurationException e) {
			throw new MessageProcessingException("Internal error when generating sensitive key data: " + e.getMessage(), e);
		} 
	}
	
	/**
	 * Method to serialize and encrypt a sensitive key data to a given list of recipients.
	 * <p>
	 * The data will first be transformed into a encrypted data.
	 * 
	 * @param key the sensitive key data to serialize
	 * @param recipients a list of recipients to encrypt the data to.
	 * @return a serialized version of the hard token data.
	 * @throws MessageContentException if hard token data contained invalid content.
	 * @throws MessageProcessingException if internal problems occurred marshalling the data.
	 */
	public byte[] encryptAndMarshall(KeyData key, List<X509Certificate> recipients) throws MessageContentException, MessageProcessingException{
		Document doc;
		try {
			doc = getDocumentBuilder().newDocument();
			getMarshaller().marshal(key, doc);
			
			Document encDoc = xmlEncrypter.encryptElement(doc, recipients, false);
			StringWriter writer = new StringWriter();
			getTransformer().transform(new DOMSource(encDoc), new StreamResult(writer));
			String output = writer.getBuffer().toString();	
			return output.getBytes("UTF-8");
		} catch (JAXBException e) {
			throw new MessageContentException("Message content error when generating sensitive key data: " + e.getMessage(), e);
		} catch (TransformerException e) {
			throw new MessageProcessingException("Internal error when generating sensitive key data: " + e.getMessage(), e);
		} catch (UnsupportedEncodingException e) {
			throw new MessageProcessingException("Internal error when generating sensitive key data: " + e.getMessage(), e);
		}catch (ParserConfigurationException e) {
			throw new MessageProcessingException("Internal error when generating sensitive key data: " + e.getMessage(), e);
		} 
	}
	

	private DocumentBuilder getDocumentBuilder() throws ParserConfigurationException {
		return XMLUtils.createSecureDocumentBuilderFactory().newDocumentBuilder();
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
    		String jaxbClassPath = "org.signatureservice.messages.sensitivekeys.jaxb:org.signatureservice.messages.xenc.jaxb:org.signatureservice.messages.xmldsig.jaxb";
    			    		
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
    	
    	schemaFactory.setResourceResolver(new SensitiveKeysParserLSResourceResolver());
		
        Source[] sources = new Source[3];
        sources[0] = new StreamSource(getClass().getResourceAsStream(DefaultCSMessageParser.XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION));
        sources[1] = new StreamSource(getClass().getResourceAsStream(DefaultCSMessageParser.XMLENC_XSD_SCHEMA_RESOURCE_LOCATION));
        sources[2] = new StreamSource(getClass().getResourceAsStream(SENSITIVE_KEYS_XSD_SCHEMA_RESOURCE_LOCATION));
        
        
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
    
    public class SensitiveKeysParserLSResourceResolver implements  LSResourceResolver {
		
		public LSInput resolveResource(String type, String namespaceURI,
				String publicId, String systemId, String baseURI) {
			try {
				if(systemId != null && systemId.equals("datatypes.dtd")){
					return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream("/datatypes.dtd"));
				}
				if(systemId != null && systemId.equals("http://www.w3.org/2001/XMLSchema.dtd")){
					return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream("/XMLSchema.dtd"));
				}
				if(namespaceURI != null){
					if(namespaceURI.equals(DefaultCSMessageParser.XMLENC_NAMESPACE)){
						return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream(DefaultCSMessageParser.XMLENC_XSD_SCHEMA_RESOURCE_LOCATION));
					}
					if(namespaceURI.equals(DefaultCSMessageParser.XMLDSIG_NAMESPACE)){
						return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream(DefaultCSMessageParser.XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION));
					}
					if(namespaceURI.equals(NAMESPACE)){
						return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream(SENSITIVE_KEYS_XSD_SCHEMA_RESOURCE_LOCATION));
					}
				}
			} catch (MessageProcessingException e) {
				throw new IllegalStateException("Error couldn't read XSD from class path: " + e.getMessage(), e);
			}
			return null;
		}
	}

	private KeyFactory getKeyFactory(String algoritm) throws MessageContentException {
		KeyFactory retval = keyFactoryMap.get(algoritm);
		if(retval == null){
			try {
				retval = KeyFactory.getInstance(algoritm);
			} catch (NoSuchAlgorithmException e) {
				throw new MessageContentException("Error in KeyData XML, unsupported key algorithm: " + algoritm);
			}
			keyFactoryMap.put(algoritm,retval);
		}

		return retval;
	}

	
}
