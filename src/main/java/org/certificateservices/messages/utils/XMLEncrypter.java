/************************************************************************
 *                                                                       *
 *  Certificate Service - Messages                                       *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.certificateservices.messages.utils;

import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.KeyName;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.EncryptionConstants;
import org.certificateservices.messages.*;
import org.certificateservices.messages.ContextMessageSecurityProvider.Context;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;

import static org.certificateservices.messages.utils.XMLSigner.XMLDSIG_NAMESPACE;


/**
 * Helper methods to perform XML Encryption and Decryption tasks on JAXB Elements.
 * 
 * @author Philip Vendil
 *
 */
public class XMLEncrypter {
	private static String XMLENC_NAMESPACE = "http://www.w3.org/2001/04/xmlenc#";

	private MessageSecurityProvider securityProvider;
	private DocumentBuilder documentBuilder;
	private Marshaller marshaller;
	private Unmarshaller unmarshaller;

	private Map<Context, XMLCipher> encKeyXMLCipherMap = new HashMap<Context, XMLCipher>();
	private Map<Context, XMLCipher> encDataXMLCipherMap = new HashMap<Context, XMLCipher>();
	private XMLCipher decChiper;

	private CertificateFactory cf;
	private Map<Context, KeyGenerator> dataKeyGeneratorMap = new HashMap<Context, KeyGenerator>();

	private Set<String> supportedEncryptionChipers = new HashSet<String>();

	/**
	 * Enumeration of supported KeyInfoTypes
	 */
	public enum KeyInfoType{
		KEYNAME,
		KEYVALUE,
		X509CERTIFICATE
	}

	/**
	 * Contsructor of a xml XML Encrypter.
	 *
	 * @param securityProvider the used context message security provider
	 * @param documentBuilder  the DOM Document Builder used for related messages.
	 * @param marshaller       the JAXB Marshaller used for related messages.
	 * @param unmarshaller     the JAXB Unmarshaller used for related messages.
	 * @throws MessageProcessingException if problems occurred initializing this helper class.
	 */
	public XMLEncrypter(MessageSecurityProvider securityProvider,
						DocumentBuilder documentBuilder,
						Marshaller marshaller,
						Unmarshaller unmarshaller) throws MessageProcessingException {
		this.securityProvider = securityProvider;
		this.documentBuilder = documentBuilder;
		this.marshaller = marshaller;
		this.unmarshaller = unmarshaller;

		try {
			this.decChiper = XMLCipher.getInstance();
			cf = CertificateFactory.getInstance("X.509");

			for (EncryptionAlgorithmScheme s : EncryptionAlgorithmScheme.values()) {
				supportedEncryptionChipers.add(s.getDataEncryptionAlgorithmURI());
				supportedEncryptionChipers.add(s.getKeyEncryptionAlgorithmURI());
			}

		} catch (Exception e) {
			throw new MessageProcessingException("Error instanciating XML chipers: " + e.getMessage(), e);
		}
	}

	/**
	 * Method to create a encrypted DOM structure containing a EncryptedData element of the related JAXB Element.
	 *
	 * @param element     the JAXB element to decrypt.
	 * @param receipients a list of reciepiets of the message.
	 * @param useKeyId    if in key info should be included the shorter KeyName tag instead of X509Certificate
	 * @return a new DOM Document the encrypted data.
	 * @throws MessageProcessingException if internal problems occurred generating the data.
	 */
	@Deprecated
	public Document encryptElement(JAXBElement<?> element, List<X509Certificate> receipients, boolean useKeyId) throws MessageProcessingException {
		return encryptElement(ContextMessageSecurityProvider.DEFAULT_CONTEXT, element,receipients,useKeyId);
	}

	/**
	 * Method to create a encrypted DOM structure containing a EncryptedData element of the related JAXB Element.
	 *
	 * @param context the message security provider context to use
	 * @param element     the JAXB element to decrypt.
	 * @param receipients a list of reciepiets of the message.
	 * @param useKeyId    if in key info should be included the shorter KeyName tag instead of X509Certificate
	 * @return a new DOM Document the encrypted data.
	 * @throws MessageProcessingException if internal problems occurred generating the data.
	 */
	public Document encryptElement(Context context, JAXBElement<?> element, List<X509Certificate> receipients, boolean useKeyId) throws MessageProcessingException {
		return encryptElement(context,element,receipients,useKeyId?KeyInfoType.KEYNAME:KeyInfoType.X509CERTIFICATE);
	}

	/**
	 * Method to create a encrypted DOM structure containing a EncryptedData element of the related JAXB Element.
	 *
	 * @param context the message security provider context to use
	 * @param element     the JAXB element to decrypt.
	 * @param receipients a list of reciepiets of the message.
	 * @param keyInfoType    The type of keyinfo to add to the encrypted element.
	 * @return a new DOM Document the encrypted data.
	 * @throws MessageProcessingException if internal problems occurred generating the data.
	 */
	public Document encryptElement(Context context, JAXBElement<?> element, List<X509Certificate> receipients, KeyInfoType keyInfoType) throws MessageProcessingException {
		try {
			Document doc = documentBuilder.newDocument();

			marshaller.marshal(element, doc);

			return encryptElement(context, doc, receipients, keyInfoType);

		} catch (Exception e) {
			if (e instanceof MessageProcessingException) {
				throw (MessageProcessingException) e;
			}
			throw new MessageProcessingException("Internal error occurred when encrypting XML: " + e.getMessage(), e);
		}
	}

	/**
	 * Method to create a encrypted DOM structure containing a EncryptedData element of the related JAXB Element. Uning default context
	 *
	 * @param doc         the document to encrypt.
	 * @param receipients a list of reciepiets of the message.
	 * @param useKeyId    if in key info should be included the shorter KeyName tag instead of X509Certificate
	 * @return a new DOM Document the encrypted data.
	 * @throws MessageProcessingException if internal problems occurred generating the data.
	 */
	@Deprecated
	public Document encryptElement(Document doc, List<X509Certificate> receipients, boolean useKeyId) throws MessageProcessingException{
		return encryptElement(ContextMessageSecurityProvider.DEFAULT_CONTEXT, doc,receipients,useKeyId);
    }
	/**
	 * Method to create a encrypted DOM structure containing a EncryptedData element of the related JAXB Element.
	 *
	 * @param context related security context.
	 * @param doc the document to encrypt.
	 * @param receipients a list of reciepiets of the message.
	 * @param useKeyId if in key info should be included the shorter KeyName tag instead of X509Certificate
	 * @return a new DOM Document the encrypted data.
	 * @throws MessageProcessingException if internal problems occurred generating the data.
	 */
	public  Document encryptElement(Context context, Document doc, List<X509Certificate> receipients, boolean useKeyId) throws MessageProcessingException{
		return encryptElement(context,doc,receipients,useKeyId?KeyInfoType.KEYNAME:KeyInfoType.X509CERTIFICATE);
	}

	/**
	 * Method to create a encrypted DOM structure containing a EncryptedData element of the related JAXB Element.
	 *
	 * @param context related security context.
	 * @param doc the document to encrypt.
	 * @param receipients a list of reciepiets of the message.
	 * @param keyInfoType The type of keyinfo to add to the encrypted element.
	 * @return a new DOM Document the encrypted data.
	 * @throws MessageProcessingException if internal problems occurred generating the data.
	 */
	public  Document encryptElement(Context context, Document doc, List<X509Certificate> receipients, KeyInfoType keyInfoType) throws MessageProcessingException{
		try{

			Key dataKey = getDataKeyGenerator(context).generateKey();

			XMLCipher encDataXMLCipher = getEncDataXMLCipher(context);
			encDataXMLCipher.init(XMLCipher.ENCRYPT_MODE, dataKey);
			EncryptedData encData = encDataXMLCipher.getEncryptedData();
			KeyInfo keyInfo = new KeyInfo(doc);
			for(X509Certificate receipient: receipients){
				keyInfo.add(addReceipient(context, doc, dataKey, receipient, keyInfoType));
			}
			encData.setKeyInfo(keyInfo);
			Element documentElement = doc.getDocumentElement();
			doc = encDataXMLCipher.doFinal(doc, documentElement, false);
			return doc;

		}catch(Exception e){
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageProcessingException("Internal error occurred when encrypting XML: " + e.getMessage(),e);
		}
	}
	
	/**
	 * Method to decrypt all encrypted structures in the related message. Using default context.
	 * 
	 * <b>Important: If multiple EncryptedData exists it must be encrypted with the same data key and receipients.</b>
	 * @param doc the document containing encrypted data.
	 * @return a JAXB version of the document where all encrypted attributes are decrypted.
	 * @throws MessageProcessingException if internal problems occurred decrypting the message.
	 * @throws MessageContentException if content of message was invalid
	 * @throws NoDecryptionKeyFoundException if no related decryption key could be found with the message.
	 */
	@Deprecated
	public Object decryptDocument(Document doc) throws MessageProcessingException, MessageContentException, NoDecryptionKeyFoundException{
		return decryptDocument(ContextMessageSecurityProvider.DEFAULT_CONTEXT, doc, null);
	}

	/**
	 * Method to decrypt all encrypted structures in the related message.
	 *
	 * <b>Important: If multiple EncryptedData exists it must be encrypted with the same data key and receipients.</b>
	 * @param context the message security context to use.
	 * @param doc the document containing encrypted data.
	 * @return a JAXB version of the document where all encrypted attributes are decrypted.
	 * @throws MessageProcessingException if internal problems occurred decrypting the message.
	 * @throws MessageContentException if content of message was invalid
	 * @throws NoDecryptionKeyFoundException if no related decryption key could be found with the message.
	 */
	public Object decryptDocument(Context context, Document doc) throws MessageProcessingException, MessageContentException, NoDecryptionKeyFoundException{
		return decryptDocument(context, doc, null);
	}

	/**
	 * Method to decrypt all encrypted structures in the related message. Using default context.
	 *
	 * <b>Important: If multiple EncryptedData exists it must be encrypted with the same data key and receipients.</b>
	 *
	 * @param doc the document containing encrypted data.
	 * @param converter the post decryption xml converter to manipulate the result to fullfill schema, null to disable manipulation.
	 * @return a JAXB version of the document where all encrypted attributes are decrypted.
	 * @throws MessageProcessingException if internal problems occurred decrypting the message.
	 * @throws MessageContentException if content of message was invalid
	 * @throws NoDecryptionKeyFoundException if no related decryption key could be found with the message.
	 */
	@Deprecated
	public Object decryptDocument(Document doc, DecryptedXMLConverter converter) throws MessageProcessingException, MessageContentException, NoDecryptionKeyFoundException{
		return decryptDocument(ContextMessageSecurityProvider.DEFAULT_CONTEXT,doc,converter);
	}
	/**
	 * Method to decrypt all encrypted structures in the related message.
	 * 
	 * <b>Important: If multiple EncryptedData exists it must be encrypted with the same data key and receipients.</b>
	 * @param context the message security context to use.
	 * @param doc the document containing encrypted data.
	 * @param converter the post decryption xml converter to manipulate the result to fullfill schema, null to disable manipulation.
	 * @return a JAXB version of the document where all encrypted attributes are decrypted.
	 * @throws MessageProcessingException if internal problems occurred decrypting the message.
	 * @throws MessageContentException if content of message was invalid
	 * @throws NoDecryptionKeyFoundException if no related decryption key could be found with the message.
	 */
	public Object decryptDocument(Context context, Document doc, DecryptedXMLConverter converter) throws MessageProcessingException, MessageContentException, NoDecryptionKeyFoundException{
		try{
			return unmarshaller.unmarshal(decryptDoc(doc,converter));
		}catch(Exception e){
			if(e instanceof NoDecryptionKeyFoundException){
				throw (NoDecryptionKeyFoundException) e;
			}
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageProcessingException("Internal error occurred when decrypting XML: " + e.getMessage(),e);
		}
	}

	/**
	 * Method to decrypt all encrypted structures in the related message, using default context.
	 *
	 * <b>Important: If multiple EncryptedData exists it must be encrypted with the same data key and receipients.</b>
	 * @param doc the document containing encrypted data.
	 * @param converter the post decryption xml converter to manipulate the result to fullfill schema, null to disable manipulation.
	 * @return a new Document with decrypted content.
	 * @throws MessageProcessingException if internal problems occurred decrypting the message.
	 * @throws MessageContentException if content of message was invalid
	 * @throws NoDecryptionKeyFoundException if no related decryption key could be found with the message.
	 */
	public Document decryptDoc(Document doc, DecryptedXMLConverter converter) throws MessageProcessingException, MessageContentException, NoDecryptionKeyFoundException{
		return decryptDoc(ContextMessageSecurityProvider.DEFAULT_CONTEXT, doc, converter);
	}

	/**
	 * Method to decrypt all encrypted structures in the related message.
	 * 
	 * <b>Important: If multiple EncryptedData exists it must be encrypted with the same data key and receipients.</b>
	 * @param context the message security context to use with the security provider.
	 * @param doc the document containing encrypted data.
	 * @param converter the post decryption xml converter to manipulate the result to fullfill schema, null to disable manipulation.
	 * @return a new Document with decrypted content.
	 * @throws MessageProcessingException if internal problems occurred decrypting the message.
	 * @throws MessageContentException if content of message was invalid
	 * @throws NoDecryptionKeyFoundException if no related decryption key could be found with the message.
	 */
	public Document decryptDoc(Context context, Document doc, DecryptedXMLConverter converter) throws MessageProcessingException, MessageContentException, NoDecryptionKeyFoundException{
		try{
			verifyKeyInfo(doc);
			NodeList nodeList = doc.getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS, EncryptionConstants._TAG_ENCRYPTEDDATA);

			while(nodeList.getLength() > 0){
				Element encryptedElement = (Element) nodeList.item(0);
				verifyCiphers(encryptedElement);
				Key kekKey = findKEK(context,encryptedElement);

				if(securityProvider instanceof HSMMessageSecurityProvider){
					String provider = ((HSMMessageSecurityProvider) securityProvider).getHSMProvider();
					Key encKey = resolveKey(encryptedElement, kekKey, provider);
					decChiper.init(XMLCipher.DECRYPT_MODE, encKey);
				} else {
					decChiper.init(XMLCipher.DECRYPT_MODE, null);
					decChiper.setKEK(kekKey);
				}

				doc = decChiper.doFinal(doc, encryptedElement);
				nodeList = doc.getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS, EncryptionConstants._TAG_ENCRYPTEDDATA);
			}

			if(converter != null){
				doc = converter.convert(doc);
			}
			
			return doc;
		}catch(Exception e){
			if(e instanceof NoDecryptionKeyFoundException){
				throw (NoDecryptionKeyFoundException) e;
			}
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageProcessingException("Internal error occurred when decrypting XML: " + e.getMessage(),e);
		}
	}

	/**
	 * Method to resolve (unwrap) a symmetric key using a specific provider.
	 * This must be used in some cases when unwrapping is performed using
	 * a HSM and with a specific Java Security Provider (JSP).
	 *
	 * @param element Element containing encrypted symmetric key
	 * @param kekKey Key-encryption key
	 * @param provider Provider to use for unwrap operation.
	 * @return Unwrapped symmetric encryption key or null if an error occurred.
	 */
	Key resolveKey(Element element, Key kekKey, String provider) {
		try {
			Element keyInfoElement = (Element) element.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "KeyInfo").item(0);
			XMLCipher cipher = XMLCipher.getProviderInstance(provider);
			cipher.init(Cipher.UNWRAP_MODE, kekKey);
			EncryptedKey ek = cipher.loadEncryptedKey(keyInfoElement);
			return cipher.decryptKey(ek, XMLCipher.AES_256);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Method to encrypt java.util.Properties in XML-format
	 * @param properties properties to encrypt
	 * @param receipients a list of recipients of the properties.
	 * @param useKeyId if in key info should be included the shorter KeyName tag instead of X509Certificate
	 * @return a new DOM Document with the encrypted properties.
	 * @throws MessageProcessingException if internal problems occurred encrypting the message.
	 */
	public Document encryptProperties(Properties properties, List<X509Certificate> receipients, boolean useKeyId) throws MessageProcessingException {
		Document encDocument = null, document = null;
		try {
			ByteArrayOutputStream os = new ByteArrayOutputStream();		
			properties.storeToXML(os, null, "UTF-8");			
			InputStream is = new ByteArrayInputStream(os.toByteArray());
			documentBuilder.setEntityResolver(new EntityResolver() {
				@Override
				public InputSource resolveEntity(String publicId, String systemId) throws SAXException, IOException {
					if(systemId != null && systemId.equals("http://java.sun.com/dtd/properties.dtd")){
						return new InputSource(this.getClass().getResourceAsStream("/properties.dtd"));
					}
					return null;
				}
			});
			document = documentBuilder.parse(is);

			encDocument = encryptElement(document, receipients, useKeyId);
		} catch(Exception e){
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageProcessingException("Internal error occurred when encrypting properties: " + e.getMessage(), e);
		}

		return encDocument;
	}

	/**
	 * Method to decrypt document containing properties in XML-format.
	 * @param encDocument the document containing encrypted data.
	 * @return decrypted properties
	 * @throws NoDecryptionKeyFoundException if no related decryption key could be found.
	 * @throws MessageProcessingException if internal problems occurred decrypting the message.
	 * @throws MessageContentException if content of document was invalid
	 */
	public Properties decryptProperties(Document encDocument) throws NoDecryptionKeyFoundException, MessageProcessingException, MessageContentException {
		Properties properties = null;
		
		try {
			Document document = decryptDoc(encDocument, null);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();		
			Source src = new DOMSource(document);
			Result res = new StreamResult(baos);
			Transformer trf = TransformerFactory.newInstance().newTransformer();
			trf.setOutputProperty(OutputKeys.DOCTYPE_SYSTEM, "http://java.sun.com/dtd/properties.dtd");
			trf.transform(src, res);
			InputStream is = new ByteArrayInputStream(baos.toByteArray());
			properties = new Properties();
			properties.loadFromXML(is);
		} catch(Exception e){
			if(e instanceof NoDecryptionKeyFoundException){
				throw (NoDecryptionKeyFoundException) e;
			}
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageProcessingException("Internal error occurred when decrypting properties: " + e.getMessage(), e);
		}
		
		return properties;
	}
	
	/**
	 * Method to verify that data was encrypted with supported chiphers only.
	 * @param encryptedElement the encrypted element to verify.
	 * @throws MessageContentException if unsupported ciphers was used.
	 */
	private void verifyCiphers(Element encryptedElement) throws MessageContentException{
		NodeList nodeList = encryptedElement.getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS, EncryptionConstants._TAG_ENCRYPTIONMETHOD);
		for(int i=0; i<nodeList.getLength();i++){
			Element encryptionMetod = (Element) nodeList.item(0);
			String alg = encryptionMetod.getAttribute(EncryptionConstants._ATT_ALGORITHM);
			if(!supportedEncryptionChipers.contains(alg)){
		       throw new MessageContentException("Error unsupported encryption algorithm " + alg + " for encrypted XML data");		
			}
		}
		
	}

	/**
	 * Method to verify KeyInfo of an encrypted document and perform any required
	 * processing to it (i.e. resolve EncryptedKey references).
	 * @param document The encrypted document to verify
	 * @throws MessageContentException If error occurred when processing encrypted element.
	 */
	private void verifyKeyInfo(Document document) throws MessageContentException {
		NodeList keyInfoList = document.getElementsByTagNameNS(XMLDSIG_NAMESPACE, "KeyInfo");
		if (keyInfoList.getLength() == 0) {
			throw new MessageContentException("No KeyInfo found in encrypted element");
		}

		NodeList encryptedKeyList = document.getElementsByTagNameNS(XMLENC_NAMESPACE, "EncryptedKey");

		// Check for RetrievalMethod elements and resolve them by replacing the element
		// with the references URI element (currently only EncryptedKey are supported).
		for(int i=0; i<keyInfoList.getLength(); i++) {
			Node keyInfo = keyInfoList.item(i);
			NodeList keyInfoChildren = keyInfo.getChildNodes();
			for (int j = 0; j < keyInfoChildren.getLength(); j++) {
				if (keyInfoChildren.item(j).getLocalName() != null && keyInfoChildren.item(j).getLocalName().equals("RetrievalMethod")) {
					Element retrievalMethodElement = (Element) keyInfoChildren.item(j);
					if (!retrievalMethodElement.getAttribute("Type").equals("http://www.w3.org/2001/04/xmlenc#EncryptedKey")) {
						throw new MessageContentException("RetrievalMethod not supported: " + retrievalMethodElement.getAttribute("Type"));
					}

					String uri = retrievalMethodElement.getAttribute("URI").substring(1);
					for (int k = 0; k < encryptedKeyList.getLength(); k++) {
						if (((Element) encryptedKeyList.item(k)).getAttribute("Id").equals(uri)) {
							keyInfo.replaceChild(encryptedKeyList.item(k), keyInfoChildren.item(j));
						}
					}
				}
			}
		}
	}

	/**
	 * Help method that looks through all key info and tries to find all Key Info elements of type KeyName or X509Certificate
	 * that is used to check if message security provider has relevant decryption key.
	 *
	 * @param context the message security context to use with the security provider.
	 * @param encryptedElement the encrypted element to extract key info from
	 * @return a related Private Key used to decrypt the data key with.
	 * @throws MessageContentException if no valid decryption key could be found in the key info.
	 */
	private Key findKEK(Context context, Element encryptedElement) throws NoDecryptionKeyFoundException {
		try{
			Set<String> availableKeyIds;
			if(securityProvider instanceof ContextMessageSecurityProvider){
				availableKeyIds = ((ContextMessageSecurityProvider) securityProvider).getDecryptionKeyIds(context);
			}else{
				availableKeyIds = securityProvider.getDecryptionKeyIds();
			}

			NodeList keyNameList = encryptedElement.getElementsByTagNameNS(XMLDSIG_NAMESPACE, "KeyName");
			for(int i=0; i<keyNameList.getLength();i++){
				Node keyName = keyNameList.item(i);
				String keyId = keyName.getFirstChild().getNodeValue();
				if(keyId != null){
					keyId = keyId.trim();
					if(availableKeyIds.contains(keyId)){
						return getDecryptionKey(context,keyId);
					}
				}			
			}

			NodeList certList = encryptedElement.getElementsByTagNameNS(XMLDSIG_NAMESPACE, "X509Certificate");
			for(int i=0; i<certList.getLength();i++){
				Node certNode = certList.item(i);
				String certData = certNode.getFirstChild().getNodeValue();
				if(certData != null){
					X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.decode(certData)));
					String keyId = generateKeyId(cert.getPublicKey());
					if(availableKeyIds.contains(keyId)){
						return getDecryptionKey(context,keyId);
					}
				}
			}

			NodeList rsaKeyValueList = encryptedElement.getElementsByTagNameNS(XMLDSIG_NAMESPACE, "RSAKeyValue");
			for(int i=0;i<rsaKeyValueList.getLength();i++){
				String modValue = null;
				String expValue = null;
				Node rsaKeyNode = rsaKeyValueList.item(i);

				NodeList modValueList = ((Element)rsaKeyNode).getElementsByTagNameNS(XMLDSIG_NAMESPACE, "Modulus");
				if(modValueList != null && modValueList.getLength() > 0) {
					modValue = modValueList.item(0).getFirstChild().getNodeValue();
				}

				NodeList expValueList = ((Element)rsaKeyNode).getElementsByTagNameNS(XMLDSIG_NAMESPACE, "Exponent");
				if(expValueList != null && expValueList.getLength() > 0) {
					expValue = expValueList.item(0).getFirstChild().getNodeValue();
				}

				if(modValue != null && expValue != null){
					BigInteger modulus = new BigInteger(1, Base64.decode(modValue));
					BigInteger exponent = new BigInteger(1, Base64.decode(expValue));
					RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
					KeyFactory factory = KeyFactory.getInstance("RSA");
					PublicKey publicKey = factory.generatePublic(spec);

					String keyId = generateKeyId(publicKey);
					if(availableKeyIds.contains(keyId)){
						return getDecryptionKey(context,keyId);
					}
				}
			}

			KeyInfo keyInfo = new KeyInfo(encryptedElement,encryptedElement.getBaseURI());
			PublicKey publicKey = keyInfo.getPublicKey();
			if(publicKey != null){
				String keyId = generateKeyId(publicKey);
				if(availableKeyIds.contains(keyId)){
					return getDecryptionKey(context,keyId);
				}
			}

		} catch(Exception e){
			throw new NoDecryptionKeyFoundException("Error finding encryption public key in XML message: " + e.getMessage(), e);
		}

		throw new NoDecryptionKeyFoundException("Error couldn't find any matching decryption key to decrypt XML message");

	}


	private PrivateKey getDecryptionKey(Context context, String keyId) throws MessageProcessingException {
		if(securityProvider instanceof ContextMessageSecurityProvider){
			return ((ContextMessageSecurityProvider) securityProvider).getDecryptionKey(context,keyId);
		}else{
			return securityProvider.getDecryptionKey(keyId);
		}
	}

	private static MessageDigest generateKeyDigest;
	/**
	 * Help method to generate a key id from a public key by calculating its SHA-256 Hash value and Base64 encoding it.
	 */
	public static String generateKeyId(PublicKey publicKey) throws MessageProcessingException{
		try{
			if(generateKeyDigest == null){
				generateKeyDigest = MessageDigest.getInstance("SHA-256");
			}
			generateKeyDigest.update(publicKey.getEncoded());
			return new String(Base64.encode(generateKeyDigest.digest()));
		}catch(Exception e){
			throw new MessageProcessingException(e.getMessage(),e);
		}
	}
	
	/**
	 * Help method to add a receipient to a message.
	 */
	private EncryptedKey addReceipient(Context context, Document doc, Key dataKey, X509Certificate receipient, KeyInfoType keyInfoType) throws XMLEncryptionException, CertificateEncodingException, MessageProcessingException{
		XMLCipher encKeyXMLCipher = getEncKeyXMLCipher(context);
		encKeyXMLCipher.init(XMLCipher.WRAP_MODE,receipient.getPublicKey());
		KeyInfo keyInfo = new KeyInfo(doc);
		EncryptedKey retval = encKeyXMLCipher.encryptKey(doc, dataKey);

		switch (keyInfoType){
			case KEYNAME:
				KeyName keyName = new KeyName(doc, generateKeyId(receipient.getPublicKey()));
				keyInfo.add(keyName);
				break;
			case KEYVALUE:
				keyInfo.add(receipient.getPublicKey());
				break;
			case X509CERTIFICATE:
				X509Data x509Data = new X509Data(doc);
				x509Data.addCertificate(receipient.getEncoded());
				keyInfo.add(x509Data);
				break;
		}
		retval.setKeyInfo(keyInfo);
		return retval;
	}

	private XMLCipher getEncKeyXMLCipher(Context context) throws MessageProcessingException{
		XMLCipher retval = encKeyXMLCipherMap.get(context);
		if(retval == null){
			try {
				retval = XMLCipher.getInstance(getScheme(context).getKeyEncryptionAlgorithmURI());
				encKeyXMLCipherMap.put(context,retval);
			}catch(XMLEncryptionException e){
				throw new MessageProcessingException("Error creating Enc Key Alg Scheme: " + e.getMessage(),e);
			}
		}

		return retval;
	}

	private XMLCipher getEncDataXMLCipher(Context context) throws MessageProcessingException{
		XMLCipher retval = encDataXMLCipherMap.get(context);
		if(retval == null){
			try {
				retval = XMLCipher.getInstance(getScheme(context).getDataEncryptionAlgorithmURI());
				encDataXMLCipherMap.put(context,retval);
			}catch(XMLEncryptionException e){
				throw new MessageProcessingException("Error creating Enc Data Alg Scheme: " + e.getMessage(),e);
			}
		}

		return retval;
	}

	private KeyGenerator getDataKeyGenerator(Context context) throws MessageProcessingException {
		KeyGenerator retval = dataKeyGeneratorMap.get(context);
		if(retval == null){
			try {
				EncryptionAlgorithmScheme scheme = getScheme(context);
				switch(scheme){
					case RSA_OAEP_WITH_AES256:
					case RSA_PKCS1_5_WITH_AES256:
						retval = KeyGenerator.getInstance("AES");
						retval.init(256);
						break;
					default:
						throw new MessageProcessingException("Unsupported Encryption scheme " + scheme);
				}
				dataKeyGeneratorMap.put(context,retval);
			} catch (NoSuchAlgorithmException e) {
				throw new MessageProcessingException("Error creating Encryption key generator: " + e.getMessage(),e);
			}
		}

		return retval;
	}

	private EncryptionAlgorithmScheme getScheme(Context context) throws MessageProcessingException {
		if(securityProvider instanceof ContextMessageSecurityProvider){
			return ((ContextMessageSecurityProvider) securityProvider).getEncryptionAlgorithmScheme(context);
		}else{
			return securityProvider.getEncryptionAlgorithmScheme();
		}
	}


	
	/**
	 * Interface to do post decryption manipulation to the DOM to have the decrypted document to fullfill it schema.
	 * 
	 * @author Philip Vendil
	 */
	public interface DecryptedXMLConverter{
		
		/**
		 * Method to manipulate a encrypted document structure.
		 * @param doc the decrypted document
		 * @return a converted document that satisfies schema.
		 * @throws MessageContentException if decrypted document contain faulty schema.
		 */
		Document convert(Document doc) throws MessageContentException;
	}
}
