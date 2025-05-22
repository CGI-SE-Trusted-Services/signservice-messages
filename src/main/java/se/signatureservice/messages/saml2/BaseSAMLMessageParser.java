/************************************************************************
 *                                                                       *
 *  Signature Service - Messages                                         *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.messages.saml2;

import se.signatureservice.messages.*;
import se.signatureservice.messages.*;
import se.signatureservice.messages.assertion.ResponseStatusCodes;
import se.signatureservice.messages.csmessages.DefaultCSMessageParser;
import se.signatureservice.messages.csmessages.XSDLSInput;
import se.signatureservice.messages.saml2.assertion.jaxb.*;
import se.signatureservice.messages.saml2.assertion.jaxb.*;
import se.signatureservice.messages.saml2.protocol.jaxb.*;
import se.signatureservice.messages.utils.*;
import se.signatureservice.messages.saml2.protocol.jaxb.ObjectFactory;
import se.signatureservice.messages.utils.*;
import se.signatureservice.messages.utils.XMLEncrypter.DecryptedXMLConverter;
import se.signatureservice.messages.utils.XMLSigner.SignatureLocationFinder;
import se.signatureservice.messages.xmldsig.jaxb.X509DataType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import jakarta.xml.bind.*;
import jakarta.xml.bind.util.JAXBSource;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Base SAML Message Parser that all SAML Message Parser that is not connected to the
 * CSMessage workflow should inherit.
 * <p>
 *     It is possible to extend the parsing of XML using the settings 'jaxb.customclasspath' and 'jaxb.customschemas'
 * </p>
 *
 * 
 * @author Philip Vendil
 *
 */
public abstract class BaseSAMLMessageParser {


	/**
	 * A ':' separated string containing package paths to JAXB libraries used with extensions to the
	 * parser.
	 */
	public static String SETTING_CUSTOM_JAXBCLASSPATH = "jaxb.customclasspath";

	/**
	 * A ':' separated string containing the resource path to custom schemas used during validation.
	 * Each path should be found using the getResourceAsStream method, so the schema might be placed
	 * inside a Jar on the classpath.
	 */
	public static String SETTING_CUSTOM_SCHEMALOCATIONS = "jaxb.customschemas";

	public static String ASSERTION_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:assertion";
	public static String PROTOCOL_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:protocol";


	public static String DEFAULT_SAML_VERSION = "2.0";

	public static final String ASSERTION_XSD_SCHEMA_2_0_RESOURCE_LOCATION = "/cs-message-saml-schema-assertion-2.0.xsd";
	public static final String SAMLP_XSD_SCHEMA_2_0_RESOURCE_LOCATION = "/cs-message-saml-schema-protocol-2.0.xsd";


	protected String customJAXBClasspath = null;
	protected String[] customSchemaLocations = new String[0];
	protected se.signatureservice.messages.saml2.assertion.jaxb.ObjectFactory of = new se.signatureservice.messages.saml2.assertion.jaxb.ObjectFactory();
	protected ObjectFactory samlpOf = new ObjectFactory();
	protected se.signatureservice.messages.xmldsig.jaxb.ObjectFactory dsigOf = new se.signatureservice.messages.xmldsig.jaxb.ObjectFactory();
	protected SystemTime systemTime = new DefaultSystemTime();
	protected XMLEncrypter xmlEncrypter;
	EncryptedAttributeXMLConverter encryptedAttributeXMLConverter = new EncryptedAttributeXMLConverter();

	protected XMLSigner xmlSigner;
	protected CertificateFactory cf;
	protected SAMLParserCustomisations customisations;
	protected MessageSecurityProvider messageSecurityProvider;

	protected Validator schemaValidator;

	protected AssertionSignatureLocationFinder assertionSignatureLocationFinder = new AssertionSignatureLocationFinder();
	protected SAMLPSignatureLocationFinder samlpSignatureLocationFinder = new SAMLPSignatureLocationFinder();



	/**
	 * Method to initialise the SAML parser using standard XSDs.
	 * @param secProv Message Security Provider to use.
	 * @throws MessageProcessingException if internal problems occurred setting up the SAMLMessageParser.
     */
	public void init(MessageSecurityProvider secProv) throws MessageProcessingException {
		init(secProv,null);
	}

	/**
	 * Method to initialise the parser using standard XSDs and extra XSD used for extentions.
	 *
	 * @param secProv Message Security Provider to use. If context is not default must a ContextMessageSecurityProvider be specified.
	 * @param customisations implementation to specify non-SAML core JAXB extensions.
	 *
	 * @throws MessageProcessingException if internal problems occurred setting up the SAMLMessageParser.
	 */
	public void init(MessageSecurityProvider secProv, SAMLParserCustomisations customisations)
			throws MessageProcessingException {
		try {
			this.customisations = customisations;

			if(customisations != null) {
				customJAXBClasspath = customisations.getCustomJAXBClasspath();
				customSchemaLocations = customisations.getCustomSchemaLocations();
			}
			messageSecurityProvider = secProv;
			xmlEncrypter = new XMLEncrypter(secProv, getDocumentBuilder(), getMarshaller(), getUnmarshaller());
			xmlSigner = new XMLSigner(secProv, true, getSignatureLocationFinder(), getOrganisationLookup());
			cf = CertificateFactory.getInstance("X.509");

			schemaValidator = generateSchema().newValidator();
		} catch (Exception e) {
			throw new MessageProcessingException("Error initializing JAXB in SAMLMessageParser: " + e.getMessage(),e);
		}
	}

	/**
	 * Method that should return the main namespace of the packate
	 */
	public abstract String getNameSpace();

	/**
	 * @return  all related JAXBPackages.
	 */
	protected abstract String getJAXBPackages();

	/**
	 * @return an array of schema locations used by the parser. The string value should
	 * point to resources available using getResourceAsStream()
	 */
	protected abstract String[] getDefaultSchemaLocations() throws SAXException;


	/**
	 *
	 * @return returns the implementation locating the signature element of a specific message.
     */
	protected abstract XMLSigner.SignatureLocationFinder getSignatureLocationFinder();

	/**
	 *
	 * @return the implementation to lookup related organisation in a specific message.
     */
	protected abstract XMLSigner.OrganisationLookup getOrganisationLookup();


	/**
	 * Method to find Schema for a specific  element related to the custom schema locations. The implementation
	 * only need to find it's related XSD, the basic datatypes and XML itself are not needed.
	 *
	 * @param type The type of the resource being resolved. For XML [XML 1.0] resources (i.e. entities),
	 *             applications must use the value "http://www.w3.org/TR/REC-xml". For XML Schema [XML Schema Part 1],
	 *             applications must use the value "http://www.w3.org/2001/XMLSchema". Other types of resources are
	 *             outside the scope of this specification and therefore should recommend an absolute URI in order
	 *             to use this method.
	 * @param namespaceURI The namespace of the resource being resolved, e.g. the target namespace of the XML Schema
	 *                     [XML Schema Part 1] when resolving XML Schema resources.
	 * @param publicId The public identifier of the external entity being referenced, or null if no public identifier
	 *                 was supplied or if the resource is not an entity.
	 * @param systemId The system identifier, a URI reference [IETF RFC 2396], of the external resource being
	 *                 referenced, or null if no system identifier was supplied.
	 * @param baseURI The absolute base URI of the resource being parsed, or null if there is no base URI.
	 * @return the resource as stream path to related schema XSD, or null if no matching found.
	 */
	protected abstract String lookupSchemaForElement(String type, String namespaceURI,
												  String publicId, String systemId, String baseURI);

	private Schema schema = null;
	private Schema getSchema() throws SAXException {
		if(schema == null){
			schema = generateSchema();
		}
		return schema;
	}

	public Schema generateSchema() throws SAXException {
		SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);

		schemaFactory.setResourceResolver(new BaseLSResourceResolver(customisations));

		String[] defaultSchemaLocations = getDefaultSchemaLocations();
		int index = 0;
		Source[] sources = new Source[defaultSchemaLocations.length + (customSchemaLocations != null ?customSchemaLocations.length:0)];
		for(String schemaLocation: defaultSchemaLocations){
			sources[index++] = new StreamSource(getClass().getResourceAsStream(schemaLocation));
		}
		if(customSchemaLocations != null) {
			for (String schemaLocation : customSchemaLocations) {
				sources[index++] = new StreamSource(getClass().getResourceAsStream(schemaLocation));
			}
		}

		return schemaFactory.newSchema(sources);
	}

	/**
	 * Method to validate a JAXB Object against  Schema.
	 */
	public void schemaValidate(Object message) throws MessageContentException {
		 try {
			schemaValidator.validate(new JAXBSource(getJAXBContext(),message));
		} catch (Exception e) {
			throw new MessageContentException("Error validating Assertion agains schema: " + e.getMessage(),e);
		}
	}

	/**
	 * Method to parses a generic SAML message and generates a JAXB structure.
	 *
	 *
	 * @param message the message data.
	 * @param requireSignature indicates if signature should exist and be valid.
	 * @return a parsed SAML message..
	 * @throws MessageContentException if response message data was invalid.
	 * @throws MessageProcessingException if internal problems occurred generated the message.
	 */
	public Object parseMessage(ContextMessageSecurityProvider.Context context, byte[] message, boolean requireSignature) throws MessageContentException, MessageProcessingException{

		try {
			if(requireSignature){
				xmlSigner.verifyEnvelopedSignature(context, message, getSignatureLocationFinder(), getOrganisationLookup());
			}
			return unmarshall(message);
		} catch (Exception e) {
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageContentException("Error parsing SAML Message Data: " + e.getMessage(),e);
		}
	}
	
	/**
	 * Method to generate a general SAMLP failure message.
	 * @param context message security related context.
	 * @param inResponseTo the ID of the attribute query
	 * @param statusCode the failure code to respond to
	 * @param failureMessage a descriptive failure message, may be null.
	 * @return a SAMLP failure message.
	 * @throws MessageContentException if parameters where invalid.
	 * @throws MessageProcessingException if internal problems occurred generated the message.
	 */
	public byte[] genFailureMessage(ContextMessageSecurityProvider.Context context,String inResponseTo, ResponseStatusCodes statusCode, String failureMessage) throws MessageContentException, MessageProcessingException{
		return genFailureMessage(context,inResponseTo,null,null,null,null,statusCode,failureMessage,false);
	}

	/**
	 * Method to generate a general SAMLP failure message.
	 *
	 * @param context message security related context.
	 * @param inResponseTo the ID of the request, null if message was unreadable
	 * @param issuer Identifies the entity that generated the response message. (Optional, null for no issuer)
	 * @param destination  A URI reference indicating the address to which this response has been sent. This is useful to prevent
	 *                        malicious forwarding of responses to unintended recipients, a protection that is required by some
	 *                        protocol bindings. If it is present, the actual recipient MUST check that the URI reference identifies the
	 *                        location at which the message was received. If it does not, the response MUST be discarded. Some
	 *                        protocol bindings may require the use of this attribute. (Optional, null for no destination)
	 * @param consent Indicates whether or not (and under what conditions) consent has been obtained from a principal in
	 *                   the sending of this response. See Section 8.4 for some URI references that MAY be used as the value
	 *                   of the Consent attribute and their associated descriptions. If no Consent value is provided, the
	 *                   identifier urn:oasis:names:tc:SAML:2.0:consent:unspecified (see Section 8.4.1) is in
	 *                   effect.
	 * @param extensions This extension point contains optional protocol message extension elements that are agreed on
	 *                      between the communicating parties. . No extension schema is required in order to make use of this
	 *                      extension point, and even if one is provided, the lax validation setting does not impose a requirement
	 *                      for the extension to be valid. SAML extension elements MUST be namespace-qualified in a non-SAML-defined namespace. (Optional, null for no extensions)
	 * @param statusCode the failure code to respond to (Required)
	 * @param failureMessage a descriptive failure message, may be null.
	 * @param signSAMLPResponse if the response should be signed.
	 * @return a SAMLP failure message.
	 * @throws MessageContentException if parameters where invalid.
	 * @throws MessageProcessingException if internal problems occurred generated the message.
	 */
	public byte[] genFailureMessage(ContextMessageSecurityProvider.Context context, String inResponseTo, NameIDType issuer, String destination, String consent, ExtensionsType extensions, ResponseStatusCodes statusCode, String failureMessage, boolean signSAMLPResponse) throws MessageContentException, MessageProcessingException{
		try{
			StatusCodeType statusCodeType = samlpOf.createStatusCodeType();
			statusCodeType.setValue(statusCode.getURIValue());

			StatusType statusType = samlpOf.createStatusType();
			statusType.setStatusCode(statusCodeType);

			if(failureMessage != null){
				statusType.setStatusMessage(failureMessage);
			}

			ResponseType responseType = samlpOf.createResponseType();
			responseType.setID("_" + MessageGenerateUtils.generateRandomUUID());
			responseType.setIssueInstant(MessageGenerateUtils.dateToXMLGregorianCalendarNoTimeZone(systemTime.getSystemTime()));
			responseType.setVersion(DEFAULT_SAML_VERSION);
			responseType.setInResponseTo(inResponseTo);
			responseType.setStatus(statusType);

			responseType.setIssuer(issuer);
			responseType.setDestination(destination);
			responseType.setConsent(consent);
			responseType.setExtensions(extensions);

			JAXBElement<ResponseType> response = samlpOf.createResponse(responseType);

			if(signSAMLPResponse){
				return marshallAndSignSAMLPOrAssertion(context,response,false,true);
			}

			return marshall(response);
		}catch(Exception e){
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageProcessingException("Error generation SAMLP Failure Message: " + e.getMessage(),e);
		}
	}



	/**
	 * Help method to get the first signing certificate from a digital signature.
	 * @param assertion to extract certificate from.
	 * @return the first found certificate in assertion.
	 * @throws MessageContentException if response message data was invalid.
	 * @throws MessageProcessingException if internal problems occurred generated the message.
	 */
	public X509Certificate getCertificateFromAssertion(JAXBElement<AssertionType> assertion) throws MessageContentException, MessageProcessingException{
		Iterator<Object> keyInfos = assertion.getValue().getSignature().getKeyInfo().getContent().iterator();
		while(keyInfos.hasNext()){
			Object next = keyInfos.next();
			if(next instanceof JAXBElement<?> && ((JAXBElement<?>) next).getValue() instanceof X509DataType){
			  Iterator<Object> x509Datas = ((X509DataType) ((JAXBElement<?>)next).getValue()).getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
			  while(x509Datas.hasNext()){
				  Object nextX509Data = x509Datas.next();
				  if(nextX509Data instanceof JAXBElement<?>){
					  JAXBElement<?> jaxbElement = (JAXBElement<?>) nextX509Data;
					  if(jaxbElement.getName().getLocalPart().equals("X509Certificate") && jaxbElement.getName().getNamespaceURI().equals("http://www.w3.org/2000/09/xmldsig#")){
						  try {
							return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream((byte[]) jaxbElement.getValue()));
						} catch (CertificateException e) {
							throw new MessageContentException("Error parsing certificate from digital signature: " + e.getMessage(),e);
						}
					  }
				  }
			  }
			}
		}
	
		throw new MessageContentException("Error parsing certificate from digital signature, no certificate found in KeyInfo data,");
	}
	
	/**
	 * Help method to extract a Assertion to be included in a CSMessasge from a response type
	 * 
	 * @param responseType the response type to extract from, never null.
	 * @return the first assertion type of null if no assertion was found.
	 */
	public JAXBElement<AssertionType> getAssertionFromResponseType(ResponseType responseType){
		if(responseType.getAssertionOrEncryptedAssertion().size() == 0){
			return null;
		}
		return of.createAssertion((AssertionType) responseType.getAssertionOrEncryptedAssertion().get(0));
	}

	/**
	 * Method to decrypt an assertion containing encrypted attributes.
	 *
	 * @param context message security related context.
	 * @param assertion the assertion to decrypt and parse
	 * @return an decrypted assertion
	 * @throws MessageContentException if content of message was invalid.
	 * @throws MessageProcessingException if internal problems occurred parsing the assertions.
	 * @throws NoDecryptionKeyFoundException if no key could be found decrypting the assertion.
	 */
	public JAXBElement<AssertionType> decryptAssertion(ContextMessageSecurityProvider.Context context, JAXBElement<AssertionType> assertion) throws MessageContentException, MessageProcessingException, NoDecryptionKeyFoundException{
		try {
			Document doc = getDocumentBuilder().newDocument();
			getMarshaller().marshal(assertion, doc);
			
			@SuppressWarnings("unchecked")
			JAXBElement<AssertionType> decryptedAssertion = (JAXBElement<AssertionType>) xmlEncrypter.decryptDocument(context, doc, encryptedAttributeXMLConverter);
			
			schemaValidate(decryptedAssertion);

			return decryptedAssertion;
		} catch (JAXBException e) {
			throw new MessageContentException("Error parsing assertion : " + e.getMessage(), e);
		}catch (SecurityException e) {
			throw new MessageProcessingException("Internal error parsing assertion: " + e.getMessage(),e);
		}
	}


	
	
	/**
	 * Method that verifies the notBefore and notOnOrAfter conditions, all other conditions set in an assertion
	 * is ignored.
	 * @param assertionType the assertion to verify
	 * @param conditionLookup implementation to check a specific set of conditions.
	 * @throws MessageContentException if conditions wasn't met.
	 */
	public void verifyAssertionConditions(AssertionType assertionType, ConditionLookup conditionLookup) throws MessageContentException {
		try{
			ConditionsType conditionsType = assertionType.getConditions();
			if(conditionsType != null){
				verifyConditions(conditionsType, "Assertion", assertionType.getID(),conditionLookup);
			}

		}catch(Exception e){
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			throw new MessageContentException("Error verifying conditions on assertion ticket: " + e.getMessage(),e);
		}
		
	}

	public void verifyConditions(ConditionsType conditions, String type, String messageId, ConditionLookup conditionLookup) throws MessageContentException {
		try{
			long clockSkew = conditionLookup.acceptedClockSkew();
			Date currentTime = systemTime.getSystemTime();

			Date notBeforeOptional = MessageGenerateUtils.xMLGregorianCalendarToDate(conditions.getNotBefore());
			if(notBeforeOptional != null) {
				Date notBefore = new Date(notBeforeOptional.getTime() - clockSkew);
				if(notBefore.after(currentTime)){
					throw new MessageContentException("Error " + type + " not yet valid, not valid until: " + notBefore);
				}
			}

			Date notOnOrAfterOptional = MessageGenerateUtils.xMLGregorianCalendarToDate(conditions.getNotOnOrAfter());
			if(notOnOrAfterOptional != null) {
				Date notOnOrAfter = new Date(notOnOrAfterOptional.getTime() + clockSkew);
				if(notOnOrAfter.before(currentTime) || notOnOrAfter.equals(currentTime)){
					throw new MessageContentException("Error " + type + " has expired on: " + notOnOrAfter);
				}
			}

			for(ConditionAbstractType cat : conditions.getConditionOrAudienceRestrictionOrOneTimeUse()){
				if(cat instanceof OneTimeUseType){
					if(conditionLookup.usedBefore(messageId)){
						throw new MessageContentException("Error " + type + " has been used before and contains OneTime condition");
					};

				}
				if(cat instanceof AudienceRestrictionType){
					AudienceRestrictionType art = (AudienceRestrictionType) cat;
					String thisAudienceId = conditionLookup.getThisAudienceId();
					boolean foundMatch = false;
					for(String audience : art.getAudience()){
						if(audience.equals(thisAudienceId)){
							foundMatch = true;
							break;
						}
					}
					if(!foundMatch){
						throw new MessageContentException("Error " + type + " not did not fullfill audience restriction condition");
					}
				}

			}


		}catch(Exception e){
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			throw new MessageContentException("Error verifying conditions on assertion ticket: " + e.getMessage(),e);
		}
	}



	/**
	 * Generates a simple basic SAMLP response containing one unencrypted assertion.
	 * @param inResponseTo the request id.
	 * @param assertion the unencrypted assertion to add to teh response.
	 * @return a successful SAMLPResponse.
	 * @throws MessageProcessingException if internal problems occurred generating the message.
     */
	public JAXBElement<ResponseType> genSuccessfulSAMLPResponse(String inResponseTo, JAXBElement<AssertionType> assertion) throws MessageProcessingException{
		StatusCodeType statusCodeType = samlpOf.createStatusCodeType();
		statusCodeType.setValue(ResponseStatusCodes.SUCCESS.getURIValue());
		
		StatusType statusType = samlpOf.createStatusType();
		statusType.setStatusCode(statusCodeType);
		
		ResponseType responseType = samlpOf.createResponseType();
		responseType.setID("_" + MessageGenerateUtils.generateRandomUUID());
		responseType.setIssueInstant(MessageGenerateUtils.dateToXMLGregorianCalendarNoTimeZone(systemTime.getSystemTime()));
		responseType.setVersion(DEFAULT_SAML_VERSION);
		responseType.setInResponseTo(inResponseTo);
		
		responseType.setStatus(statusType);
		responseType.getAssertionOrEncryptedAssertion().add(assertion.getValue());
		
		return samlpOf.createResponse(responseType);
	}


	private JAXBContext jaxbContext = null;
	/**
	 * Help method maintaining the JAXB Context.
	 */
	protected JAXBContext getJAXBContext() throws JAXBException{
		if(jaxbContext== null){
			jaxbContext = JAXBContext.newInstance(getJAXBPackages() + (customJAXBClasspath == null ? "" : ":" + customJAXBClasspath));

		}
		return jaxbContext;
	}
	
	
	/**
	 * Help method to marshall a message without signing it.
	 * @param message the message to marshall into a XML byte array.
	 * @return the marshalled byte array 
	 * @throws MessageProcessingException if problem occurred marshalling the message.
	 */
	public byte[] marshall(Object message) throws MessageProcessingException{
		try{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		getMarshaller().marshal(message, baos);
		return baos.toByteArray();
		}catch(Exception e){
			throw new MessageProcessingException("Error occurred marshalling object: " + CSMessageUtils.getMarshallingExceptionMessage(e),e );
		}
	}

	protected Object unmarshall(byte[] message) throws MessageProcessingException, MessageContentException{
		try {
			Object object = getUnmarshaller().unmarshal(new ByteArrayInputStream(message));
			if (object instanceof JAXBElement) {
				return ((JAXBElement<?>) object).getValue();
			}
			return object;
		}catch(SAXException e){

			throw new MessageContentException("Error occurred during SAML unmarshaller: " + CSMessageUtils.getMarshallingExceptionMessage(e),e);
		}catch(JAXBException e){
			throw new MessageContentException("Error occurred during SAML unmarshaller: " + CSMessageUtils.getMarshallingExceptionMessage(e),e);
		}

	}



	/**
	 * Help method to marshall and sign an JAXB data that is supported by the parser implementation.
	 *
	 * Method that generates the signature and marshalls the message to byte array in UTF-8 format.
	 * @param message to sign and marshall.
	 * @return a marshalled and signed message.
	 * @throws MessageProcessingException if problems occurred when processing the message.
	 * @throws MessageContentException if unsupported version is detected in message.
	 */
	public byte[] marshallAndSign(ContextMessageSecurityProvider.Context context,Object message) throws MessageProcessingException, MessageContentException{
		if(message == null){
			throw new MessageProcessingException("Error marshalling assertion, message cannot be null.");
		}
		Document doc = getDocumentBuilder().newDocument();
		try {
			getMarshaller().marshal(message, doc);
		} catch (JAXBException e) {
			throw new MessageProcessingException("Error marshalling message " + e.getMessage(), e);
		}

        xmlSigner.sign(context,doc, getSignatureLocationFinder());

		return xmlSigner.marshallDoc(doc);
	}

	/**
	 * Help method to marshall a Doc into byte array, generates no signature just converts.
	 *
	 * @param doc Document to marshall into byte array
	 * @return a byte array representation of the doc
	 * @throws MessageProcessingException if internal problems occurred when processing the message.
	 * @throws MessageContentException if message was malformed.
	 */
	public byte[] marshallDoc(Document doc) throws MessageProcessingException, MessageContentException{
		return xmlSigner.marshallDoc(doc);
	}

	/**
	 * Method to convert a message to a Document
	 * @param message the bytearray xml message to convert to Document.
	 * @return the Document object.
	 * @throws MessageContentException if message was malformed.
	 */
	public Document unmarshallDoc(byte[] message) throws MessageContentException, MessageProcessingException{
		try{
			return getDocumentBuilder().parse(new ByteArrayInputStream(message));
		}catch(Exception e){
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageContentException("Error converting message into Document: " + e.getMessage(),e);
		}
	}
	
	/**
	 * Help method to marshall and sign an Assertion, either standalone or inside a SAMLP Response
	 * 
	 * Method that generates the signature and marshalls the message to byte array in UTF-8 format.
	 * @param context the message security context to use.
	 * @param message a Assertion or Response (SAMLP) structure.
	 * @return a marshalled and signed message.
	 * @throws MessageProcessingException if problems occurred when processing the message.
	 * @throws MessageContentException if unsupported version is detected in message.
	 */
	protected byte[] marshallAndSignSAMLPOrAssertion(ContextMessageSecurityProvider.Context context,JAXBElement<?> message, boolean signAssertion, boolean signSAMLP) throws MessageProcessingException, MessageContentException{
		if(message == null){
			throw new MessageProcessingException("Error marshalling assertion, message cannot be null.");
		}
		Document doc = getDocumentBuilder().newDocument();
		try {
			getMarshaller().marshal(message, doc);
		} catch (JAXBException e) {
			throw new MessageProcessingException("Error marshalling message " + e.getMessage(), e);
		}


		if(signAssertion) {

			xmlSigner.sign(context,doc,  assertionSignatureLocationFinder);
		}
		if(signSAMLP){

			xmlSigner.sign(context,doc, samlpSignatureLocationFinder);
		}
		return xmlSigner.marshallDoc(doc);
	}


	

	protected DocumentBuilder getDocumentBuilder() throws MessageProcessingException {
		try {
			return XMLUtils.createSecureDocumentBuilderFactory().newDocumentBuilder();
		}catch(ParserConfigurationException e){
			throw new MessageProcessingException("Internal error creating Documentbuilder, ParserConfigurationException: " + e.getMessage());
		}
	}
	
	protected Marshaller getMarshaller() throws JAXBException{
		Marshaller marshaller = getJAXBContext().createMarshaller();
		marshaller.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
		return marshaller;
	}
	
	protected Unmarshaller getUnmarshaller() throws JAXBException, SAXException{
		Unmarshaller unmarshaller = getJAXBContext().createUnmarshaller();
		unmarshaller.setSchema(getSchema());
		return unmarshaller;
	}

    /**
     * Converter that replaces all decrypted EncryptedAttributes with Attributes
     */
    public static class EncryptedAttributeXMLConverter implements DecryptedXMLConverter{
		public Document convert(Document doc) throws MessageContentException {
			NodeList nodeList = doc.getElementsByTagNameNS(BaseSAMLMessageParser.ASSERTION_NAMESPACE, "Attribute");
			for(int i =0; i < nodeList.getLength(); i++){
				Element attribute= (Element) nodeList.item(i);
				Element parent = (Element) attribute.getParentNode();
				if(parent.getLocalName().equals("EncryptedAttribute") && parent.getNamespaceURI().equals(BaseSAMLMessageParser.ASSERTION_NAMESPACE)){
					parent.getParentNode().replaceChild(attribute, parent);
				}
				
			}

			return doc;
		}
	}

    public static class AssertionSignatureLocationFinder implements SignatureLocationFinder{
		public Element[] getSignatureLocations(Document doc)
				throws MessageContentException {
			try{
				if(doc.getDocumentElement().getLocalName().equals("Assertion")){
					return new Element[] {doc.getDocumentElement()};
				}
				if(doc.getDocumentElement().getLocalName().equals("Response")){
					NodeList nl  = doc.getElementsByTagNameNS(ASSERTION_NAMESPACE, "Assertion");
					if(nl.getLength() == 0){
						throw new MessageContentException("No assertion was found in response.");
					}
					Element[] result = new Element[nl.getLength()];
					for(int i = 0; i < result.length; i++){
						result[i] = (Element) nl.item(i);
					}
					return result;
				}
			}catch(Exception e){
			}
			throw new MessageContentException("Invalid assertion message type sent for signature.");
		}

		@Override
		public String getIDAttribute() {
			return "ID";
		}

		@Override
		public String getIDValue(Element signedElement) throws MessageContentException {
			return signedElement.getAttribute(getIDAttribute());
		}

		@Override
		public List<QName> getSiblingsBeforeSignature(Element element) throws MessageContentException {
			List<QName> beforeSiblings = new ArrayList<QName>();
			beforeSiblings.add(new QName(ASSERTION_NAMESPACE, "Subject"));
			beforeSiblings.add(new QName(ASSERTION_NAMESPACE, "Conditions"));
			beforeSiblings.add(new QName(ASSERTION_NAMESPACE, "Advice"));
			beforeSiblings.add(new QName(ASSERTION_NAMESPACE, "Statement"));
			beforeSiblings.add(new QName(ASSERTION_NAMESPACE, "AuthnStatement"));
			beforeSiblings.add(new QName(ASSERTION_NAMESPACE, "AuthzDecisionStatement"));
			beforeSiblings.add(new QName(ASSERTION_NAMESPACE, "AttributeStatement"));
			return beforeSiblings;
		}

	}

	public static class SAMLPSignatureLocationFinder implements SignatureLocationFinder{


		public Element[] getSignatureLocations(Document doc)
				throws MessageContentException {
			try{
				if(doc.getDocumentElement().getNamespaceURI().equals(PROTOCOL_NAMESPACE)){
					return new Element[] {doc.getDocumentElement()};
				}
			}catch(Exception e){
			}
			throw new MessageContentException("Invalid SAMLP message type sent for signature.");
		}

		@Override
		public String getIDAttribute() {
			return "ID";
		}

		@Override
		public String getIDValue(Element signedElement) throws MessageContentException {
			return signedElement.getAttribute(getIDAttribute());
		}

		@Override
		public List<QName> getSiblingsBeforeSignature(Element element) throws MessageContentException {
			List<QName> beforeSiblings = new ArrayList<QName>();
			beforeSiblings.add(new QName(PROTOCOL_NAMESPACE, "Extensions"));
			beforeSiblings.add(new QName(PROTOCOL_NAMESPACE, "Status"));
			return beforeSiblings;
		}

	}
    
    protected class BaseLSResourceResolver implements  LSResourceResolver {

		private SAMLParserCustomisations customizations;

		public BaseLSResourceResolver(SAMLParserCustomisations customizations){
			this.customizations = customizations;
		}

		public LSInput resolveResource(String type, String namespaceURI,
				String publicId, String systemId, String baseURI) {
			try {
				if(systemId != null && systemId.equals("http://www.w3.org/2001/XMLSchema.dtd")){
					return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream("/XMLSchema.dtd"));
				}
				if(systemId != null && systemId.equals("datatypes.dtd")){
					return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream("/datatypes.dtd"));
				}

				String retval = null;
				if(customizations != null) {
					retval = customizations.lookupSchemaForElement(type, namespaceURI, publicId, systemId, baseURI);
				}
				if(retval == null){
					retval = lookupSchemaForElement(type, namespaceURI, publicId, systemId, baseURI);
				}
				if(retval != null) {
					return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream(retval));
				}

			} catch (MessageProcessingException e) {
				throw new IllegalStateException("Error couldn't read XSD from class path: " + e.getMessage(), e);
			}
			return null;
		}
	}



	/**
	 * Class used to verify certain conditions such as OneTime
	 */
	public interface ConditionLookup {

		/**
		 * Method to check if a given assertionId have been used before, used for verifying the OneTime condition.
		 * @param messageId the assertion ID to lookup
         * @return true if this ID has been used before.
		 * @throws MessageContentException if this system doesn't support the OneTime condition.
		 * @throws MessageProcessingException if internal problems occurred.
         */
		boolean usedBefore(String messageId) throws MessageContentException, MessageProcessingException;

		/**
		 * Method to get this systems audience id, that should be matched against available
		 * audience conditions.
		 * @throws MessageContentException if this system doesn't support the audience restriction condition.
		 * @return this systems audience id, that should be matched against available
		 * audience conditions.
		 * @throws MessageContentException if this system doesn't support the Audience condition.
		 * @throws MessageProcessingException  if internal problems occurred.
         */
		String getThisAudienceId() throws MessageContentException, MessageProcessingException;

		/**
		 * Method that should return the acceptable clock skew in milliseconds when checking
		 * the not before and not after conditions
		 * @return the accepted clock skew in milliseconds
		 * @throws MessageProcessingException  if internal problems occurred.
		 */
		long acceptedClockSkew() throws MessageProcessingException;

	}

	/**
	 * Simple Condition lookup that doesn't support the OneTime or AudienceRestriction Conditions
	 * but throws MessageContentException if they exists.
	 */
	public static class SimpleConditionLookup implements BaseSAMLMessageParser.ConditionLookup {

		long clockSkew = 0L;
		public SimpleConditionLookup(){}

		public SimpleConditionLookup(long clockSkew){
			this.clockSkew = clockSkew;
		}

		@Override
		public boolean usedBefore(String messageId) throws MessageContentException, MessageProcessingException {
			throw new MessageContentException("OneTime Condition is not supported.");
		}

		@Override
		public String getThisAudienceId() throws MessageContentException, MessageProcessingException {
			throw new MessageContentException("AudienceRestriction Condition is not supported.");
		}

		@Override
		public long acceptedClockSkew() throws MessageProcessingException {
			return clockSkew;
		}
	}



}
