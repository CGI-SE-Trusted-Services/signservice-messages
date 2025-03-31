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
package org.signatureservice.messages.csmessages;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.xml.XMLConstants;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.JAXBIntrospector;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;
import jakarta.xml.bind.util.JAXBSource;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.Init;
import org.signatureservice.messages.ContextMessageSecurityProvider;
import org.signatureservice.messages.MessageContentException;
import org.signatureservice.messages.MessageProcessingException;
import org.signatureservice.messages.MessageSecurityProvider;
import org.signatureservice.messages.assertion.AssertionPayloadParser;
import org.signatureservice.messages.csmessages.PayloadParserRegistry.ConfigurationCallback;
import org.signatureservice.messages.csmessages.jaxb.ApprovalStatus;
import org.signatureservice.messages.csmessages.jaxb.Assertions;
import org.signatureservice.messages.csmessages.jaxb.CSMessage;
import org.signatureservice.messages.csmessages.jaxb.CSRequest;
import org.signatureservice.messages.csmessages.jaxb.CSResponse;
import org.signatureservice.messages.csmessages.jaxb.Credential;
import org.signatureservice.messages.csmessages.jaxb.GetApprovalRequest;
import org.signatureservice.messages.csmessages.jaxb.IsApprovedRequest;
import org.signatureservice.messages.csmessages.jaxb.IsApprovedResponseType;
import org.signatureservice.messages.csmessages.jaxb.PingRequest;
import org.signatureservice.messages.csmessages.jaxb.PingResponse;
import org.signatureservice.messages.csmessages.jaxb.ObjectFactory;
import org.signatureservice.messages.csmessages.jaxb.Originator;
import org.signatureservice.messages.csmessages.jaxb.Payload;
import org.signatureservice.messages.csmessages.jaxb.RequestStatus;
import org.signatureservice.messages.utils.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

/**
 * 
 * Default implementation of CS Message Parser.
 * 
 * @author Philip Vendil
 *
 */
public class DefaultCSMessageParser implements CSMessageParser {

	public static final String SETTING_SOURCEID = "csmessage.sourceid";
	public static final String OLD_SETTING_SOURCEID = "pkimessage.sourceid";
	
	public static final String SETTING_SIGN = "csmessage.sign";
	public static final String OLD_SETTING_SIGN = "pkimessage.sign";
	
	public static final String SETTING_REQUIRESIGNATURE = "csmessage.requiresignature";
	public static final String OLD_SETTING_REQUIRESIGNATURE = "pkimessage.requiresignature";
	
	public static final String SETTING_MESSAGE_NAME_CATALOGUE_IMPL = "csmessage.messagenamecatalogue.impl";
	public static final String OLD_SETTING_MESSAGE_NAME_CATALOGUE_IMPL = "pkimessage.messagenamecatalogue.impl";
	public static final String DEFAULT_MESSAGE_NAME_CATALOGUE_IMPL = DefaultMessageNameCatalogue.class.getName();

	public static final String CSMESSAGE_NAMESPACE = "http://certificateservices.org/xsd/csmessages2_0";
	
	private static final String CSMESSAGE_VERSION_2_0 = "2.0";
	private static final String CSMESSAGE_VERSION_2_1 = "2.1";
	private static final String CSMESSAGE_VERSION_2_2 = "2.2";
	private static final String CSMESSAGE_VERSION_2_3 = "2.3";
	
	public static final String CSMESSAGE_XSD_SCHEMA_2_0_RESOURCE_LOCATION = "/csmessages_schema2_0.xsd";
	public static final String CSMESSAGE_XSD_SCHEMA_2_1_RESOURCE_LOCATION = "/csmessages_schema2_1.xsd";
	public static final String CSMESSAGE_XSD_SCHEMA_2_2_RESOURCE_LOCATION = "/csmessages_schema2_2.xsd";
	public static final String CSMESSAGE_XSD_SCHEMA_2_3_RESOURCE_LOCATION = "/csmessages_schema2_3.xsd";

	private static final String CSMESSAGE_XSD_SCHEMA_2_0_URI = "http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd";

	private static final Map<String,String> csMessageSchemaMap = new HashMap<String,String>();
	static{
		csMessageSchemaMap.put(CSMESSAGE_VERSION_2_0, CSMESSAGE_XSD_SCHEMA_2_0_RESOURCE_LOCATION);
		csMessageSchemaMap.put(CSMESSAGE_VERSION_2_1, CSMESSAGE_XSD_SCHEMA_2_1_RESOURCE_LOCATION);
		csMessageSchemaMap.put(CSMESSAGE_VERSION_2_2, CSMESSAGE_XSD_SCHEMA_2_2_RESOURCE_LOCATION);
		csMessageSchemaMap.put(CSMESSAGE_VERSION_2_3, CSMESSAGE_XSD_SCHEMA_2_3_RESOURCE_LOCATION);
	}
	
	private static final Map<String,String> csMessageSchemaUriMap = new HashMap<String,String>();
	static{
		csMessageSchemaUriMap.put(CSMESSAGE_VERSION_2_0, CSMESSAGE_XSD_SCHEMA_2_0_URI);
		csMessageSchemaUriMap.put(CSMESSAGE_VERSION_2_1, CSMESSAGE_XSD_SCHEMA_2_0_URI);
		csMessageSchemaUriMap.put(CSMESSAGE_VERSION_2_2, CSMESSAGE_XSD_SCHEMA_2_0_URI);
		csMessageSchemaUriMap.put(CSMESSAGE_VERSION_2_3, CSMESSAGE_XSD_SCHEMA_2_0_URI);
	}
	
	public static final String XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION = "/xmldsig-core-schema.xsd";
	public static final String XMLENC_XSD_SCHEMA_RESOURCE_LOCATION = "/xenc-schema.xsd";
	
	public static final String XMLDSIG_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#";
	public static final String XMLENC_NAMESPACE = "http://www.w3.org/2001/04/xmlenc#";
	
	private static final String[] SUPPORTED_CSMESSAGE_VERSIONS = {CSMESSAGE_VERSION_2_0,CSMESSAGE_VERSION_2_1,CSMESSAGE_VERSION_2_2,CSMESSAGE_VERSION_2_3};
	
	private ObjectFactory objectFactory = new ObjectFactory();
	
	private Properties properties = null;
	private MessageSecurityProvider securityProvider = null;
	private MessageNameCatalogue messageNameCatalogue = null;
	private JAXBRelatedData jaxbData = new JAXBRelatedData();
	private SystemTime systemTime = new DefaultSystemTime();
	
	private String sourceId = null;
	private XMLSigner xmlSigner;

	public static final String DEFAULT_CSMESSAGE_PROTOCOL = CSMESSAGE_VERSION_2_3;

	private static String csMessageVersion = DEFAULT_CSMESSAGE_PROTOCOL;

	private CSMessageSignatureLocationFinder cSMessageSignatureLocationFinder = new CSMessageSignatureLocationFinder();
	/**
	 * @see CSMessageParser#init(MessageSecurityProvider, java.util.Properties)
	 */
	public void init(final MessageSecurityProvider securityProvider, Properties config)
			throws MessageProcessingException {
		this.properties = config;
		this.securityProvider = securityProvider;
		this.messageNameCatalogue = getMessageNameCatalogue(config);
		
		Init.init();
		
		// Register
		final CSMessageParser thisParser = this;
		PayloadParserRegistry.configure(new ConfigurationCallback() {
			
		
			public void updateContext() throws MessageProcessingException {
				jaxbData.clearAllJAXBData();
			}
			
			/**
			 * There is never any need for reinitialization since auto reloading of current version
			 * of CSMessageParser isn't supported.
			 */
			public boolean needReinitialization(String namespace)
					throws MessageProcessingException {
				return false;
			}
			
			/**
			 * Initialize the pay load parser with same configuration.
			 */
			public void configurePayloadParser(String namespace,
					PayloadParser payloadParser) throws MessageProcessingException {
				payloadParser.init(properties, securityProvider);
				
			}
		}, true);
		
		
		// Initialize all PayloadParsers
		try {
			jaxbData.getJAXBContext();
		} catch (JAXBException e) {
			throw new MessageProcessingException("Error occurred initializing JAXBContext: " + e.getMessage(),e);
		}

        // Initialize all marshallers for all supported version.
		for(String version : SUPPORTED_CSMESSAGE_VERSIONS){
			try{
				jaxbData.getCSMessageMarshaller(version);
				jaxbData.getCSMessageUnmarshaller(version);
			}catch(MessageContentException e){
				throw new MessageProcessingException("Unsupported CS Message version: " + version + " detected");
			}
		}

		sourceId = SettingsUtils.getProperty(config, SETTING_SOURCEID, OLD_SETTING_SOURCEID);
		if(sourceId == null || sourceId.trim().equals("")){
			throw new MessageProcessingException("Error setting " + SETTING_SOURCEID + " must be set.");
		}
		
		try {
			xmlSigner = new XMLSigner(securityProvider, signMessages(),
				cSMessageSignatureLocationFinder,new CSMessageOrganisationLookup());
		} catch (Exception e) {
			throw new MessageProcessingException("Error initizalizing XML Signer " + e.getMessage(),e);
		}
	}

	/**
	 * @see CSMessageParser#parseMessage(byte[])
	 */
	public synchronized CSMessage parseMessage(byte[] messageData)
			throws MessageContentException, MessageProcessingException {
		return parseMessage(messageData,true, true);
	}

	/**
	 * @see CSMessageParser#parseMessage(byte[], boolean)
	 */
	public synchronized CSMessage parseMessage(byte[] messageData, boolean performValidation)
			throws MessageContentException, MessageProcessingException {
		return parseMessage(messageData,performValidation,true);
		
	}

	/**
	 * @see CSMessageParser#parseMessage(byte[], boolean, boolean)
	 */
	public synchronized CSMessage parseMessage(byte[] messageData, boolean performValidation, boolean requireSignature)
			throws MessageContentException, MessageProcessingException {
		try{
			Document doc = getDocumentBuilder().parse(new ByteArrayInputStream(messageData));

			return parseMessage(doc,performValidation, requireSignature);
		} catch (SAXException e) {
			throw new MessageContentException("Error parsing CS Message: " + CSMessageUtils.getMarshallingExceptionMessage(e),e);
		} catch (IOException e) {
			throw new MessageContentException("Error parsing CS Message: " + CSMessageUtils.getMarshallingExceptionMessage(e),e);
		} catch (ParserConfigurationException e) {
			throw new MessageContentException("Error parsing CS Message: " + CSMessageUtils.getMarshallingExceptionMessage(e),e);
		}
	}

	/**
	 * @see CSMessageParser#parseMessage(Document, boolean)
	 */
	public synchronized CSMessage parseMessage(Document doc, boolean performValidation) throws MessageContentException,
			MessageProcessingException {
		return parseMessage(doc,performValidation, true);
	}

	/**
	 * @see CSMessageParser#parseMessage(Document, boolean, boolean)
	 */
	public synchronized CSMessage parseMessage(Document doc, boolean performValidation, boolean requireSignature) throws MessageContentException,
			MessageProcessingException {
		try{
			CSMessageVersion version = getVersionFromMessage(doc);
			verifyCSMessageVersion(version.getMessageVersion());
		
			Object object = jaxbData.getCSMessageUnmarshaller(version.getMessageVersion()).unmarshal(doc);
			validateCSMessage(version, object, doc, performValidation, requireSignature);
			return (CSMessage) object;
		}catch(JAXBException e){
			throw new MessageContentException("Error parsing CS Message: " + CSMessageUtils.getMarshallingExceptionMessage(e),e);
		} 
	}

	/**
	 * @see CSMessageParser#parseMessage(Document)
	 */
	public synchronized CSMessage parseMessage(Document doc) throws MessageContentException,
			MessageProcessingException {
		return parseMessage(doc,true, true);
	}

	

	/**
	 * @see CSMessageParser#generateCSRequestMessage(String, String, String, String, Object, List)
	 * 
	 */
	public byte[] generateCSRequestMessage(String requestId, String destinationId, String organisation, String payLoadVersion, Object payload, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		return generateCSRequestMessage(requestId, destinationId, organisation, payLoadVersion, payload, null, assertions);
	}

	/**
	 * @see CSMessageParser#generateCSRequestMessage(String, String, String, String, Object, Credential, List)
	 * 
	 */
	public byte[] generateCSRequestMessage(String requestId, String destinationId, String organisation, String payLoadVersion, Object payload, Credential originator, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		CSMessage message = genCSMessage(csMessageVersion, payLoadVersion,null, requestId, destinationId, organisation, originator, payload,  assertions);
		return marshallAndSignCSMessage( message);
	}

	/**
	 * @see CSMessageParser#generateCSResponseMessage(String, CSMessage, String, Object)
	 * 
	 */
	public CSMessageResponseData generateCSResponseMessage(String relatedEndEntity, CSMessage request, String payLoadVersion, Object payload) throws MessageContentException, MessageProcessingException{
		return generateCSResponseMessage(relatedEndEntity, request, payLoadVersion, payload, false);
	}
	

	/**
	 * @see CSMessageParser#generateCSResponseMessage(String, CSMessage, String, Object)
	 * 
	 */
	public CSMessageResponseData generateCSResponseMessage(String relatedEndEntity, CSMessage request, String payLoadVersion, Object payload, boolean isForwardableResponse) throws MessageContentException, MessageProcessingException{
		populateSuccessfulResponse(payload, request);
		CSMessage message = genCSMessage(request.getVersion(), payLoadVersion, request.getName(), null, request.getSourceId(), request.getOrganisation(),  getOriginatorFromRequest(request), payload,  null);
		byte[] responseData = marshallAndSignCSMessage( message);
		return new CSMessageResponseData(message, relatedEndEntity, responseData, isForwardableResponse);
	}

	/**
	 * @see CSMessageParser#generateGetApprovalRequest(String, String, String, byte[], Credential, List)
	 * 
	 */
	public byte[] generateGetApprovalRequest(String requestId, String destinationId, String organisation, byte[] request, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		CSMessage csMessage = parseMessage(request);
		CSRequest requestPayload = null;
		try{
			requestPayload = (CSRequest) csMessage.getPayload().getAny();
		}catch(Exception e){
			throw new MessageContentException("Error in request message, request didn't contain CSRequest in payload.");
		}
		GetApprovalRequest payload = objectFactory.createGetApprovalRequest();
		Payload requestedPayload = objectFactory.createPayload();
		requestedPayload.setAny(requestPayload);
		payload.setRequestPayload(requestedPayload);
		
		return generateCSRequestMessage(requestId, destinationId, organisation, csMessage.getPayLoadVersion(), payload, originator, assertions);
	}
	
	/**
	 * @see CSMessageParser#generateIsApprovedRequest(String, String, String, String, Credential, List)
	 * 
	 */
	public byte[] generateIsApprovedRequest(String requestId, String destinationId, String organisation, String approvalId, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		IsApprovedRequest payload = objectFactory.createIsApprovedRequest();
		payload.setApprovalId(approvalId);
		
		return generateCSRequestMessage(requestId, destinationId, organisation, csMessageVersion, payload, originator, assertions);
	}
	
	/**
	 * @see CSMessageParser#generateIsApprovedResponse(String, CSMessage, ApprovalStatus, List)
	 * 
	 */
	public CSMessageResponseData generateIsApprovedResponse(String relatedEndEntity, CSMessage request, ApprovalStatus approvalStatus, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		IsApprovedResponseType responseType = objectFactory.createIsApprovedResponseType();
		if(request.getPayload().getAny() instanceof IsApprovedRequest){
			responseType.setApprovalId(((IsApprovedRequest) request.getPayload().getAny()).getApprovalId());
		}else{
			throw new MessageContentException("Error generating IsApprovedResponse, no IsApprovedRequest found in request payload");
		}
		responseType.setApprovalStatus(approvalStatus);
		if(assertions != null && assertions.size() > 0){
			Assertions a = objectFactory.createAssertions();
			for(Object assertion : assertions){
			  a.getAny().add(assertion);
			}
			responseType.getAssertions().add(a);
		}
		
		return generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), objectFactory.createIsApprovedResponse(responseType));
	}
	
	/**
	 * @see CSMessageParser#generateGetApprovalResponse(String, CSMessage, String, ApprovalStatus, List)
	 */
	public CSMessageResponseData generateGetApprovalResponse(String relatedEndEntity, CSMessage request, String approvalId, ApprovalStatus approvalStatus, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		IsApprovedResponseType responseType = objectFactory.createIsApprovedResponseType();
		responseType.setApprovalId(approvalId);
		responseType.setApprovalStatus(approvalStatus);

		if(assertions != null && assertions.size() > 0){
			Assertions a = objectFactory.createAssertions();
			for(Object assertion : assertions){
			  a.getAny().add(assertion);
			}
			responseType.getAssertions().add(a);
		}
		
		
		return generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), objectFactory.createGetApprovalResponse(responseType));
	}

	/**
	 * @see CSMessageParser#generatePingRequest(String, String, String, Credential, List)
	 */
	public byte[] generatePingRequest(String requestId, String destinationId, String organisation, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException {
		return generateCSRequestMessage(requestId, destinationId, organisation, csMessageVersion, new PingRequest(), originator, assertions);
	}

	/**
	 * @see CSMessageParser#generatePingResponse(CSMessage,List)
	 */
	public CSMessageResponseData generatePingResponse(CSMessage request, List<Object> assertions) throws MessageContentException, MessageProcessingException {
		return generateCSResponseMessage(null, request, request.getPayLoadVersion(), new PingResponse());
	}

	/**
	 * @see CSMessageParser#genCSFailureResponse(String, byte[], RequestStatus, String, String, Credential)
	 */
	public CSMessageResponseData genCSFailureResponse(String relatedEndEntity,byte[] request, RequestStatus status,
			String failureMessage, String destinationID, Credential originator) throws MessageContentException,
			MessageProcessingException {
		try {
			Document doc = getDocumentBuilder().parse(new ByteArrayInputStream(request));
			
    		Node pkiMessageNode = doc.getFirstChild();
    		String version=null;
    		if(pkiMessageNode != null){
    			Node versionNode = pkiMessageNode.getAttributes().getNamedItem("version");
    			if(versionNode != null){
    				version = versionNode.getNodeValue();
    			}
    		}  
    		if(version == null || version.trim().equals("")){
    			throw new MessageContentException("Error unsupported protocol version when generating CSResponse, version: " + version);
    		}

			XPathFactory factory = XPathFactory.newInstance();
			XPath xpath = factory.newXPath();
			if(destinationID == null){
				XPathExpression expr = xpath.compile("//*[local-name()='sourceId']/text()");
				String result = (String) expr.evaluate(doc, XPathConstants.STRING);
				if(result != null){
				  destinationID = result;
				}
			}

			XPathExpression expr = xpath.compile("//*[local-name()='CSMessage']/@ID");
			Object result = expr.evaluate(doc, XPathConstants.STRING);			   
			String responseToRequestID = (String) result;

			expr = xpath.compile("//*[local-name()='organisation']/text()");
			result = expr.evaluate(doc, XPathConstants.STRING);;
			String organisation = (String) result;
			
			expr = xpath.compile("//*[local-name()='name']/text()");
			result = expr.evaluate(doc, XPathConstants.STRING);;
			String requestName = (String) result;
			
			if(organisation == null || responseToRequestID == null || destinationID == null || requestName==null){
				throw new MessageContentException("Error generating CS Message Response from request, due to missing fields organisation, sourceId, name or ID in request.");
			}
			
			CSResponse csResponse = objectFactory.createCSResponse();
			csResponse.setStatus(status);
			csResponse.setFailureMessage(failureMessage);
			csResponse.setInResponseTo(responseToRequestID);

			CSMessage csMessage = genCSMessage(version,version,requestName, null,destinationID, organisation, originator, objectFactory.createFailureResponse(csResponse), null);

			byte[] responseData = marshallAndSignCSMessage(csMessage);
			return new CSMessageResponseData(csMessage, relatedEndEntity, responseData, false );
		} catch (ParserConfigurationException e) {
			throw new MessageProcessingException("Error configuring the XML SAX Parser : " + e.getMessage());
		} catch (SAXException e) {
			throw new MessageContentException("Error parsing request XML message: " + e.getMessage());
		} catch (IOException e) {
			throw new MessageProcessingException("Error reading the XML request data : " + e.getMessage());
		} catch (XPathExpressionException e) {
			throw new MessageProcessingException("Error constructing XPath expression when generating PKI Message responses : " + e.getMessage());
		}
	}
	

	/**
	 * @see CSMessageParser#getSigningCertificate(byte[])
	 */	
	public X509Certificate getSigningCertificate(byte[] request)
			throws MessageContentException, MessageProcessingException {
		X509Certificate retval = null;
		if(requireSignature()){
				retval = xmlSigner.findSignerCertificate(request);		
		}
		return retval;
	}
	
	/**
	 * @see CSMessageParser#genCSMessage(String, String, String, String, String, String, Credential, Object, List)
	 */
	public CSMessage genCSMessage(String version, String payLoadVersion, String requestName, String messageId, String destinationID, String organisation, Credential originator, Object payload, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		CSMessage retval = objectFactory.createCSMessage();
		retval.setVersion(version);
		retval.setPayLoadVersion(payLoadVersion);
		if(messageId == null){
		  retval.setID(MessageGenerateUtils.generateRandomUUID());
		}else{
		  retval.setID(messageId);
		}
		retval.setTimeStamp(MessageGenerateUtils.dateToXMLGregorianCalendar(systemTime.getSystemTime()));
		retval.setName(messageNameCatalogue.lookupName(requestName, payload));
		retval.setDestinationId(destinationID);
		retval.setSourceId(sourceId);
		retval.setOrganisation(organisation);
		if(originator != null){
			Originator originatorElement = objectFactory.createOriginator();
			originatorElement.setCredential(originator);
		    retval.setOriginator(originatorElement);
		}
		
		if(assertions != null && assertions.size() > 0){
			Assertions assertionsElem = objectFactory.createAssertions();
			for(Object assertion : assertions){
			  assertionsElem.getAny().add(assertion);
			}
			retval.setAssertions(assertionsElem);
		}
		
		Payload payLoadElem = objectFactory.createPayload();
		payLoadElem.setAny(payload);
		retval.setPayload(payLoadElem);
			
		return retval;
	}

	/**
	 * @see CSMessageParser#populateOriginatorAssertionsAndSignCSMessage(CSMessage, String, Credential, List)
	 */
	public byte[] populateOriginatorAssertionsAndSignCSMessage(CSMessage message, String destinationId, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
        if(destinationId != null){
			message.setDestinationId(destinationId);
		}
		if(originator != null){
			Originator o = objectFactory.createOriginator();
			o.setCredential(originator);
			message.setOriginator(o);
		}
		if(assertions != null){
			message.setAssertions(objectFactory.createAssertions());
			message.getAssertions().getAny().addAll(assertions);
		}

		// Remove current signature
		message.setSignature(null);

		return marshallAndSignCSMessage(message);
	}

	/**
	 * Help method that sets status to success and the in response to ID.
	 * @param response the response object to populate
	 * @param request the related request.
	 * 
	 * @throws MessageProcessingException  if problem occurred parsing the CSResponse from the respone object.
	 */
	private void populateSuccessfulResponse(
			Object response, CSMessage request) throws MessageProcessingException {
		
		CSResponse csresp = null;
		if(response instanceof CSResponse ){
			csresp = (CSResponse) response;
		}
		if(response instanceof JAXBElement<?> ){
			if(((JAXBElement<?>) response).getValue() instanceof CSResponse){
		  	  csresp = (CSResponse) ((JAXBElement<?>) response).getValue();
			}
		}
		if(csresp == null){
			throw new MessageProcessingException("Error populating CS response, response object is not a CSResponse");
		}
		
		csresp.setFailureMessage(null);
		csresp.setStatus(RequestStatus.SUCCESS);
		csresp.setInResponseTo(request.getID());		
	}
	


	/**
	 * Method that generates the signature and marshalls the message to byte array in UTF-8 format.
	 * @param csMessage the PKIMessage to sign and marshall, never null.
	 * @return a marshalled and signed message.
	 * @throws MessageProcessingException if problems occurred when processing the message.
	 * @throws MessageContentException if unsupported version is detected in message.
	 */
	public synchronized byte[] marshallAndSignCSMessage(CSMessage csMessage) throws MessageProcessingException, MessageContentException{
		if(csMessage == null){
			throw new MessageProcessingException("Error marshalling CS Message, message cannot be null.");
		}
		
		try {
			Document doc = getDocumentBuilder().newDocument();		
			String version = csMessage.getVersion();

			jaxbData.getCSMessageMarshaller(version).marshal(csMessage, doc);

			return xmlSigner.marshallAndSign(ContextMessageSecurityProvider.DEFAULT_CONTEXT,doc, cSMessageSignatureLocationFinder);
		} catch (JAXBException e) {
			throw new MessageProcessingException("Error marshalling CS Message, " + CSMessageUtils.getMarshallingExceptionMessage(e),e);
		} catch (ParserConfigurationException e) {
			throw new MessageProcessingException("Error marshalling CS Message, " + CSMessageUtils.getMarshallingExceptionMessage(e),e);
		}
		
		
	}


	/**
	 * Method that marshalls the message to byte array in UTF-8 format without adding any signature.
	 * @param csMessage the CSMessage to marshall, never null.
	 * @return a marshalled message.
	 * @throws MessageProcessingException if problems occurred when processing the message.
	 */
	public byte[] marshallCSMessage(CSMessage csMessage) throws MessageProcessingException, MessageContentException{
		if(csMessage == null){
			throw new MessageProcessingException("Error marshalling CS Message, message cannot be null.");
		}

		try {
			Document doc = getDocumentBuilder().newDocument();
			String version = csMessage.getVersion();

			jaxbData.getCSMessageMarshaller(version).marshal(csMessage, doc);

			return xmlSigner.marshallDoc(doc);
		} catch (JAXBException e) {
			throw new MessageProcessingException("Error marshalling CS Message, " + CSMessageUtils.getMarshallingExceptionMessage(e),e);
		} catch (ParserConfigurationException e) {
			throw new MessageProcessingException("Error marshalling CS Message, " + CSMessageUtils.getMarshallingExceptionMessage(e),e);
		}
	}

	/**
     * Method that tries to parse the xml version from a message
     * @param messageData the messageData to extract version from.
     * @return the version in the version and payLoadVersion attributes of the message.
     * @throws MessageContentException didn't contains a valid version attribute.
     * @throws MessageProcessingException if internal problems occurred.
     */
    public CSMessageVersion getVersionFromMessage(byte[] messageData) throws MessageContentException, MessageProcessingException{

    	try{
    		Document doc = getDocumentBuilder().parse(new ByteArrayInputStream(messageData));
    		
    		return  getVersionFromMessage(doc);	

    	}catch(Exception e){
    		if( e instanceof MessageContentException){
    			throw (MessageContentException) e;
    		}
    		if( e instanceof MessageProcessingException){
    			throw (MessageProcessingException) e;
    		}
    		throw new MessageContentException("Error parsing XML data: " + e.getMessage(),e);
    	}

  
    }
	
    /**
     * Method that tries to parse the xml version from a message
     * @param doc the document to extract version from.
     * @return the version in the version and payLoadVersion attributes of the message.
     * @throws MessageContentException didn't contains a valid version attribute.
     * @throws MessageProcessingException if internal problems occurred.
     */
    private CSMessageVersion getVersionFromMessage(Document doc) throws MessageContentException, MessageProcessingException{
    	String messageVersion = null;
    	String payLoadVersion = null;
    	try{
    		Node csMessage = doc.getFirstChild();
    		if(csMessage != null){
    			Node versionNode = csMessage.getAttributes().getNamedItem("version");
    			if(versionNode != null){
    				messageVersion = versionNode.getNodeValue();
    			}
    			Node payLoadVersionNode = csMessage.getAttributes().getNamedItem("payLoadVersion");
    			if(payLoadVersionNode != null){
    				payLoadVersion = payLoadVersionNode.getNodeValue();
    			}
    		}    		

    	}catch(Exception e){
    		throw new MessageContentException("Error parsing XML data: " + e.getMessage(),e);
    	}

    	if(messageVersion == null || messageVersion.trim().equals("")){
    	  throw new MessageContentException("Error no version attribute found in CS Message.");
    	}
    	if(payLoadVersion == null || payLoadVersion.trim().equals("")){
      	  throw new MessageContentException("Error no payload version attribute found in CS Message.");
      	}
    	return new CSMessageVersion(messageVersion, payLoadVersion);
    }
	
	public MessageSecurityProvider getMessageSecurityProvider() {
		return securityProvider;
	}
	
	public Marshaller getMarshaller(CSMessage message)
			throws MessageContentException, MessageProcessingException {
		return jaxbData.getCSMessageMarshaller(message.getVersion());
	}

	/**
	 * Verifies that the given version is supported.
	 * @param version the version to check.
	 * @throws MessageContentException if version is unsupported.
	 */
	private void verifyCSMessageVersion(String version) throws MessageContentException{
		boolean foundVersion = false;
		for(String supportedVersion : SUPPORTED_CSMESSAGE_VERSIONS){
			if(supportedVersion.equals(version)){
				foundVersion=true;
				break;
			}
		}
		if(!foundVersion){
			throw new MessageContentException("Error unsupported protocol version " + version);
		}
	}
	

	/**
	 * Method that validates the fields of the message that isn't already validated by the schema
	 * and the digital signature of the message.
	 *
	 * @param version the versions of the CS Message
	 * @param object the message to validate.
	 * @param doc the document of the message data.
	 * @param performValidation true if the message security provider should perform
	 * validate that the signing certificate is valid and authorized for related organisation.
	 * Otherwise must validation be performed manually after the message is parsed.
	 * @param requireSignature if signature should be verified
	 * @throws MessageContentException if the message contained bad format.
	 * @throws MessageProcessingException if internal problems occurred validating the message.
	 */
	private void validateCSMessage(CSMessageVersion version, Object object, Document doc, boolean performValidation, boolean requireSignature) throws MessageContentException, MessageProcessingException {
		if(!(object instanceof CSMessage)){
			throw new MessageContentException("Error: parsed object not a CS Message.");
		}

		CSMessage csMessage = (CSMessage) object;
		validateCSMessageHeader(csMessage, doc, performValidation, requireSignature);
		if(csMessage.getAssertions() != null){
		  validateAssertions(csMessage.getAssertions().getAny());
		}
		validatePayloadObject(version, csMessage.getPayload().getAny());
	}
	
	/**
	 * Method that validates the "header" parts of the cs message.
	 * 
	 * @param csMessage the cs message to validate, never null
	 * @param doc related message as Document
	 * @param performValidation true if the message security provider should perform
	 * @param requireSignature if signatures should be verified.
	 * validate that the signing certificate is valid and authorized for related organisation.
	 * Otherwise must validation be performed manually after the message is parsed.
	 * @throws MessageContentException if the header contained illegal arguments.
	 */
	private void validateCSMessageHeader(CSMessage csMessage, Document doc, boolean performValidation, boolean requireSignature) throws MessageContentException, MessageProcessingException{
		validateSignature(doc, performValidation, requireSignature);
	}

	
	/**
	 * Method to validate a payload object separately, used for special cases such when validating GetApprovalRequest requestData etc.
	 * 
	 * @param version the versions of a CS message.
	 * @param payLoadObject the pay load object to validate schema for.
	 * 
	 * @throws MessageProcessingException
	 * @throws MessageContentException if the message contained invalid XML.
	 */
    public void validatePayloadObject(CSMessageVersion version, Object payLoadObject) throws MessageContentException {
		try {
			String payLoadNamespace = jaxbData.getNamespace(payLoadObject);
			if(!payLoadNamespace.equals(CSMESSAGE_NAMESPACE)){
			  Validator validator = jaxbData.getPayLoadValidatorFromCache(payLoadNamespace, version.getMessageVersion(), version.getPayLoadVersion());
			  validator.validate(new JAXBSource(jaxbData.getJAXBContext(), payLoadObject));
			}else{
				if(payLoadObject instanceof GetApprovalRequest){
					GetApprovalRequest getApprovalRequest = (GetApprovalRequest) payLoadObject;
					Object requestedPayload = getApprovalRequest.getRequestPayload().getAny();
					String requestedPayLoadNamespace = jaxbData.getNamespace(requestedPayload);
					Validator validator = jaxbData.getPayLoadValidatorFromCache(requestedPayLoadNamespace, version.getMessageVersion(), version.getPayLoadVersion());
					validator.validate(new JAXBSource(jaxbData.getJAXBContext(), requestedPayload));
				}
			}
		} catch (Exception e) {
		throw new MessageContentException("Error parsing payload of CS Message: " + CSMessageUtils.getMarshallingExceptionMessage(e), e);
		}   	
    }
	
	/**
	 * Method to validate a message assertions object separately.
	 * 
	 * @param assertions list of assertions to validate.
	 * 
	 * @throws MessageProcessingException if internal problems occurred.
	 * @throws MessageContentException if the message contained invalid XML.
	 */
	private void validateAssertions(List<Object> assertions) throws MessageContentException, MessageProcessingException {
		if(assertions == null){
			return;
		}
		for(Object assertion : assertions){
			getAssertionPayloadParser().schemaValidateAssertion(assertion);
		}	
	}
	

    private AssertionPayloadParser assertionPayloadParser = null;
    private AssertionPayloadParser getAssertionPayloadParser() throws MessageProcessingException{
    	if(assertionPayloadParser == null){
    		assertionPayloadParser = (AssertionPayloadParser) PayloadParserRegistry.getParser(AssertionPayloadParser.NAMESPACE);
    	}
    	
    	return assertionPayloadParser;
    }

	/**
	 * Help method to verify a message signature.
	 *
	 * @param doc the document to validate signature of.
	 * @param performValidation true if the message security provider should perform
	 * @param requireSignature if signature should be verified
	 * validate that the signing certificate is valid and authorized for related organisation.
	 * Otherwise must validation be performed manually after the message is parsed.
	 */
	private void validateSignature(Document doc, boolean performValidation, boolean requireSignature) throws MessageContentException, MessageProcessingException {
		if(requireSignature() && requireSignature){
			xmlSigner.verifyEnvelopedSignature(doc, performValidation);
		}				
	}

	private DocumentBuilder getDocumentBuilder() throws ParserConfigurationException {
		return XMLUtils.createSecureDocumentBuilderFactory().newDocumentBuilder();
	}
	

	/**
	 * Method that generates a configured message name catalogue or uses the default
	 * one if not configured.
	 * 
	 * @param config the configuration.
	 * @return a newly generated MessageNameCatalogue
	 * @throws MessageProcessingException if problems occurred generating a MessageNameCatalogue
	 */
    private MessageNameCatalogue getMessageNameCatalogue(Properties config) throws MessageProcessingException{
    	try{
    		MessageNameCatalogue retval =  (MessageNameCatalogue) this.getClass().getClassLoader().loadClass(config.getProperty(SETTING_MESSAGE_NAME_CATALOGUE_IMPL, DEFAULT_MESSAGE_NAME_CATALOGUE_IMPL)).getDeclaredConstructor().newInstance();
    		retval.init(config);
    		return retval;
    	}catch(Exception e){
    		throw new MessageProcessingException("Error creating creating name catalogue " + e.getClass().getName() + ": " + e.getMessage());
    	}
    }
	
	private Boolean signMessages;
	private boolean signMessages() throws MessageProcessingException{
		if(signMessages == null){
			signMessages = SettingsUtils.parseBooleanWithDefault(properties, SETTING_SIGN, OLD_SETTING_SIGN, true);
		}
		return signMessages;
	}
	

	private Boolean requireSignature;
	private boolean requireSignature() throws MessageProcessingException{
		if(requireSignature == null){
			requireSignature = SettingsUtils.parseBooleanWithDefault(properties, SETTING_REQUIRESIGNATURE, OLD_SETTING_REQUIRESIGNATURE,true);
		}
		return requireSignature;
	}
	
	public Credential getOriginatorFromRequest(CSMessage request) {
		Credential retval = null;
		if(request!= null && request.getOriginator() != null){
			retval = request.getOriginator().getCredential();
		}
		return retval;
	}

	/**
	 * Method to return the CSMessageVersion set in generated request messages. Response messages
	 * always use the same version as in the request.
	 *
	 * This is automatically set to the latest version.
	 * @return the CS Message Version used.
	 */
	public String getCSMessageVersion(){
		return DefaultCSMessageParser.csMessageVersion;
	}

	/**
	 * Method to set the CSMessageVersion set in generated request messages. Should
	 * only be used under special cases. Response messages
	 * always use the same version as in the request.
	 *
	 * CSMessageVersion is automatically set to the latest version.
	 *
	 */
	public void setCSMessageVersion(String csMessageVersion){
		DefaultCSMessageParser.csMessageVersion = csMessageVersion;
	}
	
	/**
	 * Helper class to group JAXB Related data, and make it easy to re-init if new payload parser is registered.
	 *  
	 * @author Philip Vendil
	 *
	 */
	private class JAXBRelatedData{
		
		private JAXBContext jaxbContext = null;
		private HashMap<String, Validator> payLoadValidatorCache = new HashMap<String, Validator>();
	    private JAXBIntrospector jaxbIntrospector = null;
		private Map<String, Schema> csMessageSchemaCache = new HashMap<String, Schema>();
		private String jaxbClassPath = "";
		
		void clearAllJAXBData(){
			jaxbClassPath = "";
			jaxbContext = null;
			payLoadValidatorCache.clear();
			csMessageSchemaCache.clear();
			jaxbIntrospector = null;
		}
		
	    /**
	     * Help method maintaining the PKI Message JAXB Context.
	     */
	    JAXBContext getJAXBContext() throws JAXBException, MessageProcessingException{
	    	if(jaxbContext== null){
	    		jaxbClassPath = "org.signatureservice.messages.csmessages.jaxb:org.signatureservice.messages.xmldsig.jaxb:org.signatureservice.messages.xenc.jaxb";
	    			    		
	    		for(String namespace : PayloadParserRegistry.getRegistredNamespaces()){
	    			String jaxbPackage = PayloadParserRegistry.getParser(namespace).getJAXBPackage();
	    			if(jaxbPackage != null){
	    			  jaxbClassPath += ":" + jaxbPackage;
	    			}
	    		}
	    		
	    		jaxbContext = JAXBContext.newInstance(jaxbClassPath);
	    		
	    	}
	    	return jaxbContext;
	    }
	    
		
		Validator getPayLoadValidatorFromCache(String payLoadNamespace, String version, String payLoadVersion) throws MessageProcessingException, MessageContentException{
			String key = payLoadNamespace + ";" + version + ";" + payLoadVersion;
			Validator retval = payLoadValidatorCache.get(key);
			if(retval == null){
				PayloadParser pp = PayloadParserRegistry.getParser(payLoadNamespace);
				InputStream payLoadSchemaStream = pp.getSchemaAsInputStream(payLoadVersion);
		    	String csMessageSchemaLocation = csMessageSchemaMap.get(version);

		    	String[] relatedSchemas = pp.getRelatedSchemas(payLoadVersion);

		        Source[] sources = new Source[(payLoadSchemaStream == null ? 2 + relatedSchemas.length: 3 + relatedSchemas.length)];
		        sources[0] = new StreamSource(getClass().getResourceAsStream(XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION));
		        sources[1] = new StreamSource(getClass().getResourceAsStream(csMessageSchemaLocation));
				for(int i = 0; i<relatedSchemas.length; i++){
					sources[2+i] = new StreamSource(getClass().getResourceAsStream(relatedSchemas[i]));
				}
		        if(payLoadSchemaStream != null){
		          sources[2 + relatedSchemas.length] = new StreamSource(payLoadSchemaStream);
		        }

				try {
					Schema s = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI).newSchema(sources);
					retval = s.newValidator();
				} catch (SAXException e) {
					throw new MessageProcessingException("Problems occurred generating pay load schema for " + payLoadNamespace + ", version " + payLoadVersion + ", error: " + e.getMessage(),e);
				}
				payLoadValidatorCache.put(key, retval);
			}
			
			return retval;
		}
		
	    JAXBIntrospector getJAXBIntrospector() throws JAXBException, MessageProcessingException{
	    	if(jaxbIntrospector== null){
	    		jaxbIntrospector = getJAXBContext().createJAXBIntrospector();
	    	}
	    	return jaxbIntrospector;
	    }
		
		Marshaller createMarshaller(String schemaLocation) throws JAXBException, MessageProcessingException {
			Marshaller retval = getJAXBContext().createMarshaller();
			retval.setProperty(Marshaller.JAXB_SCHEMA_LOCATION, schemaLocation);
			retval.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
			return retval;
		}
		
	    /**
	     * Help method to fetch the name space of a given jaxb object.
	     *  
	     * @param jaxbObject the jaxbObject to lookup
	     * 
	     * @return the related name space of the object or null of object didn't have any related name space.
	     * @throws MessageProcessingException If problems occurred generating JAXB Context.
	     * @throws JAXBException of internal JAXB problems occurred when looking up the name space.
	     */
	    private String getNamespace(Object jaxbObject) throws MessageProcessingException {
	    	QName qname = null;
			try {
				qname = getJAXBIntrospector().getElementName(jaxbObject);
			} catch (JAXBException e) {
				throw new MessageProcessingException("Problems occured generating JAXB Context ( Introspector ) : " + e.getMessage(), e);
			}
	    	if(qname != null){
	    	  return qname.getNamespaceURI();
	    	}
	    	return null;
	    }
	    
	    /**
	     * Method that returns a marshaller for a given version,
	     * @param version the version of the CS Message protocol to fetch.
	     * @return related marshaller
	     * @throws MessageProcessingException if problems occurred creating the CS Message Marshaller for the given version.
	     * @throws MessageContentException if requested version was unsupported.
	     */
	    Marshaller getCSMessageMarshaller(String version) throws MessageProcessingException, MessageContentException{
	    	if(version == null){
	    		throw new MessageContentException("Invalid CS Message, version is missing.");
	    	}
	    	
			Marshaller retval;
			String schemaURL = csMessageSchemaUriMap.get(version);
			try{
				retval = createMarshaller(schemaURL);
				retval.setSchema(getCSMessageSchema(version));
			} catch(Exception e){
				throw new MessageProcessingException("Error creating XML Marshaller for CS Message version: " + version);
			}

	    	return retval;
	    }
		
	    /**
	     * Method that returns a unmarshaller for a given version,
	     * @param version the version of the PKI Message protocol to fetch.
	     * @return related unmarshaller
	     * @throws MessageProcessingException if problems occurred creating the PKI Message Marshaller for the given version.
	     * @throws MessageContentException   if requested version was unsupported.
	     */
	    Unmarshaller getCSMessageUnmarshaller(String version) throws MessageProcessingException, MessageContentException{
	    	if(version == null){
	    		throw new MessageContentException("Invalid CS Message, version is missing.");
	    	}
	    	
	    	Unmarshaller retval;
			try{
				retval = getJAXBContext().createUnmarshaller();
				retval.setSchema(getCSMessageSchema(version));
			} catch(Exception e){
				throw new MessageProcessingException("Error creating XML Unmarshaller for CS Message version: " + version);
			}
	    	return retval;
	    }

	    
	    /**
	     * Help method to generate a  CSMessage Schema for a given version.
	     * @param version the version to look up.
	     * @return the generated Schema
	     * @throws MessageContentException
	     * @throws SAXException
	     * @throws MessageProcessingException
	     */
	    Schema getCSMessageSchema(String version) throws MessageContentException, SAXException, MessageProcessingException{
			Schema retval = csMessageSchemaCache.get(version);
			if(retval == null) {
				String schemaLocation = csMessageSchemaMap.get(version);
				SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);

				Source[] sources = new Source[2];
				sources[0] = new StreamSource(getClass().getResourceAsStream(XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION));
				sources[1] = new StreamSource(getClass().getResourceAsStream(schemaLocation));

				retval = schemaFactory.newSchema(sources);
				csMessageSchemaCache.put(version, retval);
			}
	        return retval;
	    }
	}


	public class CSMessageSignatureLocationFinder implements XMLSigner.SignatureLocationFinder {
		@Override
		public Element[] getSignatureLocations(Document doc) throws MessageContentException {
			try{
				if(doc.getDocumentElement().getLocalName().equals("CSMessage") && doc.getDocumentElement().getNamespaceURI().equals(DefaultCSMessageParser.CSMESSAGE_NAMESPACE)){
					return new Element[]{doc.getDocumentElement()};
				}
			}catch(Exception e){
			}
			throw new MessageContentException("Invalid CS message type sent for signature.");
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
			return null;
		}
	}

}
