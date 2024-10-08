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
package org.certificateservices.messages.pkimessages;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.certificateservices.messages.MessageException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.MessageSecurityProvider;
import org.certificateservices.messages.csmessages.DefaultCSMessageParser;
import org.certificateservices.messages.pkimessages.jaxb.ChangeCredentialStatusRequest;
import org.certificateservices.messages.pkimessages.jaxb.ChangeCredentialStatusResponse;
import org.certificateservices.messages.pkimessages.jaxb.Credential;
import org.certificateservices.messages.pkimessages.jaxb.CredentialStatusList;
import org.certificateservices.messages.pkimessages.jaxb.FetchHardTokenDataRequest;
import org.certificateservices.messages.pkimessages.jaxb.FetchHardTokenDataResponse;
import org.certificateservices.messages.pkimessages.jaxb.GetCredentialRequest;
import org.certificateservices.messages.pkimessages.jaxb.GetCredentialResponse;
import org.certificateservices.messages.pkimessages.jaxb.GetCredentialStatusListRequest;
import org.certificateservices.messages.pkimessages.jaxb.GetCredentialStatusListResponse;
import org.certificateservices.messages.pkimessages.jaxb.GetIssuerCredentialsRequest;
import org.certificateservices.messages.pkimessages.jaxb.GetIssuerCredentialsResponse;
import org.certificateservices.messages.pkimessages.jaxb.IsIssuerRequest;
import org.certificateservices.messages.pkimessages.jaxb.IsIssuerResponse;
import org.certificateservices.messages.pkimessages.jaxb.IssueCredentialStatusListRequest;
import org.certificateservices.messages.pkimessages.jaxb.IssueCredentialStatusListResponse;
import org.certificateservices.messages.pkimessages.jaxb.IssueTokenCredentialsRequest;
import org.certificateservices.messages.pkimessages.jaxb.IssueTokenCredentialsResponse;
import org.certificateservices.messages.pkimessages.jaxb.ObjectFactory;
import org.certificateservices.messages.pkimessages.jaxb.Originator;
import org.certificateservices.messages.pkimessages.jaxb.PKIMessage;
import org.certificateservices.messages.pkimessages.jaxb.PKIMessage.Payload;
import org.certificateservices.messages.pkimessages.jaxb.PKIResponse;
import org.certificateservices.messages.pkimessages.jaxb.RemoveCredentialRequest;
import org.certificateservices.messages.pkimessages.jaxb.RemoveCredentialResponse;
import org.certificateservices.messages.pkimessages.jaxb.RequestStatus;
import org.certificateservices.messages.pkimessages.jaxb.StoreHardTokenDataRequest;
import org.certificateservices.messages.pkimessages.jaxb.StoreHardTokenDataResponse;
import org.certificateservices.messages.pkimessages.jaxb.TokenRequest;
import org.certificateservices.messages.utils.MessageGenerateUtils;
import org.certificateservices.messages.utils.SettingsUtils;
import org.certificateservices.messages.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * Default implementation of a PKI Message parser generating and signing messages
 * accordning to the specification.
 * 
 * 
 * @author Philip Vendil
 *
 */
@SuppressWarnings({ "deprecation" })
public class DefaultPKIMessageParser implements PKIMessageParser {

	public static final String SETTING_SOURCEID = "pkimessage.sourceid";
	public static final String SETTING_SIGN = "pkimessage.sign";
	public static final String SETTING_REQUIRESIGNATURE = "pkimessage.requiresignature";
	
	public static final String SETTING_MESSAGE_NAME_CATALOGUE_IMPL = "pkimessage.messagenamecatalogue.impl";
	public static final String DEFAULT_MESSAGE_NAME_CATALOGUE_IMPL = DefaultMessageNameCatalogue.class.getName();

	private static final String PKIMESSAGE_VERSION_1_0 = "1.0";
	private static final String PKIMESSAGE_VERSION_1_1 = "1.1";
	
	private static final String PKIMESSAGE_XSD_SCHEMA_1_0_RESOURCE_LOCATION = "/pkimessages_schema1_0.xsd";
	private static final String PKIMESSAGE_XSD_SCHEMA_1_1_RESOURCE_LOCATION = "/pkimessages_schema1_1.xsd";
	
	private static final String PKIMESSAGE_XSD_SCHEMA_1_0_URI = "http://certificateservices.org/xsd/pkimessages1_0 pkimessages_schema1_0.xsd";	
	
	private static final Map<String,String> pkiMessageSchemaMap = new HashMap<String,String>();
	static{
		pkiMessageSchemaMap.put(PKIMESSAGE_VERSION_1_0, PKIMESSAGE_XSD_SCHEMA_1_0_RESOURCE_LOCATION);
		pkiMessageSchemaMap.put(PKIMESSAGE_VERSION_1_1, PKIMESSAGE_XSD_SCHEMA_1_1_RESOURCE_LOCATION);
	}
	
	private static final Map<String,String> pkiMessageSchemaUriMap = new HashMap<String,String>();
	static{
		pkiMessageSchemaUriMap.put(PKIMESSAGE_VERSION_1_0, PKIMESSAGE_XSD_SCHEMA_1_0_URI);
		pkiMessageSchemaUriMap.put(PKIMESSAGE_VERSION_1_1, PKIMESSAGE_XSD_SCHEMA_1_0_URI);
	}
	
	private static final String XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION = "/xmldsig-core-schema.xsd";
	

	private static final String[] SUPPORTED_PKIMESSAGE_VERSIONS = {"1.0","1.1"};
	

	private Map<String,Marshaller> pkixMessageMarshallers = new HashMap<String, Marshaller>();
	private Map<String,Unmarshaller> pkixMessageUnmarshallers = new HashMap<String, Unmarshaller>();
	
	private ObjectFactory objectFactory = new ObjectFactory();
	
	private Properties properties = null;
	private MessageSecurityProvider securityProvider = null;
	private MessageNameCatalogue messageNameCatalogue = null;
	
	private String sourceId = null;
	
	private String defaultVersion = PKIMESSAGE_VERSION_1_1;
		
	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#init(org.certificateservices.messages.MessageSecurityProvider, java.util.Properties)
	 */
	
	public void init(MessageSecurityProvider securityProvider,
			Properties config) throws MessageException {
		this.properties = config;
		this.securityProvider = securityProvider;
		this.messageNameCatalogue = getMessageNameCatalogue(config);
		

		// Initialize all marshallers for all supported version.
		for(String version : SUPPORTED_PKIMESSAGE_VERSIONS){
			getPKIMessageMarshaller(version);
			getPKIMessageUnmarshaller(version);
		}

		sourceId = SettingsUtils.getProperty(config, SETTING_SOURCEID, DefaultCSMessageParser.SETTING_SOURCEID);
		if(sourceId == null || sourceId.trim().equals("")){
			throw new MessageException("Error setting " + DefaultCSMessageParser.SETTING_SOURCEID + " must be set.");
		}

		
	}

	Marshaller createMarshaller(JAXBContext jaxbContext, String schemaLocation) throws JAXBException{
		Marshaller retval = jaxbContext.createMarshaller();
		
		retval.setProperty(Marshaller.JAXB_SCHEMA_LOCATION, schemaLocation);
		retval.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
		return retval;
	}
	
	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#parseMessage(byte[])
	 */
	
	public synchronized PKIMessage parseMessage(byte[] messageData)
			throws IllegalArgumentException, MessageException {
		try{
			
			
			String version = getVersionFromMessage(messageData);
			verifyPKIMessageVersion(version);
			
			
			Object object = getPKIMessageUnmarshaller(version).unmarshal(new ByteArrayInputStream(messageData));
			validatePKIMessage(object, new String(messageData,"UTF-8"));
			return (PKIMessage) object;
		}catch(JAXBException e){
			throw new IllegalArgumentException("Error parsing PKI Message: " + e.getMessage(),e);
		} catch (UnsupportedEncodingException e) {
			throw new IllegalArgumentException("Error parsing PKI Message: " + e.getMessage(),e);
		}
		
	}
	
	/**
	 * Verifies that the given version is supported.
	 * @param version the version to check.
	 * @throws IllegalArgumentException if version is unsupported.
	 */
	private void verifyPKIMessageVersion(String version) throws IllegalArgumentException{
		boolean foundVersion = false;
		for(String supportedVersion : SUPPORTED_PKIMESSAGE_VERSIONS){
			if(supportedVersion.equals(version)){
				foundVersion=true;
				break;
			}
		}
		if(!foundVersion){
			throw new IllegalArgumentException("Error unsupported protocol version " + version);
		}
	}

	/**
	 * Method that validates the fields of the message that isn't already validated by the schema
	 * and the digital signature of the message.
	 * @param object the message to validate.
	 * @param message string representation of the message data.
	 * @throws IllegalArgumentException if the message contained bad format.
	 * @throws MessageException if internal problems occurred validating the message.
	 */
	private void validatePKIMessage(Object object, String message) throws IllegalArgumentException, MessageException {
		
		if(!(object instanceof PKIMessage)){
			throw new IllegalArgumentException("Error: parsed object not a PKI Message.");
		}
		PKIMessage pkiMessage = (PKIMessage) object;
		validatePKIMessageHeader(pkiMessage, message);
	}

	/**
	 * Method that validates the "header" parts of the pki message.
	 * @param pkiMessage the pki message to validate, never null
	 * @param message string representation of the message data.
	 * @throws IllegalArgumentException if the header contained illegal arguments.
	 */
	private void validatePKIMessageHeader(PKIMessage pkiMessage, String message) throws IllegalArgumentException, MessageException{
		

		
		validateSignature(message);
		
		
	}

	private void validateSignature(String message) throws IllegalArgumentException, MessageException {
		if(requireSignature()){
			try{
				DocumentBuilder builder = XMLUtils.createDocumentBuilderFactory().newDocumentBuilder();
				Document doc = builder.parse(new InputSource(new StringReader(message)));

				Node signature = doc.getElementsByTagName("ds:Signature").item(0);

				if(signature == null){
					throw new IllegalArgumentException("Required digital signature not found in message.");
				}

				DOMValidateContext validationContext = new DOMValidateContext(new X509DataOnlyKeySelector(securityProvider), signature);
				validationContext.setIdAttributeNS(doc.getDocumentElement(), null, "ID");
				XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM",new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
				XMLSignature sig =  signatureFactory.unmarshalXMLSignature(validationContext);
				if(!sig.validate(validationContext)){
					throw new IllegalArgumentException("Error, signed message didn't pass validation.");
				}
				//sig.getKeyInfo().getContent().g
			}catch(Exception e){
				if(e instanceof IllegalArgumentException ){
					throw (IllegalArgumentException) e;
				}
				if(e instanceof MessageException){
					throw (MessageException) e;
				}
				throw new IllegalArgumentException("Error validating signature of message: " + e.getMessage(),e);
			}
		}				
	}

	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#genIssueTokenCredentialsRequest(String, String, TokenRequest)
	 */
	public byte[] genIssueTokenCredentialsRequest(String requestId, String destinationId, String organisation, 
			TokenRequest tokenRequest, Credential originator) throws IllegalArgumentException,
			MessageException {
		IssueTokenCredentialsRequest payload = objectFactory.createIssueTokenCredentialsRequest();
		payload.setTokenRequest(tokenRequest);
		PKIMessage pkiMessage = genPKIMessage(defaultVersion, requestId, destinationId, organisation, originator, payload);		
		return marshallAndSignPKIMessage( pkiMessage);
	}

	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#genIssueTokenCredentialsResponse(PKIMessage, List, List)
	 */
	
	public PKIMessageResponseData genIssueTokenCredentialsResponse(String relatedEndEntity, PKIMessage request,
			List<Credential> credentials, List<Credential> revokedCredentials) throws IllegalArgumentException,
			MessageException {
		IssueTokenCredentialsRequest issueTokenCredentialsRequest = request.getPayload().getIssueTokenCredentialsRequest();
		if(issueTokenCredentialsRequest == null){
			throw new IllegalArgumentException("Error IssueTokenCredentialsResponse requires a IssueTokenCredentialsRequest in request payload.");
		}
		
		IssueTokenCredentialsResponse payload = objectFactory.createIssueTokenCredentialsResponse();
		populateSuccessfulResponse(payload, request);
		payload.setTokenRequest(issueTokenCredentialsRequest.getTokenRequest());
		payload.setCredentials(new IssueTokenCredentialsResponse.Credentials());
		for(Credential cred : credentials){
		  payload.getCredentials().getCredential().add(cred);
		}
		if(revokedCredentials != null){
			payload.setRevokedCredentials(new IssueTokenCredentialsResponse.Credentials());
			for(Credential cred : revokedCredentials){
				payload.getRevokedCredentials().getCredential().add(cred);
			}
		}
		
		PKIMessage pkiMessage = genPKIMessage(request.getVersion(), request.getName(),null, request.getSourceId(), request.getOrganisation(), getOriginatorFromRequest(request), payload);		
		byte[] responseData = marshallAndSignPKIMessage(pkiMessage);
		return new PKIMessageResponseData(pkiMessage.getID(),pkiMessage.getName(), relatedEndEntity, pkiMessage.getDestinationId(),responseData, true);
	}

	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#genChangeCredentialStatusRequest(String, String, String, String, int, String)
	 */
	
	public byte[] genChangeCredentialStatusRequest(String requestId, String destinationId,String organisation, 
			String issuerId, String serialNumber, int newCredentialStatus,
			String reasonInformation, Credential originator) throws IllegalArgumentException,
			MessageException {
		ChangeCredentialStatusRequest payload = objectFactory.createChangeCredentialStatusRequest();
		payload.setIssuerId(issuerId);
		payload.setSerialNumber(serialNumber);
		payload.setNewCredentialStatus(newCredentialStatus);
		payload.setReasonInformation(reasonInformation);
		PKIMessage pkiMessage = genPKIMessage(defaultVersion, requestId, destinationId, organisation, originator, payload);		
		return marshallAndSignPKIMessage(pkiMessage);
	}

	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#genChangeCredentialStatusResponse(PKIMessage, String, String, int, String, Date)
	 */
	
	public PKIMessageResponseData genChangeCredentialStatusResponse(String relatedEndEntity, PKIMessage request,
			String issuerId, String serialNumber, int credentialStatus,
			String reasonInformation, Date revocationDate)
			throws IllegalArgumentException, MessageException {
		ChangeCredentialStatusRequest changeCredentialStatusRequest = request.getPayload().getChangeCredentialStatusRequest();
		if(changeCredentialStatusRequest == null){
			throw new IllegalArgumentException("Error ChangeCredentialStatusResponse requires a ChangeCredentialStatusRequest in request payload.");
		}
		
		ChangeCredentialStatusResponse payload = objectFactory.createChangeCredentialStatusResponse();
		populateSuccessfulResponse(payload, request);
		payload.setIssuerId(issuerId);
		payload.setSerialNumber(serialNumber);
		payload.setCredentialStatus(credentialStatus);
		payload.setReasonInformation(reasonInformation);
		payload.setRevocationDate(PKIMessageGenerateUtils.dateToXMLGregorianCalendar(revocationDate));
		PKIMessage pkiMessage = genPKIMessage(request.getVersion(), request.getName(),null, request.getSourceId(), request.getOrganisation(), getOriginatorFromRequest(request), payload);		
		byte[] responseData = marshallAndSignPKIMessage( pkiMessage);
		return new PKIMessageResponseData(pkiMessage.getID(),pkiMessage.getName(), relatedEndEntity, pkiMessage.getDestinationId(),responseData, true);
	}

	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#genGetCredentialRequest(String, String, String, String, String)
	 */
	
	public byte[] genGetCredentialRequest(String requestId, String destinationId, String organisation, String credentialSubType, String issuerId,
			String serialNumber, Credential originator) throws IllegalArgumentException,
			MessageException {
		GetCredentialRequest payload = objectFactory.createGetCredentialRequest();
		payload.setCredentialSubType(credentialSubType);
		payload.setIssuerId(issuerId);
		payload.setSerialNumber(serialNumber);
		PKIMessage pkiMessage = genPKIMessage(defaultVersion, requestId, destinationId, organisation, originator, payload);		
		return marshallAndSignPKIMessage(pkiMessage);
	}

	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#genGetCredentialResponse(PKIMessage, Credential)
	 */
	
	public PKIMessageResponseData genGetCredentialResponse(String relatedEndEntity,PKIMessage request,
			Credential credential) throws IllegalArgumentException,
			MessageException {
		GetCredentialRequest getCredentialRequest = request.getPayload().getGetCredentialRequest();
		if(getCredentialRequest == null){
			throw new IllegalArgumentException("Error GetCredentialResponse requires a GetCredentialRequest in request payload.");
		}
		
		GetCredentialResponse payload = objectFactory.createGetCredentialResponse();
		populateSuccessfulResponse(payload, request);
		payload.setCredential(credential);		
		PKIMessage pkiMessage = genPKIMessage(request.getVersion(),request.getName(),null, request.getSourceId(), request.getOrganisation(), getOriginatorFromRequest(request), payload);		
		byte[] responseData = marshallAndSignPKIMessage(pkiMessage);
		return new PKIMessageResponseData(pkiMessage.getID(),pkiMessage.getName(), relatedEndEntity, pkiMessage.getDestinationId(),responseData);
	}

	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#genGetCredentialStatusListRequest(String, String, String, Long, String)
	 */
	
	public byte[] genGetCredentialStatusListRequest(String requestId, String destinationId,String organisation, 
			String issuerId, Long serialNumber, String credentialStatusListType, Credential originator)
			throws IllegalArgumentException, MessageException {
		GetCredentialStatusListRequest payload = objectFactory.createGetCredentialStatusListRequest();
		payload.setIssuerId(issuerId);
		payload.setSerialNumber(serialNumber);
		payload.setCredentialStatusListType(credentialStatusListType);
		PKIMessage pkiMessage = genPKIMessage(defaultVersion, requestId, destinationId, organisation, originator, payload);		
		return marshallAndSignPKIMessage(pkiMessage);
	}

	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#genGetCredentialStatusListResponse(org.certificateservices.messages.pkimessages.jaxb.PKIMessage, org.certificateservices.messages.pkimessages.jaxb.CredentialStatusList)
	 */
	
	public PKIMessageResponseData genGetCredentialStatusListResponse(String relatedEndEntity,PKIMessage request,
			CredentialStatusList credentialStatusList)
			throws IllegalArgumentException, MessageException {
		GetCredentialStatusListRequest getCredentialStatusListRequest = request.getPayload().getGetCredentialStatusListRequest();
		if(getCredentialStatusListRequest == null){
			throw new IllegalArgumentException("Error GetCredentialStatusListResponse requires a GetCredentialStatusListRequest in request payload.");
		}
		
		GetCredentialStatusListResponse payload = objectFactory.createGetCredentialStatusListResponse();
		populateSuccessfulResponse(payload, request);
		payload.setCredentialStatusList(credentialStatusList);	
		PKIMessage pkiMessage = genPKIMessage(request.getVersion(),request.getName(),null, request.getSourceId(), request.getOrganisation(), getOriginatorFromRequest(request), payload);		
		byte[] responseData = marshallAndSignPKIMessage(pkiMessage);
		return new PKIMessageResponseData(pkiMessage.getID(),pkiMessage.getName(), relatedEndEntity, pkiMessage.getDestinationId(),responseData);
	}
	
	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#genGetIssuerCredentialsRequest(String, String, String)
	 */
	
	public byte[] genGetIssuerCredentialsRequest(String requestId,String destinationId,String organisation, 
			String issuerId, Credential originator) throws IllegalArgumentException,
			MessageException {
		GetIssuerCredentialsRequest payload = objectFactory.createGetIssuerCredentialsRequest();
		payload.setIssuerId(issuerId);
		PKIMessage pkiMessage = genPKIMessage(defaultVersion, requestId, destinationId, organisation, originator, payload);		
		return marshallAndSignPKIMessage(pkiMessage);
	}

	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#genGetIssuerCredentialsResponse(PKIMessage, Credential)
	 */
	
	public PKIMessageResponseData genGetIssuerCredentialsResponse(String relatedEndEntity, PKIMessage request,
			Credential issuerCredential) throws IllegalArgumentException,
			MessageException {
		GetIssuerCredentialsRequest getIssuerCredentialsRequest = request.getPayload().getGetIssuerCredentialsRequest();
		if(getIssuerCredentialsRequest == null){
			throw new IllegalArgumentException("Error GetIssuerCredentialsResponse requires a GetIssuerCredentialsRequest in request payload.");
		}
		
		GetIssuerCredentialsResponse payload = objectFactory.createGetIssuerCredentialsResponse();
		populateSuccessfulResponse(payload, request);
		payload.setCredential(issuerCredential);		
		PKIMessage pkiMessage = genPKIMessage(request.getVersion(),request.getName(),null, request.getSourceId(), request.getOrganisation(), getOriginatorFromRequest(request), payload);		
		byte[] responseData = marshallAndSignPKIMessage(pkiMessage);
		return new PKIMessageResponseData(pkiMessage.getID(),pkiMessage.getName(), relatedEndEntity,pkiMessage.getDestinationId(),responseData);
	}

	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#genIsIssuerRequest(String, String, String)
	 */
	
	public byte[] genIsIssuerRequest(String requestId,String destinationId, String organisation,  String issuerId, Credential originator)
			throws IllegalArgumentException, MessageException {
		IsIssuerRequest payload = objectFactory.createIsIssuerRequest();
		payload.setIssuerId(issuerId);
		PKIMessage pkiMessage = genPKIMessage(defaultVersion,requestId,destinationId, organisation, originator, payload);		
		return marshallAndSignPKIMessage(pkiMessage);
	}

	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#genIsIssuerResponse(org.certificateservices.messages.pkimessages.jaxb.PKIMessage, boolean)
	 */
	
	public PKIMessageResponseData genIsIssuerResponse(String relatedEndEntity,PKIMessage request, boolean isIssuer)
			throws IllegalArgumentException, MessageException {
		IsIssuerRequest isIssuerRequest = request.getPayload().getIsIssuerRequest();
		if(isIssuerRequest == null){
			throw new IllegalArgumentException("Error IsIssuerResponse requires a IsIssuerRequest in request payload.");
		}
		
		IsIssuerResponse payload = objectFactory.createIsIssuerResponse();
		populateSuccessfulResponse(payload, request);
		payload.setIsIssuer(isIssuer);		
		PKIMessage pkiMessage = genPKIMessage(request.getVersion(),request.getName(),null, request.getSourceId(), request.getOrganisation(), getOriginatorFromRequest(request), payload);		
		byte[] responseData = marshallAndSignPKIMessage(pkiMessage);
		return new PKIMessageResponseData(pkiMessage.getID(),pkiMessage.getName(), relatedEndEntity,pkiMessage.getDestinationId(),responseData);
	}

	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#genIssueCredentialStatusListRequest(String, String, String, String, Boolean, Date, Date)
	 */
	
	public byte[] genIssueCredentialStatusListRequest(String requestId,String destinationId,String organisation, 
			String issuerId, String credentialStatusListType, Boolean force,
			Date requestedValidFromDate, Date requestedNotAfterDate, Credential originator )
			throws IllegalArgumentException, MessageException {
		IssueCredentialStatusListRequest payload = objectFactory.createIssueCredentialStatusListRequest();
		payload.setIssuerId(issuerId);
		payload.setCredentialStatusListType(credentialStatusListType);
		payload.setForce(force);
		payload.setRequestedNotAfterDate(PKIMessageGenerateUtils.dateToXMLGregorianCalendar(requestedNotAfterDate));
		payload.setRequestedValidFromDate(PKIMessageGenerateUtils.dateToXMLGregorianCalendar(requestedValidFromDate));
		PKIMessage pkiMessage = genPKIMessage(defaultVersion,requestId, destinationId, organisation, originator, payload);		
		return marshallAndSignPKIMessage(pkiMessage);
	}

	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#genIssueCredentialStatusListResponse(org.certificateservices.messages.pkimessages.jaxb.PKIMessage, org.certificateservices.messages.pkimessages.jaxb.CredentialStatusList)
	 */
	
	public PKIMessageResponseData genIssueCredentialStatusListResponse(String relatedEndEntity,PKIMessage request,
			CredentialStatusList credentialStatusList)
			throws IllegalArgumentException, MessageException {
		IssueCredentialStatusListRequest issueCredentialStatusListRequest = request.getPayload().getIssueCredentialStatusListRequest();
		if(issueCredentialStatusListRequest == null){
			throw new IllegalArgumentException("Error IssueCredentialStatusListResponse requires a IssueCredentialStatusListRequest in request payload.");
		}
		
		IssueCredentialStatusListResponse payload = objectFactory.createIssueCredentialStatusListResponse();
		populateSuccessfulResponse(payload, request);
		payload.setCredentialStatusList(credentialStatusList);
		PKIMessage pkiMessage = genPKIMessage(request.getVersion(),request.getName(),null, request.getSourceId(), request.getOrganisation(), getOriginatorFromRequest(request), payload);		
		byte[] responseData = marshallAndSignPKIMessage(pkiMessage);
		return new PKIMessageResponseData(pkiMessage.getID(),pkiMessage.getName(), relatedEndEntity, pkiMessage.getDestinationId(),responseData, true);
	}
	
	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#genIssueCredentialStatusListResponseWithoutRequest(String, String, CredentialStatusList)
	 */
	
	public PKIMessageResponseData genIssueCredentialStatusListResponseWithoutRequest(String relatedEndEntity, String destination, String name, String organisation,
			CredentialStatusList credentialStatusList, Credential originator)
			throws IllegalArgumentException, MessageException {
		String responseId = MessageGenerateUtils.generateRandomUUID();
		IssueCredentialStatusListResponse payload = objectFactory.createIssueCredentialStatusListResponse();
		payload.setFailureMessage(null);
		payload.setStatus(RequestStatus.SUCCESS);
		payload.setInResponseTo(responseId);
		payload.setCredentialStatusList(credentialStatusList);
		PKIMessage pkiMessage = genPKIMessage(defaultVersion,name,responseId, destination, organisation, originator, payload);		
		byte[] responseData = marshallAndSignPKIMessage(pkiMessage);
		return new PKIMessageResponseData(pkiMessage.getID(),pkiMessage.getName(), relatedEndEntity, pkiMessage.getDestinationId(),responseData, true);
	}
	
	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#genRemoveCredentialRequest(String, String, String, String)
	 */
	
	public byte[] genRemoveCredentialRequest(String requestId,String destinationId,String organisation, 
			String issuerId, String serialNumber, Credential originator)
			throws IllegalArgumentException, MessageException {
		RemoveCredentialRequest payload = objectFactory.createRemoveCredentialRequest();
		payload.setIssuerId(issuerId);
		payload.setSerialNumber(serialNumber);
		PKIMessage pkiMessage = genPKIMessage(defaultVersion, requestId, destinationId, organisation, originator, payload);		
		return marshallAndSignPKIMessage(pkiMessage);
	}

	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#genRemoveCredentialResponse(org.certificateservices.messages.pkimessages.jaxb.PKIMessage)
	 */
	
	public PKIMessageResponseData genRemoveCredentialResponse(String relatedEndEntity,PKIMessage request)
			throws IllegalArgumentException, MessageException {
		RemoveCredentialRequest removeCredentialRequest = request.getPayload().getRemoveCredentialRequest();
		if(removeCredentialRequest == null){
			throw new IllegalArgumentException("Error RemoveCredentialResponse requires a RemoveCredentialRequest in request payload.");
		}
		
		RemoveCredentialResponse payload = objectFactory.createRemoveCredentialResponse();
		populateSuccessfulResponse(payload, request);
		PKIMessage pkiMessage = genPKIMessage(request.getVersion(),request.getName(),null, request.getSourceId(), request.getOrganisation(), getOriginatorFromRequest(request), payload);		
		byte[] responseData = marshallAndSignPKIMessage(pkiMessage);
		return new PKIMessageResponseData(pkiMessage.getID(),pkiMessage.getName(), relatedEndEntity,pkiMessage.getDestinationId(),responseData);
	}

	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#genFetchHardTokenDataRequest(String, String, String, String, String, Credential)
	 */
	
	public byte[] genFetchHardTokenDataRequest(String requestId,String destinationId, String organisation,
			String tokenSerial, String relatedCredentialSerialNumber,
			String relatedCredentialIssuerId, Credential adminCredential, Credential originator)
			throws IllegalArgumentException, MessageException {
		FetchHardTokenDataRequest payload = objectFactory.createFetchHardTokenDataRequest();
		payload.setTokenSerial(tokenSerial);
		payload.setRelatedCredentialSerialNumber(relatedCredentialSerialNumber);
		payload.setRelatedCredentialIssuerId(relatedCredentialIssuerId);
		payload.setAdminCredential(adminCredential);
		PKIMessage pkiMessage = genPKIMessage(defaultVersion, requestId, destinationId, organisation, originator, payload);		
		return marshallAndSignPKIMessage(pkiMessage);
	}

	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#genFetchHardTokenDataResponse(org.certificateservices.messages.pkimessages.jaxb.PKIMessage, java.lang.String, byte[])
	 */
	
	public PKIMessageResponseData genFetchHardTokenDataResponse(String relatedEndEntity,PKIMessage request,
			String tokenSerial, byte[] encryptedData)
			throws IllegalArgumentException, MessageException {
		FetchHardTokenDataRequest fetchHardTokenDataRequest = request.getPayload().getFetchHardTokenDataRequest();
		if(fetchHardTokenDataRequest == null){
			throw new IllegalArgumentException("Error FetchHardTokenDataResponse requires a FetchHardTokenDataRequest in request payload.");
		}
		
		FetchHardTokenDataResponse payload = objectFactory.createFetchHardTokenDataResponse();
		populateSuccessfulResponse(payload, request);
		payload.setTokenSerial(tokenSerial);
		payload.setEncryptedData(encryptedData);
		PKIMessage pkiMessage = genPKIMessage(request.getVersion(),request.getName(),null,request.getSourceId(), request.getOrganisation(), getOriginatorFromRequest(request), payload);		
		byte[] responseData = marshallAndSignPKIMessage(pkiMessage);
		return new PKIMessageResponseData(pkiMessage.getID(),pkiMessage.getName(), relatedEndEntity,pkiMessage.getDestinationId(),responseData);
	}

	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#genStoreHardTokenDataRequest(String, String, String, String, String, byte[])
	 */
	
	public byte[] genStoreHardTokenDataRequest(String requestId, String destinationId, String organisation,
			String tokenSerial, String relatedCredentialSerialNumber,
			String relatedCredentialIssuerId, byte[] encryptedData, 
			Credential originator)
			throws IllegalArgumentException, MessageException {
		StoreHardTokenDataRequest payload = objectFactory.createStoreHardTokenDataRequest();
		payload.setTokenSerial(tokenSerial);
		payload.setRelatedCredentialSerialNumber(relatedCredentialSerialNumber);
		payload.setRelatedCredentialIssuerId(relatedCredentialIssuerId);
		payload.setEncryptedData(encryptedData);
		PKIMessage pkiMessage = genPKIMessage(defaultVersion, requestId,destinationId, organisation, originator, payload);		
		return marshallAndSignPKIMessage(pkiMessage);
	}

	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#genStoreHardTokenDataResponse(org.certificateservices.messages.pkimessages.jaxb.PKIMessage)
	 */
	
	public PKIMessageResponseData genStoreHardTokenDataResponse(String relatedEndEntity,PKIMessage request)
			throws IllegalArgumentException, MessageException {
		StoreHardTokenDataRequest storeHardTokenDataRequest = request.getPayload().getStoreHardTokenDataRequest();
		if(storeHardTokenDataRequest == null){
			throw new IllegalArgumentException("Error StoreHardTokenDataResponse requires a StoreHardTokenDataRequest in request payload.");
		}
		
		StoreHardTokenDataResponse payload = objectFactory.createStoreHardTokenDataResponse();
		populateSuccessfulResponse(payload, request);
		PKIMessage pkiMessage = genPKIMessage(request.getVersion(),request.getName(),null,request.getSourceId(), request.getOrganisation(), getOriginatorFromRequest(request), payload);		
		byte[] responseData = marshallAndSignPKIMessage(pkiMessage);
		return new PKIMessageResponseData(pkiMessage.getID(),pkiMessage.getName(), relatedEndEntity,pkiMessage.getDestinationId(),responseData);
	}





	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#genPKIResponse(org.certificateservices.messages.pkimessages.jaxb.PKIMessage, org.certificateservices.messages.pkimessages.jaxb.RequestStatus, java.lang.String)
	 */
	
	public PKIMessageResponseData genPKIResponse(String relatedEndEntity,byte[] request, RequestStatus status,
			String failureMessage, Credential originator) throws IllegalArgumentException,
			MessageException {

		return genPKIResponse(relatedEndEntity,request, status, failureMessage, null,originator);

	}
	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#genPKIResponse(org.certificateservices.messages.pkimessages.jaxb.PKIMessage, org.certificateservices.messages.pkimessages.jaxb.RequestStatus, java.lang.String, java.lang.String)
	 */
	
	public PKIMessageResponseData genPKIResponse(String relatedEndEntity,byte[] request, RequestStatus status,
			String failureMessage, String destinationID, Credential originator) throws IllegalArgumentException,
			MessageException {
		try {
			DocumentBuilder builder = XMLUtils.createDocumentBuilderFactory().newDocumentBuilder();
			Document doc = builder.parse(new ByteArrayInputStream(request));
			
    		Node pkiMessageNode = doc.getFirstChild();
    		String version=null;
    		if(pkiMessageNode != null){
    			Node versionNode = pkiMessageNode.getAttributes().getNamedItem("version");
    			if(versionNode != null){
    				version = versionNode.getNodeValue();
    			}
    		}  
    		if(version == null || version.trim().equals("")){
    			throw new IllegalArgumentException("Error unsupported protocol version when generating PKIResponse, version: " + version);
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

			XPathExpression expr = xpath.compile("//*[local-name()='PKIMessage']/@ID");
			Object result = expr.evaluate(doc, XPathConstants.STRING);			   
			String responseToRequestID = (String) result;

			expr = xpath.compile("//*[local-name()='organisation']/text()");
			result = expr.evaluate(doc, XPathConstants.STRING);;
			String organisation = (String) result;
			
			expr = xpath.compile("//*[local-name()='name']/text()");
			result = expr.evaluate(doc, XPathConstants.STRING);;
			String requestName = (String) result;
			
			if(organisation == null || responseToRequestID == null || destinationID == null || requestName==null){
				throw new IllegalArgumentException("Error generating PKI Message Response from request, due to missing fields organisation, sourceId, name or ID in request.");
			}
			
			PKIResponse payload = objectFactory.createPKIResponse();
			payload.setStatus(status);
			payload.setFailureMessage(failureMessage);
			payload.setInResponseTo(responseToRequestID);

			PKIMessage pkiMessage = genPKIMessage(version,requestName, null,destinationID, organisation, originator, payload);

			byte[] responseData = marshallAndSignPKIMessage(pkiMessage);
			return new PKIMessageResponseData(pkiMessage.getID(),pkiMessage.getName(), relatedEndEntity, pkiMessage.getDestinationId(),responseData, false );
		} catch (ParserConfigurationException e) {
			throw new MessageException("Error configuring the XML SAX Parser : " + e.getMessage());
		} catch (SAXException e) {
			throw new IllegalArgumentException("Error parsing request XML message: " + e.getMessage());
		} catch (IOException e) {
			throw new MessageException("Error reading the XML request data : " + e.getMessage());
		} catch (XPathExpressionException e) {
			throw new MessageException("Error constructing XPath expression when generating PKI Message responses : " + e.getMessage());
		}
	}
	
	/**
	 * @see org.certificateservices.messages.pkimessages.PKIMessageParser#getSigningCertificate(PKIMessage)	 
	 */	
	public X509Certificate getSigningCertificate(byte[] request)
			throws IllegalArgumentException, MessageException {
		X509Certificate retval = null;
		if(requireSignature()){
			try{
				DocumentBuilder builder = XMLUtils.createDocumentBuilderFactory().newDocumentBuilder();
				Document doc = builder.parse(new ByteArrayInputStream(request));

				XPathFactory factory = XPathFactory.newInstance();
				XPath xpath = factory.newXPath();
				
				XPathExpression expr = xpath.compile("//*[local-name()='KeyInfo']/*[local-name()='X509Data']/*[local-name()='X509Certificate']/text()");
				String result = (String) expr.evaluate(doc, XPathConstants.STRING);
				if(result != null && !result.equals("")){
					CertificateFactory cf = 
							CertificateFactory.getInstance("X.509");
					retval = (X509Certificate) 
							cf.generateCertificate(new ByteArrayInputStream(Base64.decode(result.getBytes())));					
				}
				
			}catch(CertificateException e){
				
			} catch (ParserConfigurationException e) {
				throw new MessageException("Error building XPath Expression when fetching signing certificate: " + e.getMessage(),e);
			} catch (SAXException e) {
				throw new IllegalArgumentException("Error reading signing certificate found in PKI Message request: " + e.getMessage(),e);
			} catch (IOException e) {
				throw new IllegalArgumentException("Error reading signing certificate found in PKI Message request: " + e.getMessage(),e);
			} catch (XPathExpressionException e) {
				throw new MessageException("Error building XPath Expression when fetching signing certificate: " + e.getMessage(),e);
			} catch (Base64DecodingException e) {
				throw new MessageException("Error reading signing certificate base 64 decoding exception: " + e.getMessage(),e);
			}
			
			
			if(retval == null){
				throw new IllegalArgumentException("Error, no signing certificate found in PKI Message request.");
			}			
	}
		return retval;
	}
	
	/**
	 * Method to return the default version.
	 * @return the version used to generate requests by default.
	 */
	public String getDefaultVersion(){
		return defaultVersion;
	}

	/**
	 * Method the set the version to set in generated requests.
	 * 
	 * @param defaultVersion the version.
	 */
	public void setDefaultVersion(String defaultVersion){
		this.defaultVersion = defaultVersion;
	}
	
	/**
	 * Method that populates all fields except the signature of a PKI message
	 * @param messageId the id of the message, if null is a random id generated.
	 * @param destinationID the destination Id to use.
	 * @param organisation the related organisation
	 * @param originator the originator of the message if applicable.
	 * @param payload the payload object to set in the object
	 * @throws IllegalArgumentException if input data contained invalid format.
	 * @throws MessageException if internal problems occurred processing the pki message.
	 */
	private PKIMessage genPKIMessage(String version, String messageId, String destinationID, String organisation, Credential originator, Object payload) throws IllegalArgumentException, MessageException{
		return genPKIMessage(version,null, messageId, destinationID, organisation, originator, payload);
	}
	
	/**
	 * Method that populates all fields except the signature of a PKI message.
	 * 
	 * @param requestName the name in the request, or null if no related request exists
	 * @param messageId the id of the message, if null is a random id generated.
	 * @param destinationID the destination Id to use.
	 * @param organisation the related organisation
	 * @param originator the originator of the message if applicable.
	 * @param payload the payload object to set in the object
	 * @throws IllegalArgumentException if input data contained invalid format.
	 * @throws MessageException if internal problems occurred processing the pki message.
	 */
	private PKIMessage genPKIMessage(String version, String requestName, String messageId, String destinationID, String organisation, Credential originator, Object payload) throws IllegalArgumentException, MessageException{
		PKIMessage retval = objectFactory.createPKIMessage();
		retval.setVersion(version);
		if(messageId == null){
		  retval.setID(MessageGenerateUtils.generateRandomUUID());
		}else{
		  retval.setID(messageId);
		}
		retval.setTimeStamp(PKIMessageGenerateUtils.dateToXMLGregorianCalendar(new Date()));
		retval.setName(messageNameCatalogue.lookupName(requestName, payload));
		retval.setDestinationId(destinationID);
		retval.setSourceId(sourceId);
		retval.setOrganisation(organisation);
		if(originator != null){
			Originator originatorElement = objectFactory.createOriginator();
			originatorElement.setCredential(originator);
		    retval.setOriginator(originatorElement);
		}
		retval.setPayload(getPayLoadObject(payload));
			
		return retval;
	}
	
	/**
	 * Message generating a Message.Payload object from a standalone payload object. 
	 * @param payload the payload object to create a message Payload for.
	 * @return a new PKIMessage.Payload instance with the payload object set.
	 * @throws MessageException 
	 */
	private Payload getPayLoadObject(Object payload) throws MessageException,IllegalArgumentException {
		
		try {
			Payload retval = new Payload();
			if(payload.getClass().getSimpleName().equals("PKIResponse")){
				retval.setFailureResponse((PKIResponse) payload);
			}else{
			  Method m = retval.getClass().getMethod("set" + payload.getClass().getSimpleName(), payload.getClass());
			  m.invoke(retval,payload);
			}
			return retval;
		} catch (NoSuchMethodException e) {
			throw new IllegalArgumentException("Invalid payload object: " + payload.getClass().getSimpleName() + ", " + e.getMessage(),e);
		} catch (SecurityException e) {
			throw new MessageException("Internal error populating payload object: " + e.getMessage(),e);
		} catch (IllegalAccessException e) {
			throw new MessageException("Internal error populating payload object: " + e.getMessage(),e);
		} catch (InvocationTargetException e) {
			throw new MessageException("Internal error populating payload object: " + e.getMessage(),e);
		}
		
	}

	/**
	 * Method that generates the signature and marshalls the message to byte array in UTF-8 format.
	 * @param pkiMessage the PKIMessage to sign and marshall, never null.
	 * @return a marshalled and signed message.
	 * @throws MessageException if problems occurred when processing the message.
	 */
	public synchronized byte[] marshallAndSignPKIMessage(PKIMessage pkiMessage) throws MessageException{
		if(pkiMessage == null){
			throw new MessageException("Error marshalling PKI Message, message cannot be null.");
		}

		try {
			Document doc = getDocumentBuilder().newDocument();		
			String version = pkiMessage.getVersion();
			getPKIMessageMarshaller(version).marshal(pkiMessage, doc);
			if(signMessages()){
	
				XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM",new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
				DigestMethod digestMethod = fac.newDigestMethod 
						("http://www.w3.org/2001/04/xmlenc#sha256", null);

				List<Transform> transFormList = new ArrayList<Transform>();
				transFormList.add(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));				
				Reference ref = fac.newReference("#" + pkiMessage.getID(),digestMethod, transFormList, null, null);

				ArrayList<Reference> refList = new ArrayList<Reference>();
				refList.add(ref);
				CanonicalizationMethod cm =  fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,(C14NMethodParameterSpec) null);
				SignatureMethod sm = fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",null);
				SignedInfo signedInfo =fac.newSignedInfo(cm,sm,refList);
				DOMSignContext signContext = null;
				signContext = new DOMSignContext(securityProvider.getSigningKey(),doc.getDocumentElement());

				signContext.setIdAttributeNS(doc.getDocumentElement(), null, "ID");
				
				KeyInfoFactory kif = KeyInfoFactory.getInstance("DOM",new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
				List<X509Certificate> certs = new ArrayList<X509Certificate>();
				X509Certificate cert = securityProvider.getSigningCertificate();
				certs.add(cert);
				X509Data x509Data = kif.newX509Data(certs);
				KeyInfo ki = kif.newKeyInfo(Collections.singletonList(x509Data)); 

				XMLSignature signature = fac.newXMLSignature(signedInfo,ki);
				signature.sign(signContext);

				org.w3c.dom.Node signatureElement = doc.getElementsByTagName("Signature").item(0);
				signatureElement.setPrefix("ds");
			}
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer transformer = tf.newTransformer();
			StringWriter writer = new StringWriter();
			transformer.transform(new DOMSource(doc), new StreamResult(writer));
			String output = writer.getBuffer().toString();	
			return output.getBytes("UTF-8");
		}catch (MessageProcessingException e) {
			throw new MessageException("Error marshalling PKI Message, " + e.getMessage(),e);
		}  catch (JAXBException e) {
			throw new MessageException("Error marshalling PKI Message, " + e.getMessage(),e);
		} catch (ParserConfigurationException e) {
			throw new MessageException("Error marshalling PKI Message, " + e.getMessage(),e);
		} catch (UnsupportedEncodingException e) {
			throw new MessageException("Error marshalling PKI Message, " + e.getMessage(),e);
		} catch (TransformerException e) {
			throw new MessageException("Error marshalling PKI Message, " + e.getMessage(),e);
		} catch (NoSuchAlgorithmException e) {
			throw new MessageException("Error signing the PKI Message, " + e.getMessage(),e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new MessageException("Error signing the PKI Message, " + e.getMessage(),e);
		} catch (MarshalException e) {
			throw new MessageException("Error signing the PKI Message, " + e.getMessage(),e);
		} catch (XMLSignatureException e) {
			throw new MessageException("Error signing the PKI Message, " + e.getMessage(),e);
		}
	}
	

	private DocumentBuilder getDocumentBuilder() throws ParserConfigurationException {
		return XMLUtils.createDocumentBuilderFactory().newDocumentBuilder();
	}
	
	
	private Boolean signMessages;
	private boolean signMessages() throws MessageException{
		if(signMessages == null){
			signMessages = PKISettingsUtils.parseBooleanWithDefault(properties, SETTING_SIGN, true);
		}
		return signMessages;
	}
	
	private Boolean requireSignature;
	private boolean requireSignature() throws MessageException{
		if(requireSignature == null){
			requireSignature = PKISettingsUtils.parseBooleanWithDefault(properties, SETTING_REQUIRESIGNATURE, true);
		}
		return requireSignature;
	}

	/**
	 * Help method that sets status to success and the in response to ID.
	 * @param response the response object to populate
	 * @param request the related request.
	 */
	private void populateSuccessfulResponse(
			PKIResponse response, PKIMessage request) {
		response.setFailureMessage(null);
		response.setStatus(RequestStatus.SUCCESS);
		response.setInResponseTo(request.getID());		
	}


	/**
	 * Method that generates a configured message name catalogue or uses the default
	 * one if not configured
	 * @param config the configuration.
	 * @return a newly generated MessageNameCatalogue
	 * @throws MessageException if problems occurred generating a MessageNameCatalogue
	 */
    private MessageNameCatalogue getMessageNameCatalogue(Properties config) throws MessageException{
    	try{
    		MessageNameCatalogue retval =  (MessageNameCatalogue) this.getClass().getClassLoader().loadClass(config.getProperty(SETTING_MESSAGE_NAME_CATALOGUE_IMPL, DEFAULT_MESSAGE_NAME_CATALOGUE_IMPL)).newInstance();
    		retval.init(config);
    		return retval;
    	}catch(Exception e){
    		throw new MessageException("Error creating creating name catalogue " + e.getClass().getName() + ": " + e.getMessage());
    	}
    }
    
    /**
     * Method that tries to parse the xml version from a message
     * @param messageData the messageData to extract version from.
     * @return the version in the version attribute of the message.
     * @throws IllegalArgumentException didn't contains a valid version attribute.
     * @throws MessageException if internal problems occurred.
     */
    private String getVersionFromMessage(byte[] messageData) throws IllegalArgumentException, MessageException{
    	String retval=null;
    	try{
    		Document doc = getDocumentBuilder().parse(new ByteArrayInputStream(messageData));
    		
    		Node pkiMessage = doc.getFirstChild();
    		if(pkiMessage != null){
    			Node versionNode = pkiMessage.getAttributes().getNamedItem("version");
    			if(versionNode != null){
    				retval = versionNode.getNodeValue();
    			}
    		}    		

    	}catch(Exception e){
    		throw new IllegalArgumentException("Error parsing XML data: " + e.getMessage(),e);
    	}

    	if(retval == null || retval.trim().equals("")){
    	  throw new IllegalArgumentException("Error no version attribute found in PKI Message.");
    	}
    	return retval;
    }
    
    /**
     * Method that returns a marshaller for a given version,
     * @param version the version of the PKI Message protocol to fetch.
     * @return related marshaller
     * @throws MessageException if problems occurred creating the PKI Message Marshaller for the given version.
     */
    private Marshaller getPKIMessageMarshaller(String version) throws MessageException{
    	if(version == null){
    		throw new IllegalArgumentException("Invalid PKI Message, version is missing.");
    	}
    	
    	Marshaller retval = pkixMessageMarshallers.get(version);
    	if(retval == null){
    		String schemaURL = pkiMessageSchemaUriMap.get(version);
    		try{
    			retval = createMarshaller(getJAXBContext(), schemaURL);
    			retval.setSchema(generatePKIMessageSchema(version)); 
    			pkixMessageMarshallers.put(version, retval);
    		}catch(Exception e){
    			throw new MessageException("Error creating XML Marshaller for PKI Message version: " + version, e);
    		}
    	}
    	return retval;
    	
    }
    
	public static Credential getOriginatorFromRequest(PKIMessage request) {
		Credential retval = null;
		if(request!= null && request.getOriginator() != null){
			retval = request.getOriginator().getCredential();
		}
		return retval;
	}
    
    /**
     * Method that returns a unmarshaller for a given version,
     * @param version the version of the PKI Message protocol to fetch.
     * @return related unmarshaller
     * @throws MessageException if problems occurred creating the PKI Message Marshaller for the given version.
     */
    private Unmarshaller getPKIMessageUnmarshaller(String version) throws MessageException{
    	if(version == null){
    		throw new IllegalArgumentException("Invalid PKI Message, version is missing.");
    	}
    	
    	Unmarshaller retval = pkixMessageUnmarshallers.get(version);
    	if(retval == null){
    		try{
    			retval = jaxbContext.createUnmarshaller();
    			retval.setSchema(generatePKIMessageSchema(version));
    			pkixMessageUnmarshallers.put(version, retval);
    		}catch(Exception e){
    			throw new MessageException("Error creating XML Unmarshaller for PKI Message version: " + version);
    		}
    	}
    	return retval;
    	
    }
    
    /**
     * Help method to generate a PKIMessage Schema for a given version.
     * @param version the version to look up.
     * @return
     * @throws IllegalArgumentException
     * @throws SAXException
     * @throws MessageException
     */
    private Schema generatePKIMessageSchema(String version) throws IllegalArgumentException, SAXException, MessageException{
    	String schemaLocation = pkiMessageSchemaMap.get(version);
		URL xsdURL = getClass().getResource(schemaLocation);
		SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
		URL xsdURL2 = getClass().getResource(XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION);
		String xsdContent = null;
		try {		
			InputStream resourceAsStream = xsdURL2.openStream();
			synchronized (resourceAsStream) {
				byte[] i = new byte[resourceAsStream.available()];
				resourceAsStream.read(i);
				xsdContent = new String(i);
			}
		} catch (IOException e) {
			throw new MessageException("Error reading DigSig XSD config");
		}
	    final String digSigXSD = xsdContent;
	    // A Custom resolver for the dig-sig XSD to avoid time-out resolving external resources using HTTP.
        schemaFactory.setResourceResolver(new LSResourceResolver() {
			
			
			public LSInput resolveResource(String type,
                    String namespaceURI,
                    String publicId,
                    String systemId,
                    String baseURI) {
				if(systemId.contains("xmldsig-core-schema.xsd")){						
					return new XSDLSInput(publicId, systemId, digSigXSD);
				}
				
				return null;
			}
		});        
        Schema schema = schemaFactory.newSchema(xsdURL);
        
        return schema;
    }
    
    /**
     * Help method maintaining the PKI Message JAXB Context.
     */
    private JAXBContext jaxbContext = null;
    private JAXBContext getJAXBContext() throws JAXBException{
    	if(jaxbContext== null){
    		jaxbContext = JAXBContext.newInstance("org.certificateservices.messages.pkimessages.jaxb");
    	}
    	return jaxbContext;
    }
    

}
