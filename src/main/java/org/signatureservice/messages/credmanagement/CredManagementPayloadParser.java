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
package org.signatureservice.messages.credmanagement;


import java.io.InputStream;
import java.util.Date;
import java.util.List;

import org.signatureservice.messages.MessageContentException;
import org.signatureservice.messages.MessageProcessingException;
import org.signatureservice.messages.credmanagement.jaxb.*;
import org.signatureservice.messages.credmanagement.jaxb.IssueTokenCredentialsRequest.FieldValues;
import org.signatureservice.messages.credmanagement.jaxb.IssueTokenCredentialsResponse.Credentials;
import org.signatureservice.messages.credmanagement.jaxb.IssueTokenCredentialsResponse.RevokedCredentials;
import org.signatureservice.messages.credmanagement.jaxb.ObjectFactory;
import org.signatureservice.messages.csmessages.BasePayloadParser;
import org.signatureservice.messages.csmessages.CSMessageResponseData;
import org.signatureservice.messages.csmessages.PayloadParser;
import org.signatureservice.messages.csmessages.jaxb.*;
import org.signatureservice.messages.utils.MessageGenerateUtils;

/**
 * Payload Parser for generating Credential Management messages according to 
 * credmanagement_schema2_0.xsd
 * 
 * @author Philip Vendil
 *
 */
public class CredManagementPayloadParser extends BasePayloadParser {
	
	public static String NAMESPACE = "http://certificateservices.org/xsd/credmanagement2_0";
	
	public static final String CREDMANAGEMENT_XSD_SCHEMA_2_0_RESOURCE_LOCATION = "/credmanagement_schema2_0.xsd";
	public static final String CREDMANAGEMENT_XSD_SCHEMA_2_1_RESOURCE_LOCATION = "/credmanagement_schema2_1.xsd";
	public static final String CREDMANAGEMENT_XSD_SCHEMA_2_2_RESOURCE_LOCATION = "/credmanagement_schema2_2.xsd";
	public static final String CREDMANAGEMENT_XSD_SCHEMA_2_3_RESOURCE_LOCATION = "/credmanagement_schema2_3.xsd";
	public static final String CREDMANAGEMENT_XSD_SCHEMA_2_4_RESOURCE_LOCATION = "/credmanagement_schema2_4.xsd";

	private ObjectFactory of = new ObjectFactory();


	private static final String CREDMANAGEMENT_VERSION_2_0 = "2.0";
	private static final String CREDMANAGEMENT_VERSION_2_1 = "2.1";
	private static final String CREDMANAGEMENT_VERSION_2_2 = "2.2";
	private static final String CREDMANAGEMENT_VERSION_2_3 = "2.3";
	private static final String CREDMANAGEMENT_VERSION_2_4 = "2.4";

	private static final String[] SUPPORTED_CREDMANAGEMENT_VERSIONS = {CREDMANAGEMENT_VERSION_2_0,CREDMANAGEMENT_VERSION_2_1,
			CREDMANAGEMENT_VERSION_2_2,CREDMANAGEMENT_VERSION_2_3,CREDMANAGEMENT_VERSION_2_4};

	private static final String DEFAULT_CREDMANAGEMENT_VERSION = CREDMANAGEMENT_VERSION_2_4;
	
	
	/**
	 * @see PayloadParser#getJAXBPackage()
	 */
	public String getJAXBPackage() {
		return "org.signatureservice.messages.credmanagement.jaxb";
	}

	/**
	 * @see PayloadParser#getNameSpace()
	 */
	public String getNameSpace() {
		return NAMESPACE;
	}

	/**
	 * @see PayloadParser#getSchemaAsInputStream(String)
	 */
	public InputStream getSchemaAsInputStream(String payLoadVersion)
			throws MessageContentException, MessageProcessingException {
    	if(payLoadVersion.equals("2.0")){
    		return getClass().getResourceAsStream(CREDMANAGEMENT_XSD_SCHEMA_2_0_RESOURCE_LOCATION);
    	}
		if(payLoadVersion.equals("2.1")){
			return getClass().getResourceAsStream(CREDMANAGEMENT_XSD_SCHEMA_2_1_RESOURCE_LOCATION);
		}
		if(payLoadVersion.equals("2.2")){
			return getClass().getResourceAsStream(CREDMANAGEMENT_XSD_SCHEMA_2_2_RESOURCE_LOCATION);
		}
		if(payLoadVersion.equals("2.3")){
			return getClass().getResourceAsStream(CREDMANAGEMENT_XSD_SCHEMA_2_3_RESOURCE_LOCATION);
		}
		if(payLoadVersion.equals("2.4")){
			return getClass().getResourceAsStream(CREDMANAGEMENT_XSD_SCHEMA_2_4_RESOURCE_LOCATION);
		}
    	
    	throw new MessageContentException("Error unsupported Credential Management Payload version: " + payLoadVersion);
	}
	
	/**
	 * @see BasePayloadParser#getSupportedVersions()
	 */
	@Override
	protected String[] getSupportedVersions() {
		return SUPPORTED_CREDMANAGEMENT_VERSIONS;
	}

	/**
	 * @see BasePayloadParser#getDefaultPayloadVersion()
	 */
	@Override
	protected String getDefaultPayloadVersion() {
		return DEFAULT_CREDMANAGEMENT_VERSION;
	}


	/**
	 * Method to a IssueTokenCredentialRequest message and populating it with the tokenRequest.
	 *
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param tokenRequest the tokenRequest to add to the CSRequest.
	 * @param fieldValues containing complementary input data to the request. Can be null if no complementary data is available.
	 * @param hardTokenData related hard token data to be stored in encrypted storage. Null if not applicable
	 * @param originator the original requester of a message, null if not applicable
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return generated and signed CSMessage in byte[] format.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genIssueTokenCredentialsRequest(String requestId, String destinationId, String organisation, TokenRequest tokenRequest, List<FieldValue> fieldValues, HardTokenData hardTokenData, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		return genIssueTokenCredentialsRequest(requestId,destinationId,organisation,tokenRequest,fieldValues,hardTokenData,null,originator,assertions);
	}

	/**
	 * Method to a IssueTokenCredentialRequest message and populating it with the tokenRequest.
	 * 
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param tokenRequest the tokenRequest to add to the CSRequest.
	 * @param fieldValues containing complementary input data to the request. Can be null if no complementary data is available.
	 * @param hardTokenData related hard token data to be stored in encrypted storage. Null if not applicable
	 * @param recoverableKeys a list of keys that should be stored in backed for later recovery in case token is lost.
	 * @param originator the original requester of a message, null if not applicable
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return generated and signed CSMessage in byte[] format.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genIssueTokenCredentialsRequest(String requestId, String destinationId, String organisation, TokenRequest tokenRequest, List<FieldValue> fieldValues, HardTokenData hardTokenData, List<RecoverableKey> recoverableKeys, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		IssueTokenCredentialsRequest payload = of.createIssueTokenCredentialsRequest();
		payload.setTokenRequest(tokenRequest);
		
		if(fieldValues != null && fieldValues.size() > 0){
			FieldValues values = new IssueTokenCredentialsRequest.FieldValues();
			values.getFieldValue().addAll(fieldValues);
			
			payload.setFieldValues(values);
		}

		if(hardTokenData != null){
			payload.setHardTokenData(hardTokenData);
		}

		if(recoverableKeys != null) {
			IssueTokenCredentialsRequest.RecoverableKeys rks = of.createIssueTokenCredentialsRequestRecoverableKeys();
			rks.getKey().addAll(recoverableKeys);
			payload.setRecoverableKeys(rks);
		}
		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * Method to a IssueTokenCredentialResponse message and populating it with the tokenRequest and the
	 * generated responses.
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param credentials the credentials to populate the response with.
	 * @param revokedCredentials credentials revoked in the operation or null, if no credentials where revoked.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genIssueTokenCredentialsResponse(String relatedEndEntity, CSMessage request, List<Credential> credentials, List<Credential> revokedCredentials, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		IssueTokenCredentialsResponse response = of.createIssueTokenCredentialsResponse();
		if(request.getPayload().getAny() instanceof IssueTokenCredentialsRequest){
			IssueTokenCredentialsRequest requestPayLoad = (IssueTokenCredentialsRequest) request.getPayload().getAny();
			response.setTokenRequest(requestPayLoad.getTokenRequest());
		}else{
			throw new MessageContentException("Error generating IssueTokenCredentialsResponse, related request not a IssueTokenCredentialsResponse");
		}
		
		Credentials credentialsElement = new IssueTokenCredentialsResponse.Credentials();
		credentialsElement.getCredential().addAll(credentials);
		response.setCredentials(credentialsElement);
		
		if(revokedCredentials != null && revokedCredentials.size() > 0){
			RevokedCredentials revokedCredElements = new IssueTokenCredentialsResponse.RevokedCredentials();
			revokedCredElements.getCredential().addAll(revokedCredentials);
			response.setRevokedCredentials(revokedCredElements);
		}
		
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response, true);
	}
	
	/**
	 * Method to generate a ChangeCredentialStatusRequest
	 * 
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @param serialNumber The serial number of the credential in hexadecimal encoding lowercase (for X509 certificates).
	 * @param newCredentialStatus The new credential status to set.
	 * @param reasonInformation More detailed information about the revocation status
	 * @param originator the original requester of a message, null if not applicable
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genChangeCredentialStatusRequest(String requestId, String destinationId, String organisation, String issuerId, String serialNumber, int newCredentialStatus, String reasonInformation, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		ChangeCredentialStatusRequest payload = of.createChangeCredentialStatusRequest();
		payload.setIssuerId(issuerId);
		payload.setSerialNumber(serialNumber);
		payload.setNewCredentialStatus(newCredentialStatus);
		payload.setReasonInformation(reasonInformation);
		
		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * Method to generate a ChangeCredentialStatusResponse
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @param serialNumber The serial number of the credential in hexadecimal encoding lowercase (for X509 certificates).
	 * @param credentialStatus the resulted credential status of the request
	 * @param reasonInformation More detailed information about the revocation status
	 * @param revocationDate the timestamp when the credential was revoked.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genChangeCredentialStatusResponse(String relatedEndEntity, CSMessage request, String issuerId, String serialNumber, int credentialStatus, String reasonInformation, Date revocationDate, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		ChangeCredentialStatusResponse response = of.createChangeCredentialStatusResponse();
		response.setCredentialStatus(credentialStatus);
		response.setIssuerId(issuerId);
		response.setSerialNumber(serialNumber);
		response.setReasonInformation(reasonInformation);
		response.setRevocationDate(MessageGenerateUtils.dateToXMLGregorianCalendar(revocationDate));
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response, true);
	}

	/**
	 * Method to generate a ChangeUserStatusRequest
	 *
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param userUniqueId The unique id of the user to revoke credentials for.
	 * @param tokenFilter The token filter specifying a filter for a which credentials in the users token that should
	 *                    be revoked. Optional if null is all credentials for all tokens revoked (matching credential filter).
	 * @param credentialFilter The credential filter used to specify which matching credentials that should be revoked.
	 *                         Optional if null is all credentials for all tokens revoked (matching optional token filter).
	 * @param newCredentialStatus The new credential status to set.
	 * @param reasonInformation More detailed information about the revocation status
	 * @param originator the original requester of a message, null if not applicable
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genChangeUserStatusRequest(String requestId, String destinationId, String organisation, String userUniqueId, TokenFilter tokenFilter, CredentialFilter credentialFilter, int newCredentialStatus, String reasonInformation, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		ChangeUserStatusRequest payload = of.createChangeUserStatusRequest();
		payload.setUserUniqueId(userUniqueId);
		payload.setTokenFilter(tokenFilter);
		payload.setCredentialFilter(credentialFilter);
		payload.setNewCredentialStatus(newCredentialStatus);
		payload.setReasonInformation(reasonInformation);

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}

	/**
	 * Method to generate a ChangeUserStatusResponse
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param user The related user with updated token and credential information.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genChangeUserStatusResponse(String relatedEndEntity, CSMessage request, User user, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		ChangeUserStatusResponse response = of.createChangeUserStatusResponse();
		response.setUser(user);
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response, true);
	}

	/**
	 * Method to generate a ChangeTokenStatusRequest
	 *
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param tokenSerialNumber The unique serial number within the organisation.
	 * @param credentialFilter The credential filter used to specify which matching credentials that should be revoked.
	 *                         Optional if null is all credentials for all tokens revoked (matching optional token filter).
	 * @param newCredentialStatus The new credential status to set.
	 * @param reasonInformation More detailed information about the revocation status
	 * @param originator the original requester of a message, null if not applicable
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genChangeTokenStatusRequest(String requestId, String destinationId, String organisation, String tokenSerialNumber,  CredentialFilter credentialFilter, int newCredentialStatus, String reasonInformation, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		ChangeTokenStatusRequest payload = of.createChangeTokenStatusRequest();
		payload.setTokenSerialNumber(tokenSerialNumber);
		payload.setCredentialFilter(credentialFilter);
		payload.setNewCredentialStatus(newCredentialStatus);
		payload.setReasonInformation(reasonInformation);

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}

	/**
	 * Method to generate a ChangeTokenStatusResponse
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param token The related token with updated credential information.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genChangeTokenStatusResponse(String relatedEndEntity, CSMessage request, Token token, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		ChangeTokenStatusResponse response = of.createChangeTokenStatusResponse();
		response.setToken(token);
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response, true);
	}

	/**
	 * Method to generate a GetCredentialRequest
	 * 
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param credentialSubType the credential sub type of the credential.
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @param serialNumber The serial number of the credential in hexadecimal encoding lowercase (for X509 certificates).
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genGetCredentialRequest(String requestId, String destinationId, String organisation, String credentialSubType, String issuerId, String serialNumber, Credential originator, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		GetCredentialRequest payload = of.createGetCredentialRequest();
		payload.setIssuerId(issuerId);
		payload.setCredentialSubType(credentialSubType);
		payload.setSerialNumber(serialNumber);
		
		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * Method to generate a GetCredentialResponse
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param credential the matching credential of the issued id and serial number
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genGetCredentialResponse(String relatedEndEntity, CSMessage request, Credential credential, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		GetCredentialResponse response = of.createGetCredentialResponse();
		response.setCredential(credential);
		
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}
	
	/**
	 * Method to generate a GetCredentialStatusListRequest
	 * 
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @param serialNumber The number of the credential status list in the request (Optional)
	 * @param credentialStatusListType The type of status list to fetch
	 * @param originator the original requester of a message, null if not applicable.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genGetCredentialStatusListRequest(String requestId, String destinationId, String organisation, String issuerId, Long serialNumber, String credentialStatusListType, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		GetCredentialStatusListRequest payload = of.createGetCredentialStatusListRequest();
		payload.setIssuerId(issuerId);
		payload.setCredentialStatusListType(credentialStatusListType);
		payload.setSerialNumber(serialNumber);
		
		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * Method to generate a GetCredentialStatusListResponse
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param credentialStatusList the matching credential status list
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genGetCredentialStatusListResponse(String relatedEndEntity, CSMessage request, CredentialStatusList credentialStatusList, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		GetCredentialStatusListResponse response = of.createGetCredentialStatusListResponse();
		response.setCredentialStatusList(credentialStatusList);
		
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}
	
	/**
	 * Method to generate a GetIssuerCredentialsRequest
	 * 
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genGetIssuerCredentialsRequest(String requestId, String destinationId, String organisation, String issuerId, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		GetIssuerCredentialsRequest payload = of.createGetIssuerCredentialsRequest();
		payload.setIssuerId(issuerId);
		
		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * Method to generate a GetIssuerCredentialsResponse
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param issuerCredential the issuers credential
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genGetIssuerCredentialsResponse(String relatedEndEntity, CSMessage request, Credential issuerCredential, List<Object> assertions)throws MessageContentException, MessageProcessingException{
		GetIssuerCredentialsResponse response = of.createGetIssuerCredentialsResponse();
		response.setCredential(issuerCredential);
		
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}
	
	/**
	 * Method to generate a IsIssuerRequest
	 * 
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genIsIssuerRequest(String requestId, String destinationId, String organisation, String issuerId, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		IsIssuerRequest payload = of.createIsIssuerRequest();
		payload.setIssuerId(issuerId);
		
		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * Method to generate a IsIssuerResponse
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param isIssuer indicating if current server is issuer or not
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genIsIssuerResponse(String relatedEndEntity, CSMessage request, boolean isIssuer, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		IsIssuerResponse response = of.createIsIssuerResponse();
		response.setIsIssuer(isIssuer);
		
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}
	
	/**
	 * Method to generate a IssueCredentialStatusListRequest
	 * 
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @param credentialStatusListType The type of status list to fetch
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException
	 * @throws MessageProcessingException
	 */
	public byte[] genIssueCredentialStatusListRequest(String requestId, String destinationId, String organisation, String issuerId, String credentialStatusListType, Boolean force, Date requestedValidFromDate, Date requestedNotAfterDate, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		IssueCredentialStatusListRequest payload = of.createIssueCredentialStatusListRequest();
		payload.setIssuerId(issuerId);
		payload.setCredentialStatusListType(credentialStatusListType);
		payload.setForce(force);
		payload.setRequestedValidFromDate(MessageGenerateUtils.dateToXMLGregorianCalendar(requestedValidFromDate));
		payload.setRequestedNotAfterDate(MessageGenerateUtils.dateToXMLGregorianCalendar(requestedNotAfterDate));
		
		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * Method to generate a IssueCredentialStatusListResponse
	 * 
     * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param credentialStatusList the new credential status list
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genIssueCredentialStatusListResponse(String relatedEndEntity,CSMessage request, CredentialStatusList credentialStatusList, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		IssueCredentialStatusListResponse response = of.createIssueCredentialStatusListResponse();
		response.setCredentialStatusList(credentialStatusList);
		
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response, true);
	}
	
	/**
	 * Method to generate a IssueCredentialStatusListResponse where there are no request, such 
	 * as scheduled CRL issuing.
     *
     * @param csMessageVersion the version of the CS Message Core protocol.
     * @param payLoadVersion the version of the credential management pay load protocol.
     * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param destinationId the destination of the response set in the CS message.
	 * @param requestName the name of the request message this response whould normally reply to.
	 * @param organisation the organisation set in the response message.
	 * @param credentialStatusList the new credential status list
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genIssueCredentialStatusListResponseWithoutRequest(String csMessageVersion, String payLoadVersion, String relatedEndEntity, String destinationId, String requestName, String organisation, CredentialStatusList credentialStatusList, Credential originator, List<Object> assertions)throws MessageContentException, MessageProcessingException{
		String responseId = MessageGenerateUtils.generateRandomUUID();
		
		IssueCredentialStatusListResponse response = of.createIssueCredentialStatusListResponse();
		response.setCredentialStatusList(credentialStatusList);
		response.setFailureMessage(null);
		response.setStatus(RequestStatus.SUCCESS);
		response.setInResponseTo(responseId);

		CSMessage csMessage = getCSMessageParser().genCSMessage(csMessageVersion, payLoadVersion,requestName,responseId, destinationId, organisation, originator, response, assertions);
		byte[] responseData = getCSMessageParser().marshallAndSignCSMessage(csMessage);
		return new CSMessageResponseData(csMessage, relatedEndEntity, responseData, true);
		
	}
	
	/**
	 * Method to generate a RemoveCredentialRequest
	 * 
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @param serialNumber The serial number of the credential in hexadecimal encoding lowercase (for X509 certificates).
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genRemoveCredentialRequest(String requestId, String destinationId, String organisation, String issuerId, String serialNumber, Credential originator, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		RemoveCredentialRequest payload = of.createRemoveCredentialRequest();
		payload.setIssuerId(issuerId);
		payload.setSerialNumber(serialNumber);
		
		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * Method to generate a RemoveCredentialResponse
	 *  
     * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genRemoveCredentialResponse(String relatedEndEntity, CSMessage request, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		RemoveCredentialResponse response = of.createRemoveCredentialResponse();
		
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response, true);
	}
	
	/**
	 * Method to generate a FetchHardTokenDataRequest
	 * 
     * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param tokenSerial The unique serial number of the hard token within the organisation
	 * @param relatedCredentialIssuerId The unique id of the issuer of the related credential, usually the subject DN name of the issuer.
	 * @param adminCredential the credential of the requesting card administrator that need the hard token data. The response data is encrypted with this administrator as recipient.
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genFetchHardTokenDataRequest(String requestId, String destinationId, String organisation, String tokenSerial, String relatedCredentialIssuerId, Credential adminCredential, Credential originator, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		FetchHardTokenDataRequest payload = of.createFetchHardTokenDataRequest();
		payload.setTokenSerial(tokenSerial);
		payload.setRelatedCredentialIssuerId(relatedCredentialIssuerId);
		payload.setAdminCredential(adminCredential);

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), of.createFetchHardTokenDataRequest(payload), originator, assertions);
	}

	/**
	 * Method to generate a FetchHardTokenDataResponse
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request this message is a response to.
	 * @param tokenSerial The unique serial number of the hard token within the organisation.
	 * @param encryptedData The token data encrypted with the token administrators credential sent in the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genFetchHardTokenDataResponse(String relatedEndEntity, CSMessage request, String tokenSerial, byte[] encryptedData, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		FetchHardTokenDataResponse response = of.createFetchHardTokenDataResponse();
		response.setTokenSerial(tokenSerial);
		response.setEncryptedData(encryptedData);
		
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), of.createFetchHardTokenDataResponse(response));
	}

	/**
	 * Method to generate a RecoverHardTokenDataRequest
	 *
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param tokenSerial The unique serial number of the hard token within the organisation
	 * @param relatedCredentialIssuerId The unique id of the issuer of the related credential, usually the subject DN name of the issuer.
	 * @param adminCredential the credential of the requesting card administrator that need the hard token data. The response data is encrypted with this administrator as recipient.
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genRecoverHardTokenRequest(String requestId, String destinationId, String organisation, String tokenSerial, String relatedCredentialIssuerId, Credential adminCredential, Credential originator, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		FetchHardTokenDataRequest payload = of.createFetchHardTokenDataRequest();
		payload.setTokenSerial(tokenSerial);
		payload.setRelatedCredentialIssuerId(relatedCredentialIssuerId);
		payload.setAdminCredential(adminCredential);

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), of.createRecoverHardTokenRequest(payload), originator, assertions);
	}

	/**
	 * Method to generate a RecoverHardTokenResponse
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request this message is a response to.
	 * @param tokenSerial The unique serial number of the hard token within the organisation.
	 * @param encryptedData The token data encrypted with the token administrators credential sent in the request.
	 * @param keys list of encrypted keys recovered from frontend system.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genRecoverHardTokenResponse(String relatedEndEntity, CSMessage request, String tokenSerial, byte[] encryptedData, List<Key> keys, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		RecoverHardTokenResponse response = of.createRecoverHardTokenResponse();
		response.setTokenSerial(tokenSerial);
		response.setEncryptedData(encryptedData);
		RecoverHardTokenResponse.RecoveredKeys rk = of.createRecoverHardTokenResponseRecoveredKeys();
		rk.getKey().addAll(keys);
		response.setRecoveredKeys(rk);

		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}
	
	/**
	 * Method to generate a StoreHardTokenDataRequest
	 * 
     * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param tokenSerial The unique serial number of the hard token within the organisation
	 * @param relatedCredentialIssuerId The unique id of the issuer of the related credential, usually the subject DN name of the issuer.
	 * @param encryptedData The token data encrypted with a credential provided out-of-bands by the CS administrator to protect the data during transport.
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genStoreHardTokenDataRequest(String requestId, String destinationId, String organisation, String tokenSerial, String relatedCredentialIssuerId, byte[] encryptedData, Credential originator, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		StoreHardTokenDataRequest payload = of.createStoreHardTokenDataRequest();
		payload.setTokenSerial(tokenSerial);
		payload.setRelatedCredentialIssuerId(relatedCredentialIssuerId);
		payload.setEncryptedData(encryptedData);
		
		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}
	
	
	/**
	 * Method to generate a StoreHardTokenDataResponse
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request this message is a response to.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genStoreHardTokenDataResponse(String relatedEndEntity, CSMessage request, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		StoreHardTokenDataResponse response = of.createStoreHardTokenDataResponse();
		
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}
	

	/**
	 * Method to generate a GetTokensRequest without pagination used in 2.0 protocol
	 * 
     * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param serialNumber The unique serial number of the hard token within the organisation, complete or part of the serial number
	 * @param exactMatch If only exactly matching tokens should be fetched. 
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genGetTokensRequest(String requestId, String destinationId, String organisation, String serialNumber, boolean exactMatch,  Credential originator, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		return genGetTokensRequest(requestId,destinationId,organisation,serialNumber,exactMatch,null,null,originator,assertions);
	}

	/**
	 * Method to generate a GetTokensRequest with pagination support (2.1)
	 *
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param serialNumber The unique serial number of the hard token within the organisation, complete or part of the serial number
	 * @param exactMatch If only exactly matching tokens should be fetched.
	 * @param startIndex the index to fetch the resulting user data.
	 * @param resultSize the maximum number of entries to return, should not be larger that the maximum setting in server.
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genGetTokensRequest(String requestId, String destinationId, String organisation, String serialNumber, boolean exactMatch, Integer startIndex, Integer resultSize, Credential originator, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		GetTokensRequest payload = of.createGetTokensRequest();
		payload.setSerialNumber(serialNumber);
		payload.setExactMatch(exactMatch);
		payload.setStartIndex(startIndex);
		payload.setResultSize(resultSize);

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}


	
	/**
	 * Method to generate a GetTokensResponse, used for 2.0 messages.
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request this message is a response to.
	 * @param tokens a list of matching tokens, never null.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genGetTokensResponse(String relatedEndEntity, CSMessage request, List<Token> tokens, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		return genGetTokensResponse(relatedEndEntity,request,tokens,null,null,assertions);
	}


	/**
	 * Method to generate a GetTokensResponse used for pagination (pagination elements are only populated if request is 2.1 or above
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request this message is a response to.
	 * @param tokens a list of matching tokens, never null.
	 * @param startIndex the start index of the page in the result set. Is only set if request is 2.1 or above
	 * @param totalMatching the total matching users in query. Is only set if request is 2.1 or above
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genGetTokensResponse(String relatedEndEntity, CSMessage request, List<Token> tokens, Integer startIndex, Integer totalMatching, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		GetTokensResponse response = of.createGetTokensResponse();
		GetTokensResponse.Tokens tokensElement = new GetTokensResponse.Tokens();
		for(Token t : tokens){
			tokensElement.getToken().add(t);
		}

		response.setTokens(tokensElement);
		if(!request.getPayLoadVersion().equals(CREDMANAGEMENT_VERSION_2_0)){
			response.setStartIndex(startIndex);
			response.setTotalMatching(totalMatching);
		}else{
			// if protocol is 2.0 should departmentName be removed.
			for(Token token: tokens){
				token.setDepartmentName(null);
			}
		}

		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}


	
	/**
	 * Method to generate a GetUsersRequest without pagination used in 2.0 protocol
	 * 
     * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param uniqueId The unique id of the user within the organisation, complete or part of the unique id to search for
	 * @param exactMatch If only exactly matching tokens should be fetched. 
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genGetUsersRequest(String requestId, String destinationId, String organisation, String uniqueId, boolean exactMatch,  Credential originator, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		return genGetUsersRequest(requestId,destinationId,organisation,uniqueId,exactMatch,null,null,originator,assertions);
	}

	/**
	 * Method to generate a GetUsersRequest with pagination support (2.1)
	 *
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param uniqueId The unique id of the user within the organisation, complete or part of the unique id to search for
	 * @param exactMatch If only exactly matching tokens should be fetched.
	 * @param startIndex the index to fetch the resulting user data.
	 * @param resultSize the maximum number of entries to return, should not be larger that the maximum setting in server.
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genGetUsersRequest(String requestId, String destinationId, String organisation, String uniqueId, boolean exactMatch, Integer startIndex, Integer resultSize, Credential originator, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		GetUsersRequest payload = of.createGetUsersRequest();
		payload.setUniqueId(uniqueId);
		payload.setExactMatch(exactMatch);
		payload.setStartIndex(startIndex);
		payload.setResultSize(resultSize);

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}
	
	
	/**
	 * Method to generate a GetUsersResponse, used for 2.0 messages.
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request this message is a response to.
	 * @param users a list of matching users, never null.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genGetUsersResponse(String relatedEndEntity, CSMessage request, List<User> users, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		return genGetUsersResponse(relatedEndEntity,request,users,null,null,assertions);
	}

	/**
	 * Method to generate a GetUsersResponse used for pagination (pagination elements are only populated if request is 2.1 or above
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request this message is a response to.
	 * @param users a list of matching users, never null.
	 * @param startIndex the start index of the page in the result set. Is only set if request is 2.1 or above
	 * @param totalMatching the total matching users in query. Is only set if request is 2.1 or above
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genGetUsersResponse(String relatedEndEntity, CSMessage request, List<User> users, Integer startIndex, Integer totalMatching, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		GetUsersResponse response = of.createGetUsersResponse();
		GetUsersResponse.Users usersElement = new GetUsersResponse.Users();
		for(User u : users){
			usersElement.getUser().add(u);
		}

		response.setUsers(usersElement);
		if(!request.getPayLoadVersion().equals(CREDMANAGEMENT_VERSION_2_0)){
			response.setStartIndex(startIndex);
			response.setTotalMatching(totalMatching);
		}else{
			// if protocol is 2.0 should departmentName be removed.
			for(User u : users){
				if(u.getTokens() != null) {
					for (Token t : u.getTokens().getToken()) {
						t.setDepartmentName(null);
					}
				}
			}
		}

		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}


	/**
	 * Method to generate a GetEjbcaUserCredentialsRequest with pagination support (2.4)
	 *
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param ejbcaUsername The unique and full EJBCA Username to fetch certificate for.
	 *
	 * @param startIndex the index to fetch the resulting user data.
	 * @param resultSize the maximum number of entries to return, should not be larger that the maximum setting in server.
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genGetEjbcaUserCredentialsRequest(String requestId, String destinationId, String organisation, String ejbcaUsername,
									 Integer startIndex, Integer resultSize, Credential originator, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		GetEjbcaUserCredentialsRequest payload = of.createGetEjbcaUserCredentialsRequest();
		payload.setEjbcaUsername(ejbcaUsername);
		payload.setStartIndex(startIndex);
		payload.setResultSize(resultSize);

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}

	/**
	 * Method to generate a GetUsersResponse used for pagination (pagination elements are only populated if request is 2.1 or above
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request this message is a response to.
	 * @param credentials a list of matching credentials issued for related EJBCA User.
	 * @param startIndex the start index of the page in the result set. Is only set if request is 2.1 or above
	 * @param totalMatching the total matching users in query. Is only set if request is 2.1 or above
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genGetEjbcaUserCredentialsResponse(String relatedEndEntity, CSMessage request, List<Credential> credentials, Integer startIndex, Integer totalMatching, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		GetEjbcaUserCredentialsResponse response = of.createGetEjbcaUserCredentialsResponse();
		GetEjbcaUserCredentialsResponse.Credentials credentialsElement = of.createGetEjbcaUserCredentialsResponseCredentials();
		credentialsElement.getCredential().addAll(credentials);
		response.setCredentials(credentialsElement);
		response.setStartIndex(startIndex);
		response.setTotalMatching(totalMatching);

		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}

	/**
	 * Method to generate a RecoverKeyRequest
	 *
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param adminCredential the admin credential to encrypt the key store data to.
	 * @param relatedCredentials the credentials pointing out which keys should be recovered from frontend store.
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genRecoverKeyRequest(String requestId, String destinationId, String organisation, Credential adminCredential, List<Credential> relatedCredentials,  Credential originator, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		RecoverKeyRequest payload = of.createRecoverKeyRequest();
		payload.setAdminCredential(adminCredential);
		RecoverKeyRequest.RelatedCredentials rc = of.createRecoverKeyRequestRelatedCredentials();
		rc.getCredential().addAll(relatedCredentials);
		payload.setRelatedCredentials(rc);


		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}

	/**
	 * Method to generate a RecoverKeyResponse
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request this message is a response to.
	 * @param keys a list of recovered keys, never null.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genRecoverKeyResponse(String relatedEndEntity, CSMessage request, List<Key> keys, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		RecoverKeyResponse response = of.createRecoverKeyResponse();
		RecoverKeyResponse.RecoveredKeys rk = of.createRecoverKeyResponseRecoveredKeys();
		rk.getKey().addAll(keys);
		response.setRecoveredKeys(rk);

		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}

	/**
	 * Method to generate a StoreKeyRequest
	 *
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param keys a list en encrypted keys to store in frontend system.
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genStoreKeyRequest(String requestId, String destinationId, String organisation, List<Key> keys,  Credential originator, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		StoreKeyRequest payload = of.createStoreKeyRequest();
		StoreKeyRequest.RecoverableKeys rk = of.createStoreKeyRequestRecoverableKeys();
		rk.getKey().addAll(keys);
		payload.setRecoverableKeys(rk);

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}

	/**
	 * Method to generate a StoreKeyResponse
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request this message is a response to.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genStoreKeyResponse(String relatedEndEntity, CSMessage request, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		StoreKeyResponse response = of.createStoreKeyResponse();

		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}

	/**
	 * Method to generate a GetCredentialAvailableActionsRequest to get available renewal action available
	 * for a given certificate.
	 *
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param issuerId The unique id of the issuer, usually the subject DN name of the issuer.
	 * @param serialNumber The serial number of the credential in hexadecimal encoding lowercase (for X509 certificates).
	 * @param locale the locale in BCP 47 string, i.e en or en_GB or se_SV
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genGetCredentialAvailableActionsRequest(String requestId, String destinationId, String organisation, String issuerId, String serialNumber, String locale, Credential originator, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		GetCredentialAvailableActionsRequest payload = of.createGetCredentialAvailableActionsRequest();
		payload.setIssuerId(issuerId);
		payload.setSerialNumber(serialNumber);
		payload.setLocale(locale);

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}

	/**
	 * Method to generate a GetCredentialAvailableActionsResponse
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request this message is a response to.
	 * @param operations a list of operations that is available for a given credential when renewing.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genGetCredentialAvailableActionsResponse(String relatedEndEntity, CSMessage request, List<CredentialAvailableActionsOperation> operations, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		GetCredentialAvailableActionsResponse response = of.createGetCredentialAvailableActionsResponse();
		GetCredentialAvailableActionsResponse.Operations ops = of.createGetCredentialAvailableActionsResponseOperations();
		ops.getOperation().addAll(operations);
		response.setOperations(ops);

		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}

	/**
	 * Method to generate a AutomaticRenewCredentialRequest to renew a given credential with an identical
	 * credential and used for automation steps.
	 *
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param automationLevel The level of automation, AUTOMATIC if requesting system updates automatically, or MANUAL of manual
	 *                        steps needs to be taked for renewal
	 * @param renewalRequestData A list of request data. The request data is PKCS7 of PKCS10 data signed with original certificate.
	 * @param originator the original requester of a message, null if not applicable.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genAutomaticRenewCredentialRequest(String requestId, String destinationId, String organisation, AutomationLevel automationLevel, List<byte[]> renewalRequestData, Credential originator, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		AutomaticRenewCredentialRequest payload = of.createAutomaticRenewCredentialRequest();
		payload.setAutomationLevel(automationLevel);
		payload.getRenewalRequestData().addAll(renewalRequestData);

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}

	/**
	 * Method to generate a AutomaticRenewalResponse
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request this message is a response to.
	 * @param renewedCredentials a list of renewed credential with a reference to the unique id of the original credential.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genAutomaticRenewCredentialResponse(String relatedEndEntity, CSMessage request, List<AutomaticRenewCredentialResponse.RenewedCredential> renewedCredentials, List<Object> assertions)  throws MessageContentException, MessageProcessingException{
		AutomaticRenewCredentialResponse response = of.createAutomaticRenewCredentialResponse();
		response.getRenewedCredential().addAll(renewedCredentials);

		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}

	/**
	 * Help method to generate a Key structure consisting of a relatedCredential and an encryptedKey.
	 *
	 * @param relatedCredential the related credential to the key.
	 * @param encryptedKey the key in xml encrypted base64binary string.
     * @return a newly generate key.
     */
	public Key genKey(Credential relatedCredential, byte[] encryptedKey){
		Key retval = of.createKey();
		retval.setRelatedCredential(relatedCredential);
		retval.setEncryptedData(encryptedKey);
		return retval;
	}

	/**
	 * Help method to generate a RecoverableKey structure consisting of a relatedCredentialRequestId and an encryptedKey.
	 *
	 * @param relatedCredentialRequestId reference to the credential request id.
	 * @param encryptedKey the key in xml encrypted base64binary string.
	 * @return a newly generate key.
	 */
	public RecoverableKey genRecoverableKey(int relatedCredentialRequestId, byte[] encryptedKey){
		RecoverableKey retval = of.createRecoverableKey();
		retval.setRelatedCredentialRequestId(relatedCredentialRequestId);
		retval.setEncryptedData(encryptedKey);
		return retval;
	}
}
