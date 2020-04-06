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
package org.certificateservices.messages.autoenroll;


import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.autoenroll.jaxb.*;
import org.certificateservices.messages.csmessages.*;
import org.certificateservices.messages.csmessages.jaxb.Attribute;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.Credential;
import org.certificateservices.messages.csmessages.jaxb.CredentialRequest;
import org.certificateservices.messages.sensitivekeys.jaxb.KeyData;
import org.certificateservices.messages.sensitivekeys.jaxb.KeyDataType;

import java.io.InputStream;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Payload Parser for generating auto enroll messages according to
 * autoenroll_schema2_0.xsd
 * 
 * @author Philip Vendil
 *
 */
public class AutoEnrollPayloadParser extends BasePayloadParser {

	public static String NAMESPACE = "http://certificateservices.org/xsd/autoenroll2_x";

	public static final String AUTOENROLL_XSD_SCHEMA_2_0_RESOURCE_LOCATION = "/autoenroll_schema2_0.xsd";

	private ObjectFactory of = new ObjectFactory();
	
	private static final String[] SUPPORTED_AUTOENROLL_VERSIONS = {"2.0"};
	
	private static final String DEFAULT_AUTOENROLL_VERSION = "2.0";
	
	
	/**
	 * @see PayloadParser#getJAXBPackage()
	 */
	public String getJAXBPackage() {
		return "org.certificateservices.messages.autoenroll.jaxb";
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
    		return getClass().getResourceAsStream(AUTOENROLL_XSD_SCHEMA_2_0_RESOURCE_LOCATION);
    	}
    	
    	throw new MessageContentException("Error unsupported Auto Enroll Payload version: " + payLoadVersion);
	}
	
	/**
	 * @see BasePayloadParser#getSupportedVersions()
	 */
	@Override
	protected String[] getSupportedVersions() {
		return SUPPORTED_AUTOENROLL_VERSIONS;
	}

	/**
	 * @see BasePayloadParser#getDefaultPayloadVersion()
	 */
	@Override
	protected String getDefaultPayloadVersion() {
		return DEFAULT_AUTOENROLL_VERSION;
	}


	/**
	 *  Method to create a CheckStatusRequest message with a list CheckStatusRequest.Type for each enabled
	 *  auto enrollment profile. The message is unsigned.
	 *
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param autoEnrollmentProfileTypes a list profile types to check status for.
	 * @param originator the original requester of a message, null if not applicable
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return generated and signed CSMessage in byte[] format.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genCheckStatusRequest(String requestId, String destinationId, String organisation, List<CheckStatusRequest.Type> autoEnrollmentProfileTypes, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		CheckStatusRequest payload = of.createCheckStatusRequest();
		payload.getType().addAll(autoEnrollmentProfileTypes);
		CSMessageParser csMessageParser = getCSMessageParser();
		CSMessage message = csMessageParser.genCSMessage(DefaultCSMessageParser.DEFAULT_CSMESSAGE_PROTOCOL, DEFAULT_AUTOENROLL_VERSION,null, requestId, destinationId, organisation, originator, payload,  assertions);
		return csMessageParser.marshallCSMessage(message);
	}


	/**
	 * Method to a generate a CheckStatusResponse message instructing the client which actions
	 * to perform for each enabled auto enrollment profile.
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param autoEnrollmentProfileTypes a list of profile types instructin the client what to do.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genCheckStatusResponse(String relatedEndEntity, CSMessage request, List<CheckStatusResponse.Type> autoEnrollmentProfileTypes, List<Object> assertions) throws MessageContentException, MessageProcessingException{

		CheckStatusResponse payload = of.createCheckStatusResponse();
		payload.getType().addAll(autoEnrollmentProfileTypes);

		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), payload, false);
	}

	/**
	 *  Method to create a ClientActionRequest message with a list ClientActionRequest.Type for each enabled
	 *  auto enrollment profile. The message is unsigned.
	 *
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param autoEnrollmentProfileTypes a list profile types to perform client actions for.
	 * @param originator the original requester of a message, null if not applicable
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return generated and signed CSMessage in byte[] format.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genClientActionRequest(String requestId, String destinationId, String organisation, List<ClientActionRequest.Type> autoEnrollmentProfileTypes, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		ClientActionRequest payload = of.createClientActionRequest();
		payload.getType().addAll(autoEnrollmentProfileTypes);
		CSMessageParser csMessageParser = getCSMessageParser();
		CSMessage message = csMessageParser.genCSMessage(DefaultCSMessageParser.DEFAULT_CSMESSAGE_PROTOCOL, DEFAULT_AUTOENROLL_VERSION,null, requestId, destinationId, organisation, originator, payload,  assertions);
		return csMessageParser.marshallCSMessage(message);
	}

	/**
	 * Method to a generate a ClientActionResponse message returning resulting data for the
	 * related client action request for each requested profile.
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param autoEnrollmentProfileTypes a list of profile types for each requested profile-
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genClientActionResponse(String relatedEndEntity, CSMessage request, List<ClientActionResponse.Type> autoEnrollmentProfileTypes, List<Object> assertions) throws MessageContentException, MessageProcessingException{

		ClientActionResponse payload = of.createClientActionResponse();
		payload.getType().addAll(autoEnrollmentProfileTypes);

		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), payload, false);
	}


	/**
	 * Help method to create a check status request for a specific autoEnrollmentProfile type.
	 * @param autoEnrollmentProfile the types related profile
	 * @param currentCredentials the current credentials that exists on current computer for given type.
     * @return a new CheckStatusRequest.Type object.
     */
	public CheckStatusRequest.Type genCheckStatusRequestType(String autoEnrollmentProfile, List<Credential> currentCredentials){
		CheckStatusRequest.Type retval = of.createCheckStatusRequestType();
		retval.setAutoEnrollmentProfile(autoEnrollmentProfile);
		CheckStatusRequest.Type.CurrentCredentials cc = of.createCheckStatusRequestTypeCurrentCredentials();
		cc.getCredential().addAll(currentCredentials);
		retval.setCurrentCredentials(cc);
		return retval;
	}

	/**
	 * Help method to create a check status response for a specific autoEnrollmentProfile type.
	 *
	 * @param autoEnrollmentProfile the types related profile
	 * @param performActions perform actions that specifies all the actions the client should perform.
	 * @return a new CheckStatusResponse.Type object.
	 */
	public CheckStatusResponse.Type genCheckStatusResponseType(String autoEnrollmentProfile, CheckStatusResponse.Type.PerformActions performActions){
		CheckStatusResponse.Type retval = of.createCheckStatusResponseType();
		retval.setAutoEnrollmentProfile(autoEnrollmentProfile);
		retval.setPerformActions(performActions);
		return retval;
	}

	/**
	 * Help method to create a client action request for a specific autoEnrollmentProfile type.
	 * @param autoEnrollmentProfile the types related profile
	 * @param currentCredentials the current credentials that exists on current computer for given type.
	 * @param actions specifies the given actions the client what to perform.
	 * @return a new ClientActionRequest.Type object.
	 */
	public ClientActionRequest.Type genClientActionRequestType(String autoEnrollmentProfile, List<Credential> currentCredentials, ClientActionRequest.Type.Actions actions){
		ClientActionRequest.Type retval = of.createClientActionRequestType();
		retval.setAutoEnrollmentProfile(autoEnrollmentProfile);
		ClientActionRequest.Type.CurrentCredentials cc = of.createClientActionRequestTypeCurrentCredentials();
		cc.getCredential().addAll(currentCredentials);
		retval.setCurrentCredentials(cc);
		retval.setActions(actions);

		return retval;
	}

	/**
	 * Help method to create a client action request for a specific autoEnrollmentProfile type.
	 * @param autoEnrollmentProfile the types related profile
	 * @param tokenDatas a list of token data of related credentials and optionally keys, use null of response
	 *                   doesn't require any token datas.
	 * @return a new ClientActionResponse.Type object.
	 */
	public ClientActionResponse.Type genClientActionResponseType(String autoEnrollmentProfile,List<TokenData> tokenDatas){
		ClientActionResponse.Type retval = of.createClientActionResponseType();
		retval.setAutoEnrollmentProfile(autoEnrollmentProfile);
		if(tokenDatas != null) {
			ClientActionResponse.Type.TokenDatas tds = of.createClientActionResponseTypeTokenDatas();
			tds.getTokenData().addAll(tokenDatas);
			retval.setTokenDatas(tds);
		}

		return retval;
	}


	/**
	 * Method to create a PerformFetchExistingTokensAction
	 * @return a new PerformFetchExistingTokensAction
     */
	public PerformFetchExistingTokensAction genPerformFetchExistingTokensAction(){
		return of.createPerformFetchExistingTokensAction();
	}

	/**
	 * Method to create a PerformGenerateCredentialRequestAction
	 *
	 * @param keyRecoverable to indicate to the client that it should backup the generated private key by
	 *                       including it along with the credential request.
	 * @param wrappingCredential the credential that should be used to encrypt the key towards the frontend service.
	 *                           required in keyRecoverable is set to true.
	 * @param credentialSubType the related credential subtype to generate.
	 * @param tokenRequestAttributes map of used token request attributes used to construct the pkcs10, usually values from
	 *                               AvailableSubjectDNFields or AvailableSubjectAlternativeNames (cs-common) such as
	 *                               x509dn_cn or x509altname_dnsname
	 * @return a new PerformGenerateCredentialRequestAction
	 * @throws MessageContentException if invalid arguments such as set keyRecoverable to true but not supplied any wrapping credential.
	 */
	public PerformGenerateCredentialRequestAction genPerformGenerateCredentialRequestAction(boolean keyRecoverable, Credential wrappingCredential, String credentialSubType,  Map<String,String> tokenRequestAttributes) throws MessageContentException {
		if(keyRecoverable && wrappingCredential == null){
			throw new MessageContentException("PerformGenerateCredentialRequestAction must have a wrapping credential when set as key recoverable");
		}
		if(credentialSubType == null){
			throw new MessageContentException("PerformGenerateCredentialRequestAction must have credentialSubType set.");
		}
		if(tokenRequestAttributes == null || tokenRequestAttributes.size() < 1){
			throw new MessageContentException("Error at least on token request attribute must be specified.");
		}
		PerformGenerateCredentialRequestAction retval =  of.createPerformGenerateCredentialRequestAction();
		retval.setKeyRecoverable(keyRecoverable);
		retval.setWrappingCredential(wrappingCredential);
		retval.setCredentialSubType(credentialSubType);
		PerformGenerateCredentialRequestAction.TokenRequestAttributes tra = of.createPerformGenerateCredentialRequestActionTokenRequestAttributes();
		for(String key : tokenRequestAttributes.keySet()) {
			Attribute a = csMessageObjectFactory.createAttribute();
			a.setKey(key);
			a.setValue(tokenRequestAttributes.get(key));
			tra.getTokenRequestAttribute().add(a);

		}
		retval.setTokenRequestAttributes(tra);
		return retval;
	}

	/**
	 * Method to create a PerformRemoveCredentialsAction
	 *
	 * @param credentials list of credentials to remove, not null or empty list.
	 * @return a new PerformRemoveCredentialsAction
	 * @throws MessageContentException if invalid arguments such as empty credentials list.
	 */
	public PerformRemoveCredentialsAction genPerformRemoveCredentialsAction(List<Credential> credentials) throws MessageContentException {
		if(credentials == null || credentials.size() == 0){
			throw new MessageContentException("PerformRemoveCredentialsAction must have at least one credential.");
		}
		PerformRemoveCredentialsAction retval =  of.createPerformRemoveCredentialsAction();
		retval.getCredential().addAll(credentials);
		return retval;
	}

	public PerformedFetchExistingTokensAction genPerformedFetchExistingTokensAction(){
		return of.createPerformedFetchExistingTokensAction();
	}

	/**
	 * Method to generate a PerformedFetchExistingTokensAction for advanced use cases where a transport key
	 * exists in the clients computer
	 * @param wrappingCredential certificate that the client want’s the proxy to wrap the returned private keys with.
	 *                           This is used in advanced use cases when the client might use TMP chip with an
	 *                           existing wrapping key. If not set should the proxy return the keys unencrypted.
	 */
	public PerformedFetchExistingTokensAction genPerformedFetchExistingTokensAction(Credential wrappingCredential){
		PerformedFetchExistingTokensAction retval = of.createPerformedFetchExistingTokensAction();
		retval.setWrappingCredential(wrappingCredential);
		return retval;
	}

	/**
	 * Method to create a PerformedGenerateCredentialRequestAction
	 *
	 * @param credentialRequest the generated credential request, never null
	 * @param encryptedKey if key should be key recoverable should the key data be sent as an XML ENC encrypted key according
	 *                     to the sensitive key specification. Otherwise use null.
	 *
	 * @return a new PerformedGenerateCredentialRequestAction
	 * @throws MessageContentException if invalid arguments such as set keyRecoverable to true but not supplied any wrapping credential.
	 */
	public PerformedGenerateCredentialRequestAction genPerformedGenerateCredentialRequestAction(CredentialRequest credentialRequest, byte[] encryptedKey) throws MessageContentException {
		if(credentialRequest == null){
			throw new MessageContentException("PerformedGenerateCredentialRequestAction must have a credential request.");
		}
		PerformedGenerateCredentialRequestAction retval =  of.createPerformedGenerateCredentialRequestAction();
		retval.setCredentialRequest(credentialRequest);
		retval.setEncryptedKey(encryptedKey);
		return retval;
	}

	/**
	 * Method to create a PerformedRemoveCredentialsAction
	 *
	 * @param credentials list of credentials removed, not null or empty list.
	 * @return a new PerformedRemoveCredentialsAction
	 * @throws MessageContentException if invalid arguments such as empty credentials list.
	 */
	public PerformedRemoveCredentialsAction genPerformedRemoveCredentialsAction(List<Credential> credentials) throws MessageContentException {
		if(credentials == null || credentials.size() == 0){
			throw new MessageContentException("PerformedRemoveCredentialsAction must have at least one credential.");
		}
		PerformedRemoveCredentialsAction retval =  of.createPerformedRemoveCredentialsAction();
		retval.getCredential().addAll(credentials);
		return retval;
	}

	/**
	 * Method to generate a TokenData without any recovered key. Used for credentials
	 * that doesn't need key recovery.
	 *
	 * @param credential the credential related to a token.
	 * @return newly generated TokenData
	 * @throws MessageContentException if arguments was invalid, such as null credential.
     */
	public TokenData genTokenData(Credential credential) throws MessageContentException {
		return genTokenData(credential,(KeyData) null);
	}

	/**
	 * Method to generate a TokenData with a recovered key. Used for credentials
	 * that need key recovery.
	 *
	 * @param credential the credential related to a token.
	 * @param keyData the recovered key, unencrypted.
	 * @return newly generated TokenData
	 * @throws MessageContentException if arguments was invalid, such as null credential.
	 */
	public TokenData genTokenData(Credential credential, KeyDataType keyData) throws MessageContentException {
		if(credential == null){
			throw new MessageContentException("TokenData must have at least credential set.");
		}
		TokenData retval = of.createTokenData();
		retval.setCredential(credential);
		retval.setKey(keyData);
		return retval;
	}

	/**
	 * Method to generate a TokenData with a recovered key. Used for credentials
	 * that need key recovery and where client supports the advanced use case where
	 * it has transport key to wrap encryption keys with, such as a TPM chip.
	 *
	 *
	 * @param credential the credential related to a token.
	 * @param encryptedKey the recovered key, encrypted XMLEnc of Senstive Key specification.
	 * @return newly generated TokenData
	 * @throws MessageContentException if arguments was invalid, such as null credential.
	 */
	public TokenData genTokenData(Credential credential, byte[] encryptedKey) throws MessageContentException {
		if(credential == null){
			throw new MessageContentException("TokenData must have at least credential set.");
		}
		TokenData retval = of.createTokenData();
		retval.setCredential(credential);
		retval.setEncryptedKey(encryptedKey);
		return retval;
	}

	
}
