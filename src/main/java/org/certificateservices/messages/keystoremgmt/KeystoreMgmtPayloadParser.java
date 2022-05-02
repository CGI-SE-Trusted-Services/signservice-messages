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
package org.certificateservices.messages.keystoremgmt;

import java.io.InputStream;
import java.util.List;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.csmessages.BasePayloadParser;
import org.certificateservices.messages.csmessages.CSMessageResponseData;
import org.certificateservices.messages.csmessages.PayloadParser;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.Credential;
import org.certificateservices.messages.csmessages.jaxb.CredentialRequest;
import org.certificateservices.messages.keystoremgmt.jaxb.AttachCredentialsRequest;
import org.certificateservices.messages.keystoremgmt.jaxb.AttachCredentialsResponse;
import org.certificateservices.messages.keystoremgmt.jaxb.CredentialRequestParams;
import org.certificateservices.messages.keystoremgmt.jaxb.GenerateCredentialRequestRequest;
import org.certificateservices.messages.keystoremgmt.jaxb.GenerateCredentialRequestResponse;
import org.certificateservices.messages.keystoremgmt.jaxb.GetAvailableKeyStoreInfoRequest;
import org.certificateservices.messages.keystoremgmt.jaxb.GetAvailableKeyStoreInfoResponse;
import org.certificateservices.messages.keystoremgmt.jaxb.KeyStore;
import org.certificateservices.messages.keystoremgmt.jaxb.ObjectFactory;
import org.certificateservices.messages.keystoremgmt.jaxb.RemoveKeyRequest;
import org.certificateservices.messages.keystoremgmt.jaxb.RemoveKeyResponse;
import org.certificateservices.messages.keystoremgmt.jaxb.UpdateKeyDescriptionRequest;
import org.certificateservices.messages.keystoremgmt.jaxb.UpdateKeyDescriptionResponse;
import org.certificateservices.messages.keystoremgmt.jaxb.X509CredentialRequestParams;

/**
 * Payload Parser for generating SysConfig messages according to 
 * keystoremgmt_schema2_0.xsd
 * 
 * @author Philip Vendil
 *
 */
public class KeystoreMgmtPayloadParser extends BasePayloadParser {
	
	public static String NAMESPACE = "http://certificateservices.org/xsd/keystoremgmt2_0";
	
	private static final String KEYSTOREMGMT_XSD_SCHEMA_2_0_RESOURCE_LOCATION = "/keystoremgmt_schema2_0.xsd";

	
	private ObjectFactory of = new ObjectFactory();
	
	private static final String[] SUPPORTED_KEYSTOREMGMT_VERSIONS = {"2.0"};
	
	private static final String DEFAULT_KEYSTOREMGMT_VERSION = "2.0";
	
	
	/**
	 * @see PayloadParser#getJAXBPackage()
	 */
	public String getJAXBPackage() {
		return "org.certificateservices.messages.keystoremgmt.jaxb";
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
    		return getClass().getResourceAsStream(KEYSTOREMGMT_XSD_SCHEMA_2_0_RESOURCE_LOCATION);
    	}
    	
    	throw new MessageContentException("Error unsupported KeystoreMgmt Payload version: " + payLoadVersion);
	}
	
	/**
	 * @see BasePayloadParser#getSupportedVersions()
	 */
	@Override
	protected String[] getSupportedVersions() {
		return SUPPORTED_KEYSTOREMGMT_VERSIONS;
	}

	/**
	 * @see BasePayloadParser#getDefaultPayloadVersion()
	 */
	@Override
	protected String getDefaultPayloadVersion() {
		return DEFAULT_KEYSTOREMGMT_VERSION;
	}

	/**
	 * 
	 * Method generate a Get Available Key Store Info Request
	 * 
	 * @param requestId  id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param organisation the related organisation (short name)
	 * @param originator the credential of the original requester, null if this is the origin of the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *  
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public byte[] generateGetAvailableKeyStoreInfoRequest(String requestId, String destinationId, String organisation,  Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		GetAvailableKeyStoreInfoRequest payload = of.createGetAvailableKeyStoreInfoRequest();
	
		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}
	
	
	/**
	 * Method generate a Get Available Key Store Info Response
	 *  
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param keyStores a list of available key store data.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return as success response back to the requestor.
	 * 
	 * @throws MessageContentException
	 * @throws MessageProcessingException
	 */
    public CSMessageResponseData generateGetAvailableKeyStoreInfoResponse(String relatedEndEntity, CSMessage request, List<KeyStore> keyStores, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		GetAvailableKeyStoreInfoResponse response = of.createGetAvailableKeyStoreInfoResponse();
		response.setKeyStores(new GetAvailableKeyStoreInfoResponse.KeyStores());
		for(KeyStore ks : keyStores){
			response.getKeyStores().getKeyStore().add(ks);
		}
		
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}
	
	
	/**
	 * 
	 * Method generate a Generate Credential Request Request
	 * 
	 * @param requestId  id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param organisation the related organisation (short name)
	 * @param keyStoreProviderName the name of the key store provider managing the key
	 * @param application the application that should use the key.
	 * @param credentialRequestParams the credential request parameters.
	 * @param originator the credential of the original requester, null if this is the origin of the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *  
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public byte[] generateGenerateCredentialRequestRequest(String requestId, String destinationId, String organisation, String keyStoreProviderName, String application, CredentialRequestParams credentialRequestParams, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		GenerateCredentialRequestRequest payload = of.createGenerateCredentialRequestRequest();
		payload.setApplication(application);
		payload.setKeyStoreProviderName(keyStoreProviderName);
		payload.setOrganisationShortName(organisation);
		payload.setCredentialRequestParams(new GenerateCredentialRequestRequest.CredentialRequestParams());
		if(credentialRequestParams instanceof X509CredentialRequestParams){
		  payload.getCredentialRequestParams().setX509CredentialRequestParams(((X509CredentialRequestParams) credentialRequestParams)); 
		}else{
		  payload.getCredentialRequestParams().setBaseRequestParams(credentialRequestParams);
		}
		
		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * 
	 * Method generate a Generate Credential Request Response.
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param credentialRequest the generate credential request
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *  
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
   public CSMessageResponseData generateGenerateCredentialRequestResponse(String relatedEndEntity, CSMessage request, CredentialRequest credentialRequest , List<Object> assertions) throws MessageContentException, MessageProcessingException{
	   GenerateCredentialRequestResponse response = of.createGenerateCredentialRequestResponse();
	   response.setCredentialRequest(credentialRequest);
	   
	   return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}
	

	/**
	 * 
	 * Method generate a Remove Key Request
	 * 
	 * @param requestId  id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param organisation the related organisation (short name)
	 * @param keyStoreProviderName the name of the key store provider managing the key
	 * @param alias the alias of the key
	 * @param originator the credential of the original requester, null if this is the origin of the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *  
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public byte[] generateRemoveKeyRequest(String requestId, String destinationId, String organisation, String keyStoreProviderName, String alias, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		RemoveKeyRequest payload = of.createRemoveKeyRequest();
		payload.setAlias(alias);
		payload.setKeyStoreProviderName(keyStoreProviderName);
		payload.setOrganisationShortName(organisation);
		
		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * 
	 * Method generate a Remove Key Response.
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *  
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
   public CSMessageResponseData generateRemoveKeyResponse(String relatedEndEntity, CSMessage request, List<Object> assertions) throws MessageContentException, MessageProcessingException{
	   RemoveKeyResponse response = of.createRemoveKeyResponse();
	
	   return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}
	
	/**
	 * 
	 * Method generate a Attach Credentials Request
	 * 
	 * @param requestId  id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param organisation the related organisation (short name)
	 * @param keyStoreProviderName the name of the key store provider managing the key
	 * @param alias the alias of the key
	 * @param credentialChain one more credentials of the credential chain to attach to the key.
	 * @param originator the credential of the original requester, null if this is the origin of the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *  
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public byte[] generateAttachCredentialsRequest(String requestId, String destinationId, String organisation, String keyStoreProviderName, String alias, List<Credential> credentialChain, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		AttachCredentialsRequest payload = of.createAttachCredentialsRequest();
		payload.setAlias(alias);
		payload.setKeyStoreProviderName(keyStoreProviderName);
		payload.setOrganisationShortName(organisation);
		payload.setCredentials(new AttachCredentialsRequest.Credentials());
		for(Credential c : credentialChain){
		  payload.getCredentials().getCredential().add(c);
		}
		
		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * 
	 * Method generate a Attach Credentials Response.
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *  
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
   public CSMessageResponseData generateAttachCredentialsResponse(String relatedEndEntity, CSMessage request, List<Object> assertions) throws MessageContentException, MessageProcessingException{
	   AttachCredentialsResponse response = of.createAttachCredentialsResponse();
	   return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}
	
	/**
	 * 
	 * Method generate a Update Key Description Request
	 * 
	 * @param requestId  id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param organisation the related organisation (short name)
	 * @param keyStoreProviderName the name of the key store provider managing the key
	 * @param alias the alias of the key
	 * @param description the description to update
	 * @param originator the credential of the original requester, null if this is the origin of the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *  
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public byte[] generateUpdateKeyDescriptionRequest(String requestId, String destinationId, String organisation, String keyStoreProviderName, String alias, String description, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		UpdateKeyDescriptionRequest payload = of.createUpdateKeyDescriptionRequest();
		payload.setAlias(alias);
		payload.setKeyStoreProviderName(keyStoreProviderName);
		payload.setOrganisationShortName(organisation);
		payload.setDescription(description);
		
		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}
	
	
	/**
	 * Method generate a Update Key Description Response
	 *  
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return as success response back to the requestor.
	 * 
	 * @throws MessageContentException
	 * @throws MessageProcessingException
	 */
    public CSMessageResponseData generateUpdateKeyDescriptionResponse(String relatedEndEntity, CSMessage request, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		UpdateKeyDescriptionResponse response = of.createUpdateKeyDescriptionResponse();
		
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}




}
