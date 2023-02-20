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
package org.certificateservices.messages.signrequest;


import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.csmessages.BasePayloadParser;
import org.certificateservices.messages.csmessages.CSMessageResponseData;
import org.certificateservices.messages.csmessages.PayloadParser;
import org.certificateservices.messages.csmessages.jaxb.Attribute;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.Credential;
import org.certificateservices.messages.signrequest.jaxb.*;

import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.List;

/**
 * Payload Parser for generating SignRequest messages according to
 * signrequest_schema2_0.xsd
 *
 * @author Philip Vendil 2019-10-03
 */
public class SignRequestPayloadParser extends BasePayloadParser {

	public static String NAMESPACE = "http://certificateservices.org/xsd/signrequest2_0";


	public static final String SIGNREQUEST_PROTOCOL_XSD_SCHEMA_2_0_RESOURCE_LOCATION = "/signrequest_schema2_0.xsd";
	public static final String SIGNREQUEST_PROTOCOL_XSD_SCHEMA_2_1_RESOURCE_LOCATION = "/signrequest_schema2_1.xsd";

	private ObjectFactory of = new ObjectFactory();
	
	private static final String[] SUPPORTED_SIGNREQUEST_PROTOCOL_VERSIONS = {"2.0", "2.1"};
	
	private static final String DEFAULT_SIGNREQUEST_PROTOCOL_VERSION = "2.1";
	
	
	/**
	 * @see PayloadParser#getJAXBPackage()
	 */
	public String getJAXBPackage() {
		return "org.certificateservices.messages.signrequest.jaxb";
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
    		return getClass().getResourceAsStream(SIGNREQUEST_PROTOCOL_XSD_SCHEMA_2_0_RESOURCE_LOCATION);
    	}
		if(payLoadVersion.equals("2.1")){
			return getClass().getResourceAsStream(SIGNREQUEST_PROTOCOL_XSD_SCHEMA_2_1_RESOURCE_LOCATION);
		}
    	
    	throw new MessageContentException("Error unsupported CS Sign Request Protocol Payload version: " + payLoadVersion);
	}
	
	/**
	 * @see BasePayloadParser#getSupportedVersions()
	 */
	@Override
	protected String[] getSupportedVersions() {
		return SUPPORTED_SIGNREQUEST_PROTOCOL_VERSIONS;
	}

	/**
	 * @see BasePayloadParser#getDefaultPayloadVersion()
	 */
	@Override
	protected String getDefaultPayloadVersion() {
		return DEFAULT_SIGNREQUEST_PROTOCOL_VERSION;
	}
	

	/**
	 *  Method to create a SignRequest to request signature of the list of SignRequestTasks
	 *
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param signRequestTasks Contains a list between 1 and 100 SignRequest tasks.
	 * @param originator the original requester of a message, null if not applicable
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return generated and signed CSMessage in byte[] format.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genSignRequest(String requestId, String destinationId, String organisation, List<SignRequestTask> signRequestTasks, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		SignRequest payload = of.createSignRequest();

		SignRequest.SignRequestTasks tasksElement = of.createSignRequestSignRequestTasks();
		tasksElement.getSignRequestTask().addAll(signRequestTasks);
		payload.setSignRequestTasks(tasksElement);

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}

	/**
	 *  Method to create a GetPubKeyRequest to get a set of public keys.
	 *
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param getPukKeyRequestTasks Contains a list between 1 and 100 GetPukKeyRequest tasks.
	 * @param originator the original requester of a message, null if not applicable
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return generated and signed CSMessage in byte[] format.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genGetPubKeyRequest(String requestId, String destinationId, String organisation, List<GetPubKeyRequestTask> getPukKeyRequestTasks, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		GetPubKeyRequest payload = of.createGetPubKeyRequest();

		GetPubKeyRequest.GetPubKeyRequestTasks tasksElement = of.createGetPubKeyRequestGetPubKeyRequestTasks();
		tasksElement.getGetPubKeyRequestTask().addAll(getPukKeyRequestTasks);
		payload.setGetPubKeyRequestTasks(tasksElement);

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}

	/**
	 * Method to create a SignResponse containing list of signature responses.
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param signResponseTasks Contains a list of 0 to 100 of sign response tasks.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genSignResponse(String relatedEndEntity, CSMessage request, List<SignResponseTask> signResponseTasks) throws MessageContentException, MessageProcessingException{
		SignResponse response = of.createSignResponse();

		SignResponse.SignResponseTasks tasksElement = of.createSignResponseSignResponseTasks();
		tasksElement.getSignResponseTask().addAll(signResponseTasks);

		response.setSignResponseTasks(tasksElement);

		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response, false);
	}

	/**
	 * Method to create a GetPubKeyResponse containing list of public keys.
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param getPubKeyResponseTasks Contains a list of 0 to 100 of get pub key response tasks.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genGetPubKeyResponse(String relatedEndEntity, CSMessage request, List<GetPubKeyResponseTask> getPubKeyResponseTasks) throws MessageContentException, MessageProcessingException{
		GetPubKeyResponse response = of.createGetPubKeyResponse();

		GetPubKeyResponse.GetPubKeyResponseTasks tasksElement = of.createGetPubKeyResponseGetPubKeyResponseTasks();
		tasksElement.getGetPubKeyResponseTask().addAll(getPubKeyResponseTasks);

		response.setGetPubKeyResponseTasks(tasksElement);

		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response, false);
	}

	/**
	 * Help method to create a sign task to include in a SignRequest list.
	 *
	 *
	 * @param signTaskId A identifier in the list of signRequestTask to used identify the response in the list of responses. Can be a sequence number for each signature within one SignRequest.
	 * @param signType String identifying the type of signing operation. i.e algorithm and encoding used. Should be a descriptive name of the use case of the key.
	 * @param keyId Identifier of the key pair that should be used to perform the signing operation.
	 * @param attributes a list of meta data attribute to further describe the signature task. Can contain customly defined values used for a specific sighType.
	 * @param signRequestData Signing Data containing the data to sign. This can be a hash value or other data depending on signType.
	 * @return return a newly populated SignRequestTask.
	 */
	public SignRequestTask genSignRequestTask(String signTaskId, String signType, String keyId,  List<Attribute> attributes, byte[] signRequestData){
		SignRequestTask task = of.createSignRequestTask();
		populateBaseTask(task, signTaskId, signType, keyId, attributes);
		task.setSignRequestData(signRequestData);
		return task;
	}

	/**
	 * Help method to create a GetPubKeyRequestTask to include in a GetPubKeyRequestTask list.
	 *
	 *
	 * @param taskId A identifier in the list of getPubKeyResponseTask to used identify the response in the list of responses. Can be a sequence number for each signature within one GetPubKeyRequestTask.
	 * @param signType String identifying the type of signing operation. i.e algorithm and encoding used. Should be a descriptive name of the use case of the key.
	 * @param keyId Identifier of the key pair that should be used to perform the signing operation.
	 * @param attributes a list of meta data attribute to further describe the signature task. Can contain customly defined values used for a specific sighType.
	 * @return return a newly populated SignRequestTask.
	 */
	public GetPubKeyRequestTask genGetPubKeyRequestTask(String taskId, String signType, String keyId,  List<Attribute> attributes){
		GetPubKeyRequestTask task = of.createGetPubKeyRequestTask();
		task.setSignType(signType);
		task.setTaskId(taskId);
		task.setKeyId(keyId);
		if(attributes != null) {
			GetPubKeyRequestTask.Attributes attributesElement = of.createGetPubKeyRequestTaskAttributes();
			attributesElement.getAttribute().addAll(attributes);
			task.setAttributes(attributesElement);
		}
		return task;
	}

	/**
	 * Help method to create a SignResponseTask to include in SignResponse list.
	 *
	 * <i>Important</i>. The type of certificate in certificate chain is set to default X509 in this method.
	 *
	 * @param signTaskId A identifier in the list of signRequestTask to used identify the response in the list of responses. Can be a sequence number for each signature within one SignRequest.
	 * @param signType String identifying the type of signing operation. i.e algorithm and encoding used. Should be a descriptive name of the use case of the key.
	 * @param keyId Identifier of the key pair that should be used to perform the signing operation.
	 * @param attributes a list of meta data attribute to further describe the signature task. Can contain customly defined values used for a specific sighType. Optional
	 * @param signResponseData Base64 Encoded Signing Data containing the signing result. The actual data is defined per signType.
	 * @param certificateChain A List of X509 certificate data in Base64encoded DER encoding. It’s up to the signType definition if no certificate, only end entity certificate or entire chain should be included. But list should be ordered so end entity certificate is first and top most certificate in chain is last. Optional
	 * @param publicKey used to sign the data, actual encoding is up to signType.
	 * @return return a newly populated SignResponseTask.
	 * @throws MessageContentException if invalid parameters found.
	 */
	public SignResponseTask genSignResponseTask(String signTaskId, String signType, String keyId, List<Attribute> attributes, byte[] signResponseData, List<Certificate> certificateChain, byte[] publicKey) throws MessageContentException{
		SignResponseTask task = of.createSignResponseTask();
		populateBaseTask(task, signTaskId, signType, keyId, attributes);
		task.setSignResponseData(signResponseData);
		if(certificateChain != null) {
			CertificateChainType certificateChainType = of.createCertificateChainType();
			for(Certificate cert : certificateChain){
				try {
					certificateChainType.getCertificateData().add(cert.getEncoded());
				}catch(CertificateEncodingException e){
					throw new MessageContentException("Error encoding certificate in given chain for sign task: " + e.getMessage(),e);
				}
			}
			task.setCertificateChain(certificateChainType);
		}
		task.setPublicKey(publicKey);

		return task;
	}

	/**
	 * Help method to create a GetPubKeyResponseTask to include in GetPubKeyResponseTask list.
	 *
	 * <i>Important</i>. The type of certificate in certificate chain is set to default X509 in this method.
	 *
	 * @param taskId A identifier in the list of getPubKeyResponseTask to used identify the response in the list of responses. Can be a sequence number for each pub key within one getPubKeyResponseTask.
	 * @param signType String identifying the type of signing operation. i.e algorithm and encoding used. Should be a descriptive name of the use case of the key.
	 * @param keyId Identifier of the key pair that should be used to perform the signing operation.
	 * @param attributes a list of meta data attribute to further describe the signature task. Can contain customly defined values used for a specific sighType. Optional
	 * @param certificateChain A List of X509 certificate data in Base64encoded DER encoding. It’s up to the signType definition if no certificate, only end entity certificate or entire chain should be included. But list should be ordered so end entity certificate is first and top most certificate in chain is last. Optional
	 * @param publicKey used to sign the data, actual encoding is up to signType.
	 * @return return a newly populated SignResponseTask.
	 * @throws MessageContentException if invalid parameters found.
	 */
	public GetPubKeyResponseTask genGetPubKeyResponseTask(String taskId, String signType, String keyId, List<Attribute> attributes, List<Certificate> certificateChain, byte[] publicKey) throws MessageContentException{
		GetPubKeyResponseTask task = of.createGetPubKeyResponseTask();
		task.setSignType(signType);
		task.setTaskId(taskId);
		task.setKeyId(keyId);
		if(attributes != null) {
			GetPubKeyResponseTask.Attributes attributesElement = of.createGetPubKeyResponseTaskAttributes();
			attributesElement.getAttribute().addAll(attributes);
			task.setAttributes(attributesElement);
		}
		if(certificateChain != null) {
			CertificateChainType certificateChainType = of.createCertificateChainType();
			for(Certificate cert : certificateChain){
				try {
					certificateChainType.getCertificateData().add(cert.getEncoded());
				}catch(CertificateEncodingException e){
					throw new MessageContentException("Error encoding certificate in given chain for sign task: " + e.getMessage(),e);
				}
			}
			task.setCertificateChain(certificateChainType);
		}
		task.setPublicKey(publicKey);

		return task;
	}

	/**
	 * Common help method to populate the base parse of the sign tasks for both request and response.
	 *
	 * @param baseSignTask the base sign task to populate.
	 * @param signTaskId A identifier in the list of signRequestTask to used identify the response in the list of responses. Can be a sequence number for each signature within one SignRequest.
	 * @param signType String identifying the type of signing operation. i.e algorithm and encoding used. Should be a descriptive name of the use case of the key.
	 * @param keyId Identifier of the key pair that should be used to perform the signing operation.
	 * @param attributes a list of meta data attribute to further describe the signature task. Can contain customly defined values used for a specific sighType. Optional
	 */
	private void populateBaseTask(BaseSignTask baseSignTask, String signTaskId, String signType, String keyId,  List<Attribute> attributes) {
		baseSignTask.setSignType(signType);
		baseSignTask.setSignTaskId(signTaskId);
		baseSignTask.setKeyId(keyId);
		if(attributes != null) {
			BaseSignTask.Attributes attributesElement = of.createBaseSignTaskAttributes();
			attributesElement.getAttribute().addAll(attributes);
			baseSignTask.setAttributes(attributesElement);
		}
	}
}
