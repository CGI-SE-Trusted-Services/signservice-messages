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
package org.certificateservices.messages.v2x.backend;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.csmessages.BasePayloadParser;
import org.certificateservices.messages.csmessages.CSMessageResponseData;
import org.certificateservices.messages.csmessages.PayloadParser;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.Credential;
import org.certificateservices.messages.v2x.backend.jaxb.*;
import org.certificateservices.messages.v2x.registration.V2XPayloadParser;
import org.certificateservices.messages.v2x.registration.jaxb.RegionsType;

import java.io.InputStream;
import java.util.List;

/**
 * Payload Parser for generating V2X Backend messages according to
 * v2x_backend_schema2_0.xsd
 *
 * @author Philip Vendil 2020-05-30
 *
 */
public class V2XBackendPayloadParser extends BasePayloadParser {

	public static String NAMESPACE = "http://certificateservices.org/xsd/v2x_backend_2_0";

	private static final String V2X_BACKEND_XSD_SCHEMA_2_0_RESOURCE_LOCATION = "/v2x_backend_schema2_0.xsd";


	private ObjectFactory of = new ObjectFactory();
	
	private static final String[] SUPPORTED_V2X_BACKEND_VERSIONS = {"2.0"};
	
	private static final String DEFAULT_V2X_BACKEND_VERSION = "2.0";
	
	
	/**
	 * @see PayloadParser#getJAXBPackage()
	 */
	public String getJAXBPackage() {
		return "org.certificateservices.messages.v2x.backend.jaxb";
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
    		return getClass().getResourceAsStream(V2X_BACKEND_XSD_SCHEMA_2_0_RESOURCE_LOCATION);
    	}
    	
    	throw new MessageContentException("Error unsupported SysConfig Payload version: " + payLoadVersion);
	}

	/**
	 * Method that returns related v2x schema
	 *
	 * @param payloadVersion payload version.
	 * @return an array of related schemas if no related schemas exists is empty array returned, never null.
	 */
	@Override
	public String[] getRelatedSchemas(String payloadVersion) {
		return new String[] {V2XPayloadParser.V2X_XSD_SCHEMA_2_0_RESOURCE_LOCATION};
	}

	/**
	 * @see BasePayloadParser#getSupportedVersions()
	 */
	@Override
	protected String[] getSupportedVersions() {
		return SUPPORTED_V2X_BACKEND_VERSIONS;
	}

	/**
	 * @see BasePayloadParser#getDefaultPayloadVersion()
	 */
	@Override
	protected String getDefaultPayloadVersion() {
		return DEFAULT_V2X_BACKEND_VERSION;
	}

	/**
	 *
	 * Method generate a Sign EC Request Message.
	 *
	 * @param requestId  id of request to send. (Required)
	 * @param destinationId the destination Id to use. (Required)
	 * @param organisation the related organisation (short name) (Required)
	 * @param canonicalId the canonical name of the ITS to register. Should be a unique identifier. (Required)
	 * @param assuranceLevel the assurance level to set in the certificate (Optional, use if assuranceLevel and
	 *                          confidenceLevel should be set).
	 * @param confidenceLevel the confidenceLevel level to set in the certificate (Optional, use if assuranceLevel and
	 * 	                      confidenceLevel should be set).
	 * @param eaName name of EA that the ITSS should be associated with.
	 * @param ecProfile Name of profile to use for the enrollment credential. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default EA used.
	 * @param validityUnit  the unit used for the maximum end date for EC if specified, if empty is profile validity used. (Optional)
	 * @param validityDuration  the duration value the maximum end date for EC if specified, if empty is profile validity used. (Optional)
	 * @param regions Defines specific regions for this vehicle. The defined regions is checked against the profile and only regions that are a subset of regions defined in related profile will be accepted.
	 *                If not set is the default regions set in related profile used. (Optional)
	 * @param publicVerificationKey the public verification key as a COER encoded PublicVerificationKey from ETSI 103 097. (Required)
	 * @param publicEncryptionKey the public verification key as a COER encoded PublicEncryptionKey from ETSI 103 097. (Optional)
	 * @param originator the credential of the original requester, null if this is the origin of the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public byte[] generateSignECRequest(String requestId, String destinationId, String organisation,
										String canonicalId, Integer assuranceLevel, Integer confidenceLevel,
										String eaName, String ecProfile,
										ValidityUnitType validityUnit, Integer validityDuration,
										RegionsType regions,
										byte[] publicVerificationKey, byte[] publicEncryptionKey,
										Credential originator, List<Object> assertions)
			throws MessageContentException, MessageProcessingException{
		SignECRequest payload = of.createSignECRequest();
		payload.setCanonicalId(canonicalId);
		payload.setAssuranceLevel(assuranceLevel);
		payload.setConfidenceLevel(confidenceLevel);
		payload.setEaName(eaName);
		payload.setEcProfile(ecProfile);
		payload.setValidityUnit(validityUnit);
		payload.setValidityDuration(validityDuration);
		payload.setRegions(regions);
		payload.setPublicVerificationKey(publicVerificationKey);
		payload.setPublicEncryptionKey(publicEncryptionKey);

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(),
				payload, originator, assertions);
	}

	/**
	 * Method generate a Sign EC Response Message.
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param canonicalId the canonical name of the ITS to register. Should be a unique identifier. (Required)
	 * @param responseCode name representation of one result code in related enrolment protocol. (Required)
	 * @param message descriptive messate related to the response used in logging (Optional)
	 * @param responseData the signed response data. (Required)
	 * @return a generated and signed message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
    public CSMessageResponseData generateSignECResponse(String relatedEndEntity, CSMessage request,
														String canonicalId, String responseCode,
														String message,
														byte[] responseData)
			throws MessageContentException, MessageProcessingException{
		SignECResponse payload = of.createSignECResponse();
		payload.setCanonicalId(canonicalId);
		payload.setResponseCode(responseCode);
		payload.setMessage(message);
		payload.setResponseData(responseData);

		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), payload);
	}



	/**
	 * Method generate a SignErrorRequest message
	 *
	 * @param requestId  id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param canonicalId the canonical name of the ITS to register. Should be a unique identifier. (Required)
	 * @param eaName name of EA that the ITSS should be associated with.
	 * @param responseCode name representation of one result code in related enrolment protocol. (Required)
	 * @param message descriptive messate related to the response used in logging (Required)
	 * @param originator the credential of the original requester, null if this is the origin of the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public byte[] generateSignErrorRequest(String requestId, String destinationId, String organisation,
											String canonicalId, String eaName, String responseCode, String message,
										   Credential originator, List<Object> assertions)
			throws MessageContentException, MessageProcessingException{
		SignErrorRequest payload = of.createSignErrorRequest();
		payload.setCanonicalId(canonicalId);
		payload.setEaName(eaName);
		payload.setMessage(message);
		payload.setResponseCode(responseCode);

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}

	/**
	 * Method generate a Sign Error Response Message.
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param canonicalId the canonical name of the ITS to register. Should be a unique identifier. (Required)
	 * @param responseCode name representation of one result code in related enrolment protocol. (Required)
	 * @param message descriptive messate related to the response used in logging (Optional)
	 * @param responseData the signed response data. (Required)
	 * @return a generated and signed message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public CSMessageResponseData generateSignErrorResponse(String relatedEndEntity, CSMessage request,
															String canonicalId, String responseCode,
															String message,
															byte[] responseData)
			throws MessageContentException, MessageProcessingException{
		SignErrorResponse payload = of.createSignErrorResponse();
		payload.setCanonicalId(canonicalId);
		payload.setResponseCode(responseCode);
		payload.setMessage(message);
		payload.setResponseData(responseData);
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(),
				payload);
	}

}
