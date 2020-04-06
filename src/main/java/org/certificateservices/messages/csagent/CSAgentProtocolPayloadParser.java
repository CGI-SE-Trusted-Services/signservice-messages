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
package org.certificateservices.messages.csagent;


import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.csagent.jaxb.*;
import org.certificateservices.messages.csmessages.BasePayloadParser;
import org.certificateservices.messages.csmessages.CSMessageResponseData;
import org.certificateservices.messages.csmessages.PayloadParser;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.Credential;
import org.certificateservices.messages.utils.MessageGenerateUtils;

import java.io.InputStream;
import java.util.Date;
import java.util.List;

/**
 * Payload Parser for generating CS Agent Protocol messages according to
 * cs_agent_protocol_schema2_0.xsd
 * 
 * @author Philip Vendil
 *
 */
public class CSAgentProtocolPayloadParser extends BasePayloadParser {
	
	public static String NAMESPACE = "http://certificateservices.org/xsd/cs_agent_protocol2_0";


	public static final String CS_AGENT_PROTOCOL_XSD_SCHEMA_2_0_RESOURCE_LOCATION = "/cs_agent_protocol_schema2_0.xsd";

	private ObjectFactory of = new ObjectFactory();
	
	private static final String[] SUPPORTED_CSAGENT_PROTOCOL_VERSIONS = {"2.0"};
	
	private static final String DEFAULT_CSAGENT_PROTOCOL__VERSION = "2.0";
	
	
	/**
	 * @see PayloadParser#getJAXBPackage()
	 */
	public String getJAXBPackage() {
		return "org.certificateservices.messages.csagent.jaxb";
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
    		return getClass().getResourceAsStream(CS_AGENT_PROTOCOL_XSD_SCHEMA_2_0_RESOURCE_LOCATION);
    	}
    	
    	throw new MessageContentException("Error unsupported CS Agent Protocol Payload version: " + payLoadVersion);
	}
	
	/**
	 * @see BasePayloadParser#getSupportedVersions()
	 */
	@Override
	protected String[] getSupportedVersions() {
		return SUPPORTED_CSAGENT_PROTOCOL_VERSIONS;
	}

	/**
	 * @see BasePayloadParser#getDefaultPayloadVersion()
	 */
	@Override
	protected String getDefaultPayloadVersion() {
		return DEFAULT_CSAGENT_PROTOCOL__VERSION;
	}
	

	/**
	 *  Method to create a DiscoveredCredentialsRequest to report all found credentials found to get a list of
	 *  credential hashes of certificates not known centrally.
	 *
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param agentId The id of this agent sending in requests. (Required)
	 * @param scanId The id of this scanning session. (Required)
	 * @param scanTimeStamp The time the scan was sent in. (Required)
	 * @param discoveredCredentials Contains a list between 1 and 100 DiscoveredCredential of all credentials found on the network.
	 * @param originator the original requester of a message, null if not applicable
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return generated and signed CSMessage in byte[] format.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genDiscoveredCredentialsRequest(String requestId, String destinationId, String organisation, String agentId, String scanId, Date scanTimeStamp, List<DiscoveredCredential> discoveredCredentials, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		DiscoveredCredentialsRequest payload = of.createDiscoveredCredentialsRequest();

		payload.setAgentId(agentId);
		payload.setScanId(scanId);
		payload.setScanTimeStamp(MessageGenerateUtils.dateToXMLGregorianCalendar(scanTimeStamp));

		DiscoveredCredentialsRequest.DiscoveredCredentials dcs = new DiscoveredCredentialsRequest.DiscoveredCredentials();
		dcs.getDc().addAll(discoveredCredentials);

		payload.setDiscoveredCredentials(dcs);

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}

	/**
	 * Method to create a DiscoveredCredentialsResponse containing the hashes of all centrally unknown certificates.
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param hashValues Contains a list of 0 to 100 of unknown credential hashes.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genDiscoveredCredentialsResponse(String relatedEndEntity, CSMessage request, List<String> hashValues) throws MessageContentException, MessageProcessingException{
		DiscoveredCredentialsResponse response = of.createDiscoveredCredentialsResponse();

		DiscoveredCredentialsResponse.UnknownCredentials ucs = new DiscoveredCredentialsResponse.UnknownCredentials();
		if(hashValues != null) {
			ucs.getH().addAll(hashValues);
		}
		response.setUnknownCredentials(ucs);

		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response, false);
	}

	/**
	 *  Method to create a DiscoveredCredentialsRequest to report all found credentials found to get a list of
	 *  credential hashes of certificates not known centrally.
	 *
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param agentId The id of this agent sending in requests. (Required)
	 * @param scanId The id of this scanning session. (Required)
	 * @param scanTimeStamp The time the scan was sent in. (Required)
	 * @param discoveredCredentialDataList Contains a list between 1 and 100 DiscoveredCredentialData of all credentials found on the network.
	 * @param originator the original requester of a message, null if not applicable
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return generated and signed CSMessage in byte[] format.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genDiscoveredCredentialDataRequest(String requestId, String destinationId, String organisation, String agentId, String scanId, Date scanTimeStamp, List<DiscoveredCredentialData> discoveredCredentialDataList, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		DiscoveredCredentialDataRequest payload = of.createDiscoveredCredentialDataRequest();

		payload.setAgentId(agentId);
		payload.setScanId(scanId);
		payload.setScanTimeStamp(MessageGenerateUtils.dateToXMLGregorianCalendar(scanTimeStamp));

		DiscoveredCredentialDataRequest.DiscoveredCredentialData dcs = new DiscoveredCredentialDataRequest.DiscoveredCredentialData();
		dcs.getDcd().addAll(discoveredCredentialDataList);

		payload.setDiscoveredCredentialData(dcs);

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}

	/**
	 * Method to create a DiscoveredCredentialDataResponse sent after successful processing of request.
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genDiscoveredCredentialDataResponse(String relatedEndEntity, CSMessage request) throws MessageContentException, MessageProcessingException{
		DiscoveredCredentialDataResponse response = of.createDiscoveredCredentialDataResponse();

		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response, false);
	}
}
