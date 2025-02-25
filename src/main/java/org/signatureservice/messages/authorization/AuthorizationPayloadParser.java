/************************************************************************
 *                                                                       *
 *  Certificate Service - Messages                                       *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3 of the License, or any later version.                      *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signatureservice.messages.authorization;


import java.io.InputStream;
import java.util.Collection;
import java.util.List;

import org.signatureservice.messages.MessageContentException;
import org.signatureservice.messages.MessageProcessingException;
import org.certificateservices.messages.authorization.jaxb.*;
import org.signatureservice.messages.authorization.jaxb.*;
import org.signatureservice.messages.csmessages.BasePayloadParser;
import org.signatureservice.messages.csmessages.CSMessageResponseData;
import org.signatureservice.messages.csmessages.PayloadParser;
import org.signatureservice.messages.csmessages.jaxb.CSMessage;
import org.signatureservice.messages.csmessages.jaxb.Credential;

/**
 * Payload Parser for generating Authorization messages according to 
 * authorization2_0.xsd
 * 
 * @author Philip Vendil
 *
 */
public class AuthorizationPayloadParser extends BasePayloadParser {
	
	public static String NAMESPACE = "http://certificateservices.org/xsd/authorization2_0";
	
	public static final String AUTHORIZATION_XSD_SCHEMA_2_0_RESOURCE_LOCATION = "/authorization_schema2_0.xsd";
	public static final String AUTHORIZATION_XSD_SCHEMA_2_1_RESOURCE_LOCATION = "/authorization_schema2_1.xsd";
	public static final String AUTHORIZATION_XSD_SCHEMA_2_2_RESOURCE_LOCATION = "/authorization_schema2_2.xsd";
	public static final String AUTHORIZATION_XSD_SCHEMA_2_3_RESOURCE_LOCATION = "/authorization_schema2_3.xsd";

	private ObjectFactory of = new ObjectFactory();
	
	private static final String[] SUPPORTED_AUTHORIZATION_VERSIONS = {"2.3","2.2","2.1","2.0"};
	
	private static final String DEFAULT_AUTHORIZATION_VERSION = "2.3";

	/**
	 * @see PayloadParser#getJAXBPackage()
	 */
	public String getJAXBPackage() {
		return "org.certificateservices.messages.authorization.jaxb";
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
    		return getClass().getResourceAsStream(AUTHORIZATION_XSD_SCHEMA_2_0_RESOURCE_LOCATION);
    	}
		if(payLoadVersion.equals("2.1")){
			return getClass().getResourceAsStream(AUTHORIZATION_XSD_SCHEMA_2_1_RESOURCE_LOCATION);
		}
		if(payLoadVersion.equals("2.2")){
			return getClass().getResourceAsStream(AUTHORIZATION_XSD_SCHEMA_2_2_RESOURCE_LOCATION);
		}
		if(payLoadVersion.equals("2.3")){
			return getClass().getResourceAsStream(AUTHORIZATION_XSD_SCHEMA_2_3_RESOURCE_LOCATION);
		}
    	
    	throw new MessageContentException("Error unsupported Authorization Payload version: " + payLoadVersion);
	}
	
	/**
	 * @see BasePayloadParser#getSupportedVersions()
	 */
	@Override
	protected String[] getSupportedVersions() {
		return SUPPORTED_AUTHORIZATION_VERSIONS;
	}

	/**
	 * @see BasePayloadParser#getDefaultPayloadVersion()
	 */
	@Override
	protected String getDefaultPayloadVersion() {
		return DEFAULT_AUTHORIZATION_VERSION;
	}
	


	/**
	 * Method to create a GetRequesterRolesRequest message without any token type query.
	 * 
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param originator the original requester of a message, null if not applicable
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return generated and signed CSMessage in byte[] format.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genGetRequesterRolesRequest(String requestId, String destinationId, String organisation, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		return genGetRequesterRolesRequest(requestId,destinationId,organisation,null,originator,assertions);
	}

	/**
	 *  Method to create a GetRequesterRolesRequest message with a list of token type permission queries..
	 *
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param tokenTypeQuery a list of token types that should be checked for authorization.
	 * @param originator the original requester of a message, null if not applicable
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return generated and signed CSMessage in byte[] format.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genGetRequesterRolesRequest(String requestId, String destinationId, String organisation, List<String> tokenTypeQuery, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		GetRequesterRolesRequest payload = of.createGetRequesterRolesRequest();

		if(tokenTypeQuery != null && tokenTypeQuery.size() > 0){
			payload.setTokenTypePermissionQuery(of.createGetRequesterRolesRequestTokenTypePermissionQuery());
			payload.getTokenTypePermissionQuery().getTokenType().addAll(tokenTypeQuery);
		}

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * Method to a GetRequesterRolesResponse message and populating it with the all requesters authorized roles.
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param roles the authorized roles of the requester.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genGetRequesterRolesResponse(String relatedEndEntity, CSMessage request, List<String> roles, Collection<TokenTypePermission> tokenTypePermissions, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		GetRequesterRolesResponse response = of.createGetRequesterRolesResponse();
		
		response.setRoles(new GetRolesType.Roles());
		for(String role : roles){
			response.getRoles().getRole().add(role);
		}

		String payloadVersion = request.getPayLoadVersion();

		if(tokenTypePermissions != null && tokenTypePermissions.size() > 0){
			response.setTokenTypePermissions(of.createGetRolesTypeTokenTypePermissions());
			for(TokenTypePermission ttp : tokenTypePermissions){
				// Skip v 2.1 rules
				if(ttp.getRuleType() == TokenTypePermissionType.RECOVERKEYS){
					if(payloadVersion.equals("2.0")){
						continue;
					}
				}
				// Skip v 2.2 rules
				if(ttp.getRuleType() == TokenTypePermissionType.REQUEST){
					if(payloadVersion.equals("2.0") || payloadVersion.equals("2.1")){
						continue;
					}
				}
				// Skip v 2.3 rules
				if(ttp.getRuleType() == TokenTypePermissionType.BATCHUPDATE || ttp.getRuleType() == TokenTypePermissionType.IMPORT || ttp.getRuleType() == TokenTypePermissionType.EXPORT || ttp.getRuleType() == TokenTypePermissionType.UNBLOCK ){
					if(payloadVersion.equals("2.0") || payloadVersion.equals("2.1") || payloadVersion.equals("2.2")){
						continue;
					}
				}
				response.getTokenTypePermissions().getTokenTypePermission().add(ttp);
			}
		}
		
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response, false);
	}
	
}
