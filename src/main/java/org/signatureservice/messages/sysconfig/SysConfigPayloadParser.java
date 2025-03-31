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
package org.signatureservice.messages.sysconfig;

import java.io.InputStream;
import java.util.List;

import org.signatureservice.messages.MessageContentException;
import org.signatureservice.messages.MessageProcessingException;
import org.signatureservice.messages.csmessages.BasePayloadParser;
import org.signatureservice.messages.csmessages.CSMessageResponseData;
import org.signatureservice.messages.csmessages.PayloadParser;
import org.signatureservice.messages.csmessages.jaxb.CSMessage;
import org.signatureservice.messages.csmessages.jaxb.Credential;
import org.signatureservice.messages.sysconfig.jaxb.GetActiveConfigurationRequest;
import org.signatureservice.messages.sysconfig.jaxb.GetActiveConfigurationResponse;
import org.signatureservice.messages.sysconfig.jaxb.ObjectFactory;
import org.signatureservice.messages.sysconfig.jaxb.PublishConfigurationRequest;
import org.signatureservice.messages.sysconfig.jaxb.PublishConfigurationResponse;
import org.signatureservice.messages.sysconfig.jaxb.SystemConfiguration;

/**
 * Payload Parser for generating SysConfig messages according to 
 * sysconfig_schema2_0.xsd
 * 
 * @author Philip Vendil
 *
 */
public class SysConfigPayloadParser extends BasePayloadParser {
	
	public static String NAMESPACE = "http://certificateservices.org/xsd/sysconfig2_0";
	
	private static final String SYSCONFIG_XSD_SCHEMA_2_0_RESOURCE_LOCATION = "/sysconfig_schema2_0.xsd";

	
	private ObjectFactory of = new ObjectFactory();
	
	private static final String[] SUPPORTED_SYSCONFIG_VERSIONS = {"2.0"};
	
	private static final String DEFAULT_SYSCONFIG_VERSION = "2.0";
	
	
	/**
	 * @see PayloadParser#getJAXBPackage()
	 */
	public String getJAXBPackage() {
		return "org.signatureservice.messages.sysconfig.jaxb";
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
    		return getClass().getResourceAsStream(SYSCONFIG_XSD_SCHEMA_2_0_RESOURCE_LOCATION);
    	}
    	
    	throw new MessageContentException("Error unsupported SysConfig Payload version: " + payLoadVersion);
	}
	
	/**
	 * @see BasePayloadParser#getSupportedVersions()
	 */
	@Override
	protected String[] getSupportedVersions() {
		return SUPPORTED_SYSCONFIG_VERSIONS;
	}

	/**
	 * @see BasePayloadParser#getDefaultPayloadVersion()
	 */
	@Override
	protected String getDefaultPayloadVersion() {
		return DEFAULT_SYSCONFIG_VERSION;
	}
	
	
	/**
	 * 
	 * Method generate a Get Active Configuration Request.
	 * 
	 * @param requestId  id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param organisation the related organisation (short name)
	 * @param application the application name to fetch configuration for.
	 * @param originator the credential of the original requester, null if this is the origin of the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *  
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public byte[] generateGetActiveConfigurationRequest(String requestId, String destinationId, String organisation, String application, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		GetActiveConfigurationRequest payload = of.createGetActiveConfigurationRequest();
		payload.setApplication(application);
		payload.setOrganisationShortName(organisation);
		
		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * 
	 * Method generate a Get Active Configuration Response.
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param systemConfiguration the current active system configuration.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *  
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
    public CSMessageResponseData generateGetActiveConfigurationResponse(String relatedEndEntity, CSMessage request, SystemConfiguration systemConfiguration, List<Object> assertions) throws MessageContentException, MessageProcessingException{
    	GetActiveConfigurationResponse response = of.createGetActiveConfigurationResponse();
		response.setSystemConfiguration(systemConfiguration);
		
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}
	
	/**
	 * 
	 * Method generate a Publish Configuration Request
	 * 
	 * @param requestId  id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param organisation the related organisation (short name)
	 * @param systemConfiguration system configuration to publish to send.
	 * @param originator the credential of the original requester, null if this is the origin of the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *  
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public byte[] generatePublishConfigurationRequest(String requestId, String destinationId, String organisation, SystemConfiguration systemConfiguration, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		PublishConfigurationRequest payload = of.createPublishConfigurationRequest();
		payload.setSystemConfiguration(systemConfiguration);
		
		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}
	
	/**
	 * Method generate a Publish Configuration Response
	 *  
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return as success response back to the requestor.
	 * 
	 * @throws MessageContentException
	 * @throws MessageProcessingException
	 */
    public CSMessageResponseData generatePublishConfigurationResponse(String relatedEndEntity, CSMessage request, List<Object> assertions) throws MessageContentException, MessageProcessingException{
    	PublishConfigurationResponse response = of.createPublishConfigurationResponse();
		
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response);
	}




}
