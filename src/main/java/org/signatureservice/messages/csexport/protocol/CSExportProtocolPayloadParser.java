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
package org.signatureservice.messages.csexport.protocol;


import org.signatureservice.messages.MessageContentException;
import org.signatureservice.messages.MessageProcessingException;
import org.signatureservice.messages.csexport.data.jaxb.CSExport;
import org.signatureservice.messages.csexport.protocol.jaxb.GetCSExportRequest;
import org.signatureservice.messages.csexport.protocol.jaxb.GetCSExportResponse;
import org.signatureservice.messages.csexport.protocol.jaxb.ObjectFactory;
import org.signatureservice.messages.csexport.protocol.jaxb.QueryParameter;
import org.signatureservice.messages.csmessages.BasePayloadParser;
import org.signatureservice.messages.csmessages.CSMessageResponseData;
import org.signatureservice.messages.csmessages.PayloadParser;
import org.signatureservice.messages.csmessages.jaxb.CSMessage;
import org.signatureservice.messages.csmessages.jaxb.CSResponse;
import org.signatureservice.messages.csmessages.jaxb.Credential;
import org.signatureservice.messages.csmessages.jaxb.RequestStatus;

import javax.xml.bind.JAXBElement;
import java.io.InputStream;
import java.util.List;

/**
 * Payload Parser for generating CS Export Protocol messages according to
 * cs_export_protocol_schema2_0.xsd
 * 
 * @author Philip Vendil
 *
 */
public class CSExportProtocolPayloadParser extends BasePayloadParser {
	
	public static String NAMESPACE = "http://certificateservices.org/xsd/cs_export_protocol2_0";


	public static final String CS_EXPORT_PROTOCOL_XSD_SCHEMA_2_0_RESOURCE_LOCATION = "/cs_export_protocol_schema2_0.xsd";

	private ObjectFactory of = new ObjectFactory();
	
	private static final String[] SUPPORTED_CSEXPORT_PROTOCOL_VERSIONS = {"2.0"};
	
	private static final String DEFAULT_CSEXPORT_PROTOCOL__VERSION = "2.0";
	
	
	/**
	 * @see PayloadParser#getJAXBPackage()
	 */
	public String getJAXBPackage() {
		return "org.signatureservice.messages.csexport.protocol.jaxb";
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
    		return getClass().getResourceAsStream(CS_EXPORT_PROTOCOL_XSD_SCHEMA_2_0_RESOURCE_LOCATION);
    	}
    	
    	throw new MessageContentException("Error unsupported CS Export Protocol Payload version: " + payLoadVersion);
	}
	
	/**
	 * @see BasePayloadParser#getSupportedVersions()
	 */
	@Override
	protected String[] getSupportedVersions() {
		return SUPPORTED_CSEXPORT_PROTOCOL_VERSIONS;
	}

	/**
	 * @see BasePayloadParser#getDefaultPayloadVersion()
	 */
	@Override
	protected String getDefaultPayloadVersion() {
		return DEFAULT_CSEXPORT_PROTOCOL__VERSION;
	}
	



	/**
	 *  Method to create a GetRequesterRolesRequest message for a specified version of the CSExportData version..
	 *
	 * @param requestId the id of the request
	 * @param destinationId the destinationId used in the CSMessage.
	 * @param organisation the related organisation
	 * @param exportDataVersion version of the export data to export
	 * @param queryParameters a list of query parameters, if null or empty list will no query parameters be specified.
	 * @param originator the original requester of a message, null if not applicable
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return generated and signed CSMessage in byte[] format.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public byte[] genGetCSExportRequest(String requestId, String destinationId, String organisation, String exportDataVersion, List<QueryParameter> queryParameters, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		GetCSExportRequest payload = of.createGetCSExportRequest();
		payload.setExportDataVersion(exportDataVersion);

		if(queryParameters != null && queryParameters.size() > 0){
			GetCSExportRequest.QueryParameters params = of.createGetCSExportRequestQueryParameters();
			params.getQueryParameter().addAll(queryParameters);
			payload.setQueryParameters(params);
		}

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}

	/**
	 * Method to a GetRequesterRolesResponse message and populating it with the all requesters authorized roles.
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the request to populate the response with
	 * @param exportDataVersion version of the export data to export
	 * @param csExportData The CSExport Data to set in the response.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated message.
	 * @throws MessageContentException if CS message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the CSMessage
	 */
	public CSMessageResponseData genGetCSExportResponse(String relatedEndEntity, CSMessage request, String exportDataVersion, Object csExportData, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		GetCSExportResponse response = of.createGetCSExportResponse();
		response.setExportDataVersion(exportDataVersion);
		response.setResult(of.createResult());
		response.getResult().setAny(csExportData);

		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), response, false);
	}

	/**
	 * Help method to extract the CSExport data form a GetCSExportResponse CSMessage.
	 *
	 * @param resp the CSMessage, never null
	 * @return he internal CSExport object.
	 * @throws MessageContentException when failure illegal argument message response is received.
	 * @throws MessageProcessingException when no CS export data can be parsed from response.
	 */
	public CSExport getCSExportDataFromResponse(CSMessage resp) throws MessageContentException, MessageProcessingException {
		try {
			Object responsePayload = resp.getPayload().getAny();
			if (responsePayload instanceof JAXBElement<?> && ((JAXBElement<?>) responsePayload).getValue() instanceof CSResponse) {
				CSResponse csResponse = (CSResponse) ((JAXBElement<?>) responsePayload).getValue();
				RequestStatus requestStatus = csResponse.getStatus();
				if (requestStatus.equals(RequestStatus.ILLEGALARGUMENT)) {
					throw new MessageContentException("Failure CSExport response; status: " + requestStatus.toString() + ", message: " + csResponse.getFailureMessage());
				} else if (requestStatus.equals(RequestStatus.ERROR) || requestStatus.equals(RequestStatus.APPROVALREQUIRED) || requestStatus.equals(RequestStatus.NOTAUTHORIZED)) {
					throw new MessageProcessingException("Failure CSExport response; status: " + requestStatus.toString() + ", message: " + csResponse.getFailureMessage());
				}
			}

			if (responsePayload instanceof GetCSExportResponse) {
				return (CSExport) (((GetCSExportResponse) responsePayload).getResult().getAny());
			}

		} catch (MessageContentException e) {
			throw e;
		} catch (MessageProcessingException e) {
			throw e;
		} catch (Exception e) {
			throw new MessageProcessingException("Error parsing CSExport response from message: " + e.getMessage(), e);
		}

		throw new MessageProcessingException("Error parsing CSExport response from message, make sure it is a CSResponse object.");

	}
}
