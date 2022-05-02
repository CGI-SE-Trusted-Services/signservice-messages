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
package org.certificateservices.messages.csmessages;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Properties;

import javax.xml.bind.Marshaller;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.MessageSecurityProvider;
import org.certificateservices.messages.csmessages.jaxb.ApprovalStatus;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.Credential;
import org.certificateservices.messages.csmessages.jaxb.RequestStatus;
import org.w3c.dom.Document;

public class TestCSMessageParser implements CSMessageParser {

	
	public void init(MessageSecurityProvider securityProvider, Properties config)
			throws MessageProcessingException {

	}

	
	public byte[] generateCSRequestMessage(String requestId,
			String destinationId, String organisation, String payLoadVersion,
			Object payload, List<Object> assertions)
			throws MessageContentException, MessageProcessingException {

		return null;
	}

	
	public byte[] generateCSRequestMessage(String requestId,
			String destinationId, String organisation, String payLoadVersion,
			Object payload, Credential originator, List<Object> assertions)
			throws MessageContentException, MessageProcessingException {

		return null;
	}

	
	public CSMessageResponseData generateCSResponseMessage(
			String relatedEndEntity, CSMessage request, String payLoadVersion,
			Object payload) throws MessageContentException,
			MessageProcessingException {

		return null;
	}

	
	public CSMessageResponseData generateCSResponseMessage(
			String relatedEndEntity, CSMessage request, String payLoadVersion,
			Object payload, boolean isForwarable)
			throws MessageContentException, MessageProcessingException {

		return null;
	}

	
	public byte[] generateGetApprovalRequest(String requestId,
			String destinationId, String organisation, byte[] request,
			Credential originator, List<Object> assertions)
			throws MessageContentException, MessageProcessingException {

		return null;
	}

	
	public byte[] generateIsApprovedRequest(String requestId,
			String destinationId, String organisation, String approvalId,
			Credential originator, List<Object> assertions)
			throws MessageContentException, MessageProcessingException {

		return null;
	}

	
	public CSMessageResponseData generateIsApprovedResponse(
			String relatedEndEntity, CSMessage request,
			ApprovalStatus approvalStatus, List<Object> assertions)
			throws MessageContentException, MessageProcessingException {

		return null;
	}

	
	public CSMessageResponseData generateGetApprovalResponse(
			String relatedEndEntity, CSMessage request, String approvalId,
			ApprovalStatus approvalStatus, List<Object> assertions)
			throws MessageContentException, MessageProcessingException {

		return null;
	}

	@Override
	public byte[] populateOriginatorAssertionsAndSignCSMessage(CSMessage message, String destinationId, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException {
		return null;
	}


	public CSMessageResponseData genCSFailureResponse(String relatedEndEntity,
			byte[] request, RequestStatus status, String failureMessage,
			String destinationID, Credential originator)
			throws MessageContentException, MessageProcessingException {

		return null;
	}

	
	public X509Certificate getSigningCertificate(byte[] request)
			throws MessageContentException, MessageProcessingException {

		return null;
	}

	
	public byte[] marshallAndSignCSMessage(CSMessage csMessage)
			throws MessageProcessingException, MessageContentException {

		return null;
	}

	public byte[] marshallCSMessage(CSMessage csMessage)
			throws MessageProcessingException, MessageContentException {

		return null;
	}

	
	public void validatePayloadObject(CSMessageVersion version,
			Object payLoadObject) throws MessageContentException {

	}

	
	public CSMessageVersion getVersionFromMessage(byte[] messageData)
			throws MessageContentException, MessageProcessingException {

		return null;
	}

	
	public CSMessage parseMessage(byte[] messageData)
			throws MessageContentException, MessageProcessingException {
		return null;
	}

	public CSMessage parseMessage(byte[] messageData, boolean performValidation)
			throws MessageContentException, MessageProcessingException {
		return null;
	}

	public CSMessage parseMessage(byte[] messageData, boolean performValidation, boolean requireSignature)
			throws MessageContentException, MessageProcessingException {
		return null;
	}
	
	public CSMessage genCSMessage(String version, String payLoadVersion,
			String requestName, String messageId, String destinationID,
			String organisation, Credential originator, Object payload,
			List<Object> assertions) throws MessageContentException,
			MessageProcessingException {
		return null;
	}

	
	public Credential getOriginatorFromRequest(CSMessage request) {
		return null;
	}

	
	public MessageSecurityProvider getMessageSecurityProvider() {
		return null;
	}

	
	public Marshaller getMarshaller(CSMessage message)
			throws MessageContentException {
		return null;
	}

	
	public CSMessage parseMessage(Document doc) throws MessageContentException,
			MessageProcessingException {
		return null;
	}

	@Override
	public CSMessage parseMessage(Document doc, boolean performValidation) throws MessageContentException, MessageProcessingException {
		return null;
	}

	public CSMessage parseMessage(Document doc, boolean performValidation, boolean requireSignature) throws MessageContentException,
			MessageProcessingException {
		return null;
	}

}
