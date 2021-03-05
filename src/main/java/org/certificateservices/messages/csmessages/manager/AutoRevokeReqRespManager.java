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
package org.certificateservices.messages.csmessages.manager;

import java.io.IOException;
import java.util.Map;
import java.util.logging.Logger;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.credmanagement.CredManagementPayloadParser;
import org.certificateservices.messages.credmanagement.jaxb.IssueTokenCredentialsResponse;
import org.certificateservices.messages.csmessages.CSMessageParser;
import org.certificateservices.messages.csmessages.constants.AvailableCredentialStatuses;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.Credential;
import org.certificateservices.messages.csmessages.jaxb.RequestStatus;
import org.certificateservices.messages.utils.MessageGenerateUtils;

/**
 * Request And Response Manager that can be used in issue token request workflows where time-out requests is automatically revoked.
 * 
 * @author Philip Vendil
 *
 */
public class AutoRevokeReqRespManager extends DefaultReqRespManager {
	
	private static Logger log = Logger.getLogger(AutoRevokeReqRespManager.class.getName());

	protected CSMessageParser csMessageParser;
	protected CredManagementPayloadParser credManagementPayloadParser;
	
	protected static String REVOKE_REASON_REASONINFORMATION_CESSATIONOFOPERATION = "5"; 
	
	public AutoRevokeReqRespManager(CSMessageParser csMessageParser, CredManagementPayloadParser credManagementPayloadParser,
			long timeOut, MessageHandler messageHandler, String messageSenderName,
			String messageListenerName) throws MessageProcessingException {
		super(timeOut, messageHandler, messageSenderName,
				messageListenerName);
		this.csMessageParser = csMessageParser;
		this.credManagementPayloadParser = credManagementPayloadParser;
	}

	
	/**
	 * Method called by the MessageHandler when receiving a message intended for this
	 * message manager.
	 */
	@Override
	public void responseReceived(byte[] requestData, CSMessage responseMessage, Map<String, String> messageAttributes){
		String requestId = findRequestId(responseMessage);
		if(requestId != null){
			boolean stillWaiting = populateResponseMapIfStillExist(requestId, responseMessage);
			if(!stillWaiting){
				if(responseMessage.getPayload().getAny() instanceof IssueTokenCredentialsResponse){
					IssueTokenCredentialsResponse itcr = (IssueTokenCredentialsResponse) responseMessage.getPayload().getAny();
					if(itcr.getStatus() == RequestStatus.SUCCESS){
						// Issuance was successful but request timed-out, sending revocation message.
						if( itcr.getCredentials() != null && itcr.getCredentials().getCredential() != null){
							for(Credential c : itcr.getCredentials().getCredential()){
								// Send revocation request
								try {
									String messageId = MessageGenerateUtils.generateRandomUUID();
									byte[] revokeMessage = credManagementPayloadParser.genChangeCredentialStatusRequest(messageId, responseMessage.getSourceId(), responseMessage.getOrganisation(), c.getIssuerId(), c.getSerialNumber(), AvailableCredentialStatuses.REVOKED, REVOKE_REASON_REASONINFORMATION_CESSATIONOFOPERATION, csMessageParser.getOriginatorFromRequest(responseMessage), null);
									messageHandler.sendMessage(messageSenderName, messageId, revokeMessage, messageAttributes);
								} catch (IOException e) {
									log.severe("Error revoking timed-out certificate, io exception: " + e.getMessage());
								} catch (MessageProcessingException e) {
									log.severe("Error revoking timed-out certificate, internal error: " + e.getMessage());
								} catch (MessageContentException e) {
									log.severe("Error revoking timed-out certificate, illegal message: " + e.getMessage());
								} 															
							}
						}
					}
				}
			}
		}		
	}
	
	
}
