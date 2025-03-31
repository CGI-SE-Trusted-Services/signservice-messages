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
package se.signatureservice.messages.csmessages.manager;

import java.util.Map;

import se.signatureservice.messages.MessageContentException;
import se.signatureservice.messages.MessageProcessingException;
import se.signatureservice.messages.csmessages.jaxb.CSMessage;

/**
 * Callback interface used to signal that a response targeted for this client (i.e destinationId = current sourceId)
 * <p>
 * Main method is responseRecieved
 * <p>
 * <b>Important</b> only messages with a destination matching this source id should be sent through
 * this callback.
 * 
 * @author Philip Vendil
 *
 */
public interface MessageResponseCallback {
	
	/**
	 * Method signaling that a response was received.
     * <p>
     * <b>Important</b> only messages with a destination matching this source id should be sent through
     * this callback.
     * @param requestData the original request data
	 * @param responseMessage the response message that was received.
	 * @param messageAttributes meta data related to the message such as reply-to queues or correlation id etc if underlying implementation supports it.
	 * @throws MessageContentException if content of the message was invalid.
	 * @throws MessageProcessingException if internal error occurred processing the message.
	 */
	public void responseReceived(byte[] requestData, CSMessage responseMessage, Map<String,String> messageAttributes) throws MessageContentException, MessageProcessingException;

}
