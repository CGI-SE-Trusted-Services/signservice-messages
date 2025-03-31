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

import java.io.IOException;
import java.util.Map;

import se.signatureservice.messages.MessageContentException;
import se.signatureservice.messages.MessageProcessingException;

/**
 * 
 * Message Sender is a component in charge of sending a message.
 * 
 * @author Philip Vendil
 *
 */
public interface MessageSender extends MessageComponent{
	
	
	/**
	 * Method to use to send a message 
	 * 
	 * @param requestId the requestId.
	 * @param message the message data to send.
	 * @param messageAttributes meta data related to the message such as reply-to queues or correlation id etc if underlying implementation supports it.
	 * @throws IOException if communication problems occurred when communicating with underlying system. 
	 * @throws MessageProcessingException if internal problems occurred sending the message.
	 * @throws MessageContentException if message content invalid.
	 */
	void sendMessage(String requestId, byte[] message, Map<String,String> messageAttributes) throws IOException, MessageProcessingException, MessageContentException;

}
