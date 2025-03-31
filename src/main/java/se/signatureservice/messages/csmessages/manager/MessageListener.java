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
import java.util.Set;

import se.signatureservice.messages.MessageContentException;
import se.signatureservice.messages.MessageProcessingException;

/**
 * Interface of a message listener implementation.
 * 
 * @author Philip Vendil
 *
 */
public interface MessageListener extends MessageComponent {

	/**
	 * Used to add a messageResponse Callback to a message lister.
	 * 
	 * @param alias of the response callback. Should be unique within the message listener.
	 * @param messageResponseCallback the callback to register.
	 * @param messageResponseCallback
	 */
	void registerCallback(String alias, MessageResponseCallback messageResponseCallback);
	
	/**
	 * 
	 * @return a list of registered aliases of response callbacks.
	 */
	Set<String> getCallbackAliases();
	
	/**
	 * Method to unregister a callback from a message listener.
	 * @param alias  of the response callback. Should be unique within the message listener.
	 */
	void unregisterCallback(String alias);
	
	/**
	 * Method signaling that a response was received.
     * 
	 * @param responseMessage the response message that was received.
	 * @param messageAttributes meta data related to the message such as reply-to queues or correlation id etc if underlying implementation supports it.
	 * @throws IOException if communication problems occurred when communicating with underlying system. 
	 * @throws MessageProcessingException if internal problems occurred sending the message.
	 * @throws MessageContentException if message content invalid.
	 */
	public void responseReceived(byte[] responseMessage, Map<String, String> messageAttributes) throws IOException, MessageProcessingException, MessageContentException;
	
}
