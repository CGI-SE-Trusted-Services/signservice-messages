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
package org.signatureservice.messages.heartbeat;

import java.util.Properties;

import org.signatureservice.messages.MessageContentException;
import org.signatureservice.messages.MessageProcessingException;
import org.signatureservice.messages.MessageSecurityProvider;

/**
 * Interface used for heart beat message parsers.
 * 
 * @author Philip Vendil
 *
 */
public interface HeartBeatParser {
	
	/**
	 * Method that initializes the heart beat parser with property set.
	 * 
	 * @param securityProvider the message security provider to use.
	 * @param config the configuration of the parser.
	 * @throws MessageProcessingException if configuration contained bad configuration of security provider.
	 */
	void init(MessageSecurityProvider securityProvider, Properties config) throws MessageProcessingException;
	
	/**
	 * Method to parse the messageData into a HeartBeatMessage with validation according to the
	 * specification.
	 * 
	 * @param messageData the message data to parse
	 * @return a heart beat message from the message data.
	 * @throws MessageContentException if receipt message contained invalid data not conforming to the standard.
	 * @throws MessageProcessingException if internal state occurred when processing the message
	 */
	HeartBeatMessage parseMessage(byte[] messageData) throws MessageContentException, MessageProcessingException;
	
	/**
	 * Method to generate a heart beat message from the supplied data.
	 * 
	 * @param heartBeatMessage the heart beat message data to transform into a message structure.
	 * @return a generated heart beat message, never null.
	 * @throws MessageContentException if supplied arguments were invalid.
	 * @throws MessageProcessingException if internal problems occurred when generating the heart beat message.
	 */
	byte[] genHeartBeatMessage(String messageId, HeartBeatMessage heartBeatMessage)  throws MessageContentException, MessageProcessingException;

}
