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
package org.signatureservice.messages.receipts;

import java.util.List;
import java.util.Properties;

import org.signatureservice.messages.MessageSecurityProvider;

/**
 * @author Philip Vendil
 *
 */
public interface ReceiptParser {
	
	/**
	 * Method that initializes the receipt parser with property set.
	 * 
	 * @param securityProvider the message security provider to use.
	 * @param config the configuration of the parser.
	 * @throws ReceiptMessageException if configuration contained bad configuration of security provider.
	 */
	void init(MessageSecurityProvider securityProvider, Properties config) throws ReceiptMessageException;
	
	/**
	 * Method to parse the messageData into a ReceiptMessage with validation according to the
	 * specification.
	 * 
	 * @param messageData the message data to parse
	 * @return a list of ReceiptMessage that is valid, never null.
	 * @throws IllegalArgumentException if receipt message contained invalid data not conforming to the standard.
	 * @throws ReceiptMessageException if internal state occurred when processing the message
	 */
	List<ReceiptMessage> parseMessage(byte[] messageData) throws IllegalArgumentException, ReceiptMessageException;
	
	/**
	 * Method to generate a receipt message from the supplied data. Using destination node
	 * specified in configuration (if applicable).
	 * 
	 * @param messageId the unique message id
	 * @param status the status of the receipt message
	 * @param errorDescription optional error description, null if not applicable
	 * @return a generated receipt message, never null.
	 * @throws IllegalArgumentException if supplied arguments were invalid.
	 * @throws ReceiptMessageException if internal problems occurred when generating the receipt message.
	 */
	byte[] genReceiptMessage(String messageId, ReceiptStatus status, String errorDescription)  throws IllegalArgumentException, ReceiptMessageException;

	/**
	 * Alternative method to generate a receipt message from the supplied data but with a specified
	 * destination in header data. (if applicable).
	 * 
	 * @param messageId the unique message id
	 * @param status the status of the receipt message
	 * @param errorDescription optional error description, null if not applicable
	 * @return a generated receipt message, never null.
	 * @throws IllegalArgumentException if supplied arguments were invalid.
	 * @throws ReceiptMessageException if internal problems occurred when generating the receipt message.
	 */
	byte[] genReceiptMessage(String destinationNode, String messageId, ReceiptStatus status, String errorDescription)  throws IllegalArgumentException, ReceiptMessageException;
	
}
