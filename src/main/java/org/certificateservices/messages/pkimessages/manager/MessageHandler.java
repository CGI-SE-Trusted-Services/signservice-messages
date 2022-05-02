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
package org.certificateservices.messages.pkimessages.manager;

import java.io.IOException;
import java.util.Properties;

import org.certificateservices.messages.MessageException;
import org.certificateservices.messages.pkimessages.PKIMessageParser;


/**
 * Interface that a MQ message handler should implement in order to send and recieve messages
 * directly.
 * 
 * @author Philip Vendil
 *
 */
@SuppressWarnings({ "deprecation" })
public interface MessageHandler {
	
	/**
	 * Method called after instantiation and should check configuration and prepare
	 * everything for connection with the message queue server.
	 * 
	 * @param config the configuration.
	 * @param parser the message parser configuration.
	 * @param callback the callback interface where response messages are sent.
	 * @throws MessageException if configuration problems or other internal problems occurred.
	 */
	void init(Properties config, PKIMessageParser parser, MessageResponseCallback callback) throws MessageException;
	
	/**
	 * Method returning the connection factory used to set-up the message queues. Used only
	 * for special purposes when not extending the implementing class.
	 * 
	 * Required method for extending classes to provide the connection factory
	 * to use when connecting to the message server.
	 * 
	 * @return a connection factory to use to set up the message processing environment, never null.
	 * @throws MessageException if internal error or configuration problems occurred.
	 * @throws IOException if communication problems occurred with the message service.
	 */
	Object getConnectionFactory() throws MessageException, IOException;
	
	/**
	 * Method called by service if the MessageHandler should connect to the MessageQueue server and start processing incoming calls.
	 * @throws MessageException if configuration problems or other internal problems occurred connecting to the MQ server.
	 * @throws IOException if communication problems occurred connecting from the message server.
	 */
	void connect() throws MessageException, IOException;	
	
	/**
	 * Method to send a message to the MQ server out queue.
	 * 
	 * @param messageId the id of the message
	 * @param the message data to send
	 * @throws MessageException if configuration problems or other internal problems occurred connecting to the MQ server.
	 * @throws IOException if communication problems occurred connecting and sending to the message server.
	 */
	void sendMessage(String messageId, byte[] message)  throws MessageException, IOException;	

	/**
	 * Method returning if the handler is currently connected to the JMS broker.
	 * @return true if connected.
	 */
	public boolean isConnected();
	
	/**
	 * Method called by service if the MessageHandler should disconnect from the MessageQueue server.
	 * 
	 * @throws IOException if communication problems occurred disconnecting from the message server.
	 */
	void close() throws IOException;
}
