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
import java.util.Properties;

import org.certificateservices.messages.MessageProcessingException;


/**
 * Interface that a MQ message handler should implement in order to send and recieve messages
 * directly.
 * 
 * @author Philip Vendil
 *
 */
public interface MessageHandler {
	
	/**
	 * Method called after instantiation and should check configuration and prepare
	 * everything for connection with the message queue server.
	 * 
	 * @param config the configuration.
	 * @throws MessageProcessingException if configuration problems or other internal problems occurred.
	 */
	void init(Properties config) throws MessageProcessingException;
	
	/**
	 * Method returning the connection factory used to set-up the message queues. Used only
	 * for special purposes when not extending the implementing class.
	 * 
	 * Required method for extending classes to provide the connection factory
	 * to use when connecting to the message server.
	 * 
	 * @return a connection factory to use to set up the message processing environment, never null.
	 * @throws MessageProcessingException if internal error or configuration problems occurred.
	 * @throws IOException if communication problems occurred with the message service.
	 */
	Object getConnectionFactory() throws MessageProcessingException, IOException;
	
	
	/**
	 * Method to add a sender to this  Message Handler, this method should be called before a connection.
	 * 
	 * @param sender a MessageSender implementation.
	 */
	public void addSender(MessageSender sender);
	
	/**
	 * Method to add a listener to this  Message Handler, this method should be called before a connection.
	 * 
	 * @param listener a MessageListener implementation.
	 */
	public void addListener(MessageListener listener);
	
	/**
	 * Method to retrieved a message sender given it's name.
	 * @param name the unique name of the sender.
	 * @throws MessageProcessingException if given name didn't exist or didn't correspond to a MessageSender.
	 */
	public MessageSender getMessageSender(String name) throws MessageProcessingException;
	
	/**
	 * Method to retrieved a message listener given it's name.
	 * @param name the unique name of the listener.
	 * @throws MessageProcessingException if given name didn't exist or didn't correspond to a MessageListener.
	 */
	public MessageListener getMessageListener(String name) throws MessageProcessingException;
	
	/**
	 * Method called by service if the MessageHandler should connect to the MessageQueue server and start processing incoming calls.
	 * @throws MessageProcessingException if configuration problems or other internal problems occurred connecting to the MQ server.
	 * @throws IOException if communication problems occurred connecting from the message server.
	 */
	void connect() throws MessageProcessingException, IOException;	
	
	/**
	 * Method to send a message to the MQ server out queue.
	 * 
	 * @param componentName the componentName to use for sending.
	 * @param messageId the id of the message
	 * @param message the message data to send
	 * @param messageAttributes meta data related to the message such as reply-to queues or correlation id etc if underlying implementation supports it. use null if no related
	 * message attributes exists.
	 * @throws MessageProcessingException if configuration problems or other internal problems occurred connecting to the MQ server.
	 * @throws IOException if communication problems occurred connecting and sending to the message server.
	 */
	void sendMessage(String componentName, String messageId, byte[] message, Map<String,String> messageAttributes)  throws MessageProcessingException, IOException;	

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
