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
import org.certificateservices.messages.pkimessages.jaxb.PKIMessage;

/**
 * Message handler interface that all MQ implementations should implement, is in charge of
 * sending a request and wait for a response to occur.
 * @author Philip Vendil
 *
 */
@SuppressWarnings({ "deprecation" })
public interface MessageManager {

	
	/**
	 * Initialization method that should be called before first use. Usually called by the MQCertificateManager.
	 * 
	 * @param config configuration properties specific for a mq certificate manager. 
	 * Available property keys is depending on underlying implementation.
	 * @param parser message parser to use
	 * @param destination the destination of sent messages
	 * 
	 * @throws IllegalArgumentException if arguments sent to the method were illegal or the given property file contained bad configuration.
	 * @throws IOException if communication problems occurred with underlying systems, such as time-out.
	 * @throws MessageException if there were an critical internal error at the server side, that wasn't related to communication problems.
	 */
	void init(Properties config, PKIMessageParser parser, String destination) throws IllegalArgumentException, IOException, MessageException;
	
	
	/**
	 * Method called by service if the underlying MessageHandler should connect to the MessageQueue server and start processing incoming calls.
	 * @throws MessageException if configuration problems or other internal problems occurred connecting to the MQ server.
	 * @throws IOException if communication problems occurred connecting from the message server.
	 */
	void connect() throws MessageException, IOException;	
	
	/**
	 * Method returning the JMS connection factory used in underlying classes.
	 * <p>
	 * Used only for special purposes. and requires a JMS infrastructure underneath otherwise
	 * is a PKIMessageException thrown.
	 *
	 * 
	 * @return a connection factory to use to set up the message processing environment, never null.
	 * @throws MessageException if internal error or configuration problems occurred.
	 * @throws IOException if communication problems occurred with the message service.
	 */
	Object getConnectionFactory() throws MessageException, IOException;
	
	/**
	 * Method to return a reference to the underlying message handler used.
	 * @return underlying message handler used.
	 */
	MessageHandler getMessageHandler();
	
	/**
	 * Method that sends a request to message server and should wait for a response.
	 * 
	 * @param request the request message to send
	 * @returns the response message, never null, if timeout happened is an IOException thrown.
	 * @throws IllegalArgumentException if request contained invalid data.
	 * @throws IOException if communication problems occurred with underlying systems, such as time-out.
	 * @throws MessageException if there were an critical internal error at the server side, that wasn't related to communication problems.
	 */
	PKIMessage sendMessage(String requestId, byte[] request) throws IllegalArgumentException, IOException, MessageException;
	
	/**
	 * Method returning if the underlying message handler is currently connected.
	 * @return true if connected.
	 */
	public boolean isConnected();
	
	/**
	 * Method that should close all underlying connections and release all resources connected
	 * to the message handler.
	 * 
	 * @throws IOException if problems occurred closing the connections. 
	 */
	void close() throws IOException;
}
