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

import se.signatureservice.messages.MessageProcessingException;
import se.signatureservice.messages.csmessages.jaxb.CSMessage;

/**
 * Interface for simulating a synchronous request and response call for asynchronous communication channels such as MQ.
 * 
 * @author Philip Vendil
 *
 */
public interface ReqRespManager {

	/**
	 * Main method signaling sending a request with given id and waits for a response
	 * for a given time before a time-out IO exception is thrown.
	 */
	 CSMessage sendRequest(String requestId, byte[] request)
			throws IllegalArgumentException, IOException,
			MessageProcessingException;

	/**
	 * Main method signaling sending a request with given id and waits for a response
	 * for a given time before a time-out IO exception is thrown.
	 * This methods provides optional requestAttributes containing meta-data about
	 * the message.
	 */
	CSMessage sendRequest(String requestId, byte[] request, Map<String,String> requestAttributes)
			throws IllegalArgumentException, IOException,
			MessageProcessingException;

}