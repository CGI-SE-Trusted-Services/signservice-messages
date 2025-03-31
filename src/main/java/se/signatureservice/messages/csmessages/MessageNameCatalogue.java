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
package se.signatureservice.messages.csmessages;

import java.util.Properties;

import se.signatureservice.messages.MessageProcessingException;

public interface MessageNameCatalogue {
	
	/**
	 * Special request name that can be sent to the lookup method and indicates
	 * that the related message is a IssueCredentialStatusList that is automatically
	 * generated without any matching request.
	 */
	public static final String REQUESTNAME_CRLFORWARD = "CRLFORWARD";
	
	/**
	 * Default constructor
	 * @param config the properties file of the PKI message parser.
	 * @throws MessageProcessingException if an error occurred
	 */
	public void init(Properties config) throws MessageProcessingException;

	/**
	 * Method that looks up the name for a specific setting used to populate the 'name' attribute
	 * in the header.
	 *   
	 * @param requestName the related request name if applicable, null if this is a request. 
	 * @param payLoadObject the setting to look-up the name for. 
	 * @return the name of the message to use.
	 * @throws MessageException if name lookup failed due to internal connection problems.
	 * @throws IllegalArgumentException if name lookup failed due to bad request data
	 */
	public String lookupName(String requestName, Object payLoadObject) throws MessageProcessingException, IllegalArgumentException;
}