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
package org.certificateservices.messages;

/**
 * Exception thrown due to bad content of a message.
 * 
 * 
 * @author Philip Vendil
 *
 */
public class MessageContentException extends Exception {


	private static final long serialVersionUID = 1L;

	/**
	 * Exception thrown due to bad content of a message.
     * 
	 * @param message a descriptive message about the cause of the exception.
	 * @param cause the cause of the exception.
	 */
	public MessageContentException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Exception thrown due to bad content of a message.
     * 
	 * @param message a descriptive message about the cause of the exception.
	 */
	public MessageContentException(String message) {
		super(message);
	}
	
	

}
