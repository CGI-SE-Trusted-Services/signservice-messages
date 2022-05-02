/************************************************************************
*                                                                       *
*  Certificate Service - PKI Messages                                   *
*                                                                       *
*  This software is free software; you can redistribute it and/or       *
*  modify it under the terms of the GNU Lesser General Public License   *
*  License as published by the Free Software Foundation; either         *
*  version 3   of the License, or any later version.                    *
*                                                                       *
*  See terms of license at gnu.org.                                     *
*                                                                       *
*************************************************************************/
package org.certificateservices.messages;

/**
 * Exception thrown when internal error occurred during processing of an
 * message, this could be of bad configuration or library dependencies missing.
 * 
 * 
 * @author Philip Vendil
 *
 */
public class MessageProcessingException extends Exception {


	private static final long serialVersionUID = 1L;

	/**
	 * Exception thrown when internal error occurred during processing of an
     * message, this could be of configuration or library dependencies missing.
     * 
	 * @param message a descriptive message about the cause of the exception.
	 * @param cause the cause of the exception.
	 */
	public MessageProcessingException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Exception thrown when internal error occurred during processing of an
     * message, this could be of bad configuration or library dependencies missing.
     * 
	 * @param message a descriptive message about the cause of the exception.
	 */
	public MessageProcessingException(String message) {
		super(message);
	}
	
	

}
