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
 * Exception thrown when no decryption key could be found when trying to decrypt a message.
 * 
 * 
 * @author Philip Vendil
 *
 */
public class NoDecryptionKeyFoundException extends Exception {


	private static final long serialVersionUID = 1L;

	/**
	 * Exception thrown when no decryption key could be found when trying to decrypt a message
     * 
	 * @param message a descriptive message about the cause of the exception.
	 * @param cause the cause of the exception.
	 */
	public NoDecryptionKeyFoundException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Exception thrown when no decryption key could be found when trying to decrypt a message
     * 
	 * @param message a descriptive message about the cause of the exception.
	 */
	public NoDecryptionKeyFoundException(String message) {
		super(message);
	}
	
	

}
