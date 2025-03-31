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
package org.signatureservice.messages;

/**
 * Exception thrown due to bad internal state when processing a PKIMessage resulting
 * in a ERROR response code in the PKIMessage protocol.
 * 
 * 
 * @author Philip Vendil
 *
 */
@Deprecated
public class MessageException extends MessageProcessingException {


	private static final long serialVersionUID = 1L;

	/**
	 * Exception thrown due to bad internal state when processing a PKIMessage resulting
     * in a ERROR response code in the PKIMessage protocol.
     * 
	 * @param message a descriptive message about the cause of the exception.
	 * @param cause the cause of the exception.
	 */
	public MessageException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Exception thrown due to bad internal state when processing a PKIMessage resulting
     * in a ERROR response code in the PKIMessage protocol.
     * 
	 * @param message a descriptive message about the cause of the exception.
	 */
	public MessageException(String message) {
		super(message);
	}
	
	

}
