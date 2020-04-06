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
package org.certificateservices.messages.receipts;

/**
 * Exception thrown due to bad internal state when processing a RecieptMessage.
 * 
 * 
 * @author Philip Vendil
 *
 */
public class ReceiptMessageException extends Exception {


	private static final long serialVersionUID = 1L;

	/**
	 * Exception thrown due to bad internal state when processing a RecieptMessage.
     * 
	 * @param message a descriptive message about the cause of the exception.
	 * @param cause the cause of the exception.
	 */
	public ReceiptMessageException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Exception thrown due to bad internal state when processing a RecieptMessage.
     * 
	 * @param message a descriptive message about the cause of the exception.
	 */
	public ReceiptMessageException(String message) {
		super(message);
	}
	
	

}
