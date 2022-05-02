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
package org.certificateservices.messages.receipts;

/**
 * Enumeration defining available receipt status
 * @author Philip Vendil
 *
 */
public enum ReceiptStatus {
	
	/**
	 * Indicating that message have be sent, but no receipt have yet been received.
	 */
	SENT(0),
	/**
	 * Indicating that message have received the message OK, and receipt received.
	 */
	RECIEVED_OK(1),
	/**
	 * Indicating that message have processed the message OK, and completed the transaction, this step is not required in some workflows..
	 */
	VERIFIED_OK(2),
	/**
	 * Indicating that message was received but resulted in an error in the header on the receiving side.
	 */
	RECIEVED_WITH_HEADER_ERROR(-1),
	/**
	 * Indicating that message was received but resulted in an error in the payload on the receiving side.
	 */
	RECIEVED_WITH_PAYLOAD_ERROR(-2),
	/**
	 * Indicating that message was received but resulted in an error due to bad signature
	 */
	RECIEVED_WITH_BAD_SIGNATURE(-3),
	/**
	 * Indicating that an error occurred when sending the message.
	 */
	ERROR_SENDING_MESSAGE(-4);
	
	private int id;

	private ReceiptStatus(int id){
		this.id = id;
	}
	
	/**
	 * 
	 * @return the integer representation of this receipt status.
	 */
	public int getId(){
		return id;
	}
	
	/**
	 * Finds the corresponding status or null if no status was found.
	 */
	public static ReceiptStatus findById(int id){
		for(ReceiptStatus s : ReceiptStatus.values()){
			if(s.getId() == id){
				return s;
			}
		}
		return null;
	}
}
