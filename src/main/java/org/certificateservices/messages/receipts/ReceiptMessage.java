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

import java.util.Date;

/**
 * Value object containing all the information about a receipt message.
 * 
 * @author Philip Vendil
 *
 */
public class ReceiptMessage {

	private String messageId;
	private ReceiptStatus status;
	private String errorDescription;
	private Date timeStamp;
	
	/**
	 * Default constructor for a receipt message.
	 * 
	 * @param messageId the id of the message, never null
	 * @param status  
	 * @param errorDescription optional error description, or null if not applicable.
	 */
	public ReceiptMessage(String messageId, ReceiptStatus status, String errorDescription){
		this.messageId = messageId;
		this.status = status;
		this.errorDescription = errorDescription;
	}

	/**
	 * Default constructor for a receipt message.
	 *
	 * @param messageId the id of the message, never null
	 * @param status
	 * @param errorDescription optional error description, or null if not applicable.
	 * @param timeStamp the timestamp when the reciept was sent, optional can be null
	 */
	public ReceiptMessage(String messageId, ReceiptStatus status, String errorDescription, Date timeStamp){
		this.messageId = messageId;
		this.status = status;
		this.errorDescription = errorDescription;
		this.timeStamp = timeStamp;
	}


	
	/**
	 * 
	 * @return the id of the message, never null
	 */
	public String getMessageId() {
		return messageId;
	}
	
	/**
	 * 
	 * @param messageId the id of the message, never null
	 */
	public void setMessageId(String messageId) {
		this.messageId = messageId;
	}
	
	/**
	 * 
	 * @return the current status of the message.
	 */
	public ReceiptStatus getStatus() {
		return status;
	}
	
	/**
	 * 
	 * @param status the current status of the message.
	 */
	public void setStatus(ReceiptStatus status) {
		this.status = status;
	}
	
	/**
	 * 
	 * @return optional error description, or null if not applicable.
	 */ 
	public String getErrorDescription() {
		return errorDescription;
	}
	
	/**
	 * 
	 * @param errorDescription optional error description, or null if not applicable.
	 */
	public void setErrorDescription(String errorDescription) {
		this.errorDescription = errorDescription;
	}

	/**
	 *
	 * @return the timestamp when the reciept was sent, optional can be null
	 */
	public Date getTimeStamp() {
		return timeStamp;
	}

	/**
	 *
	 * @param timeStamp the timestamp when the reciept was sent, optional can be null
	 */
	public void setTimeStamp(Date timeStamp) {
		this.timeStamp = timeStamp;
	}

	@Override
	public String toString() {
		return "ReceiptMessage [messageId=" + messageId + ", status=" + status
				+ ", errorDescription=" + errorDescription + ", timeStamp=" + timeStamp + "]";
	}
	
	
}
