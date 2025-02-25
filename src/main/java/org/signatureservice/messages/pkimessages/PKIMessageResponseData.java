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
package org.signatureservice.messages.pkimessages;

import java.util.Arrays;

import org.signatureservice.messages.csmessages.CSMessageResponseData;


/**
 * Value class containing the result of a message processing call.
 * <p>
 * The information is mainly the response and PKI message destination.
 * 
 * @author Philip Vendil
 *
 */

public class PKIMessageResponseData extends CSMessageResponseData{
	

	/**
	 * Empty constructor
	 */
	public PKIMessageResponseData() {
		super();
	}

	/**
	 * Default constructor
	 * 
	 * @param messageId the related id of the message
	 * @param messageName the name of the message in the response
	 * @param relatedEndEntity the related end entity of the message.
	 * @param destination the PKI Message destination to send the message to.
	 * @param responseData the response data
	 */
	public PKIMessageResponseData(String messageId, String messageName, String relatedEndEntity, String destination,
			byte[] responseData) {
		super();
		this.messageId = messageId;
		this.setMessageName(messageName);
		this.setRelatedEndEntity(relatedEndEntity);
		this.destination = destination;
		this.responseData = responseData;
	}
	
	/**
	 * Constructor where it's possible to set if the response is
	 * a failure response.
	 * 
	 * @param messageId the related id of the message
	 * @param messageName the name of the message in the response
	 * @param relatedEndEntity the related end entity of the message.
	 * @param destination the PKI Message destination to send the message to.
	 * @param responseData the response data
	 * @param isForwardableResponse true if response is forwardable.
	 */
	public PKIMessageResponseData(String messageId,
			String messageName, String relatedEndEntity,
			String destination,
			byte[] responseData, boolean isForwardableResponse) {
		super();
		this.messageId = messageId;
		this.setMessageName(messageName);
		this.setRelatedEndEntity(relatedEndEntity);
		this.destination = destination;
		this.responseData = responseData;
		this.isForwardableResponse = isForwardableResponse;
	}
	


	@Override
	public String toString() {
		return "PKIMessageProcessResult [messageId=" + messageId
				+ ", destination=" + destination
				+ ", responseData=" + Arrays.toString(responseData)
				+ ", isForwardableResponse=" + isForwardableResponse + "]";
	}



}
