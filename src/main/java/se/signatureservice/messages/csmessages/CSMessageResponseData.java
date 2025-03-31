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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import se.signatureservice.messages.csmessages.constants.Constants;
import se.signatureservice.messages.csmessages.jaxb.CSMessage;

/**
 * Value class containing the result of a message processing call.
 * <p>
 * The information is mainly the response and PKI message destination.
 * 
 * @author Philip Vendil
 *
 */
public class CSMessageResponseData {
	
	protected String messageId;
	protected String messageName;
	protected String relatedEndEntity;
	protected String destination;
	protected byte[] responseData;
	protected boolean isForwardableResponse = false;
	protected CSMessage responseMessage;
	protected Map<String,String> messageProperties = new HashMap<String,String>();
	
	
	/**
	 * Empty constructor
	 */
	public CSMessageResponseData() {
		super();
	}

	/**
	 * Default constructor
	 * 
	 * @param responseMessage The related response message.
	 * @param relatedEndEntity the related end entity of the message.
	 * @param responseData the response data
	 * @param isForwardableResponse true if response is forwardable.
	 */
	public CSMessageResponseData(CSMessage responseMessage,String relatedEndEntity,
			byte[] responseData, boolean isForwardableResponse) {
		super();
		this.responseMessage = responseMessage;
		this.messageId = responseMessage.getID();
		this.setMessageName(responseMessage.getName());
		this.setRelatedEndEntity(relatedEndEntity);
		this.destination = responseMessage.getDestinationId();
		this.responseData = responseData;
		this.isForwardableResponse = isForwardableResponse;
	}

	/**
	 * Alternative constructor when CSMessage is not available.
	 *
	 * @param messageId the related id of the message
	 * @param messageName the name of the message in the response
	 * @param relatedEndEntity the related end entity of the message.
	 * @param destination the PKI Message destination to send the message to.
	 * @param responseData the response data
	 */
	public CSMessageResponseData(String messageId, String messageName, String relatedEndEntity, String destination,
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
	public CSMessageResponseData(String messageId,
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
	
	/**
	 * Help method calculating if a method should be forwarded or not.
	 * <p>
	 * Does the following calculation:
	 * <li>Is PKI Message Destination not in exclude list
	 * <li>is not a failure response
	 * <li>if both are true is true returned
	 * @param excludedDestinations a set of excluded destinations.
	 * @return true if this message should be forwarded
	 */
	public boolean isForwardable(Set<String> excludedDestinations){
		boolean excluded = excludedDestinations.contains(destination.toUpperCase().trim());
		return isForwardableResponse && !excluded;
	}
	
	
	/**
	 * 
	 * @return the PKI Message destination to send the message to.
	 */
	public String getDestination() {
		return destination;
	}
	
	/**
	 * 
	 * @param destination the PKI Message destination to send the message to.
	 */
	public void setDestination(String destination) {
		this.destination = destination;
	}
	
	/**
	 * 
	 * @return the response data
	 */
	public byte[] getResponseData() {
		return responseData;
	}
	
	/**
	 * 
	 * @param responseData the response data
	 */
	public void setResponseData(byte[] responseData) {
		this.responseData = responseData;
	}
	
	/**
	 * 
	 * @return true if response is a forwardable or not.
	 */
	public boolean getIsForwardableResponse() {
		return isForwardableResponse;
	}

	/**
	 * 
	 * @param isForwardableResponse true if response is a failure indication.
	 */
	public void setIsForwardableResponse(boolean isForwardableResponse) {
		this.isForwardableResponse = isForwardableResponse;
	}
	
	/**
	 * 
	 * @return the related id of the message
	 */
	public String getMessageId() {
		return messageId;
	}

	/**
	 * 
	 * @param messageId the related id of the message
	 */
	public void setMessageId(String messageId) {
		this.messageId = messageId;
	}

	/**
	 * 
	 * @return the related end entity of the message.
	 */
	public String getRelatedEndEntity() {
		return relatedEndEntity != null ? relatedEndEntity : Constants.RELATED_END_ENTITY_UNKNOWN;
	}

	/**
	 * 
	 * @param relatedEndEntity the related end entity of the message.
	 */
	public void setRelatedEndEntity(String relatedEndEntity) {
		this.relatedEndEntity = relatedEndEntity;
	}

	/**
	 * 
	 * @return the name of the message in the response
	 */
	public String getMessageName() {
		return messageName;
	}

	/**
	 * 
	 * @param messageName the name of the message in the response
	 */
	public void setMessageName(String messageName) {
		this.messageName = messageName;
	}

	/**
	 *
	 * @return responseMessage The related response message.
	 */
	public CSMessage getResponseMessage() {
		return responseMessage;
	}

	/**
	 *
	 * @param responseMessage The related response message.
	 */
	public void setResponseMessage(CSMessage responseMessage) {
		this.responseMessage = responseMessage;
	}

	/**
	 * Gets a map of extra properties related to a message, for specific purposes, for example
	 * JMS properties in a MQ environment.
	 * @return a map of properties, never null.
	 */
	public Map<String,String> getMessageProperties(){
		return messageProperties;
	}

	@Override
	public String toString() {
		return "CSMessageProcessResult [messageId=" + messageId
				+ ", destination=" + destination
				+ ", responseData=" + Arrays.toString(responseData)
				+ ", isForwardableResponse=" + isForwardableResponse + "]";
	}



}
