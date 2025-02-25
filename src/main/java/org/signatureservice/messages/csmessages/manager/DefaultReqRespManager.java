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
package org.signatureservice.messages.csmessages.manager;

import org.signatureservice.messages.MessageProcessingException;
import org.signatureservice.messages.csmessages.jaxb.CSMessage;
import org.signatureservice.messages.csmessages.jaxb.CSResponse;

import javax.xml.bind.JAXBElement;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Default request response manager sending a request on one queue and waiting for a response on a response queue.
 * 
 *
 * @author Philip Vendil
 *
 */
public class DefaultReqRespManager implements ReqRespManager,
		MessageResponseCallback {
	
	private static Logger log = Logger.getLogger(DefaultReqRespManager.class.getName());

	protected  Map<String, RequestEntry> responseMap = new HashMap<String, RequestEntry>();
	
	protected long timeOut;
	protected MessageHandler messageHandler;
	protected String messageListenerName;
	protected String messageSenderName;
	
	protected static long SLEEP_INTERVAL_MILLIS = 100;
	
	public static final String CALLBACK_ALIAS = "DefaultReqRespManager";
	
	/**
	 * Default constructor of a DefaultReqRespManager
	 * 
	 * @param timeOut time in milliseconds to wait for response.
	 * @param messageHandler, the related message handler.
	 * @param messageListenerName the name of the message listener to use, never null and must be registered in the message handler.
	 * @param messageSenderName the name of the message sender to use, never null and must be registered in the message handler.
	 * @throws MessageProcessingException if internal problems occurred setting up the request response manager.
	 */
	public DefaultReqRespManager(long timeOut, MessageHandler messageHandler, String messageSenderName, String messageListenerName) throws MessageProcessingException{
		this.timeOut = timeOut;
		this.messageHandler = messageHandler;
		this.messageSenderName = messageSenderName;
		this.messageListenerName = messageListenerName;
		// Register it self
		this.messageHandler.getMessageListener(messageListenerName).registerCallback(CALLBACK_ALIAS,this);
	}


	/**
	 * @see ReqRespManager#sendRequest(java.lang.String, byte[])
	 */
	@Override
	public CSMessage sendRequest(String requestId, byte[] request)
			throws IllegalArgumentException, IOException,
			MessageProcessingException {
		return sendRequest(requestId,request,null);
	}

	/**
	 * @see ReqRespManager#sendRequest(java.lang.String, byte[], Map)
	 */
	@Override
	public CSMessage sendRequest(String requestId, byte[] request, Map<String,String> requestAttributes)
			throws IllegalArgumentException, IOException,
			MessageProcessingException {
		CSMessage retval = null;

		registerWaitForRequestId(requestId);

		messageHandler.sendMessage(messageSenderName,requestId, request, requestAttributes);

		long waitTime = 0;
		while(waitTime < timeOut){
			retval = checkIfResponseIsReady(requestId);
			if(retval != null){
				break;
			}
			try {
				Thread.sleep(SLEEP_INTERVAL_MILLIS);
			} catch (InterruptedException e) {
				log.severe("waiting process interupted while waiting for MQ response: " + e.getMessage());
			}
			waitTime+= SLEEP_INTERVAL_MILLIS;

		}

		if(retval == null){
			cancelWaitForResponse(requestId);
			throw new IOException("Error: Timeout exception after waiting for message with request id: " + requestId);
		}

		return retval;
	}
	
	/**
	 * @see MessageResponseCallback#responseReceived(byte[], CSMessage, Map)
	 */
	@Override
	public void responseReceived(byte[] requestData, CSMessage responseMessage, Map<String, String> messageAttributes) {
		String requestId = findRequestId(responseMessage);
		if(requestId != null){
			populateResponseMapIfStillExist(requestId, responseMessage);
		}
	}
	
	/**
	 * Signals that the current manager is listening for this message.
	 * 
	 * @param requestId  the id of the message to register
	 */
	protected synchronized void registerWaitForRequestId(String requestId){
		responseMap.put(requestId, new RequestEntry());
	}
	
	/**
	 * Method to check if a response have been sent to a request with the given id.
	 * @param requestId the id to check for 
	 * @return the PKIMessage response or null if no response have been recieved yet.
	 */
	protected synchronized CSMessage checkIfResponseIsReady(String requestId){
		CSMessage retval = null;
		RequestEntry entry = responseMap.get(requestId);
		if(entry != null && entry.getResponse() != null){
			retval = entry.getResponse();
			responseMap.remove(requestId);
		}
		
		return retval;
	}
	

	/**
	 * Method signaling that the waiting thread have stopped listening for
	 * a response to this request.
	 */
	protected synchronized void cancelWaitForResponse(String requestId){
		responseMap.remove(requestId);
	}
	
	/**
	 * Method that is called by the responseRecieved method that it received a message
	 * to this listener and should populate the response map.
	 */
	protected synchronized boolean populateResponseMapIfStillExist(String requestId, CSMessage responseMessage){
		boolean retval = false;
		RequestEntry entry = responseMap.get(requestId);
		if(entry != null){
			entry.setResponse(responseMessage);
			retval = true;
		}
		
		return retval;
	}

	/**
	 * Method that extracts the requestId from the responseMessage. Where
	 * IssueTokenCredentialsResponse and GetCredentialResponse and FailureResponse is supported.
	 *  
	 * @param responseMessage the message to parse request id from
	 * @return the request id or null if no valid request id was found in the response
	 */
	protected String findRequestId(CSMessage responseMessage) {
		String retval = null;
		CSResponse response = findResponsePayload(responseMessage);
		if(response != null){
			retval = response.getInResponseTo();
		}
		
		if(retval != null){
			retval = retval.trim();
		}
		
		return retval;
	}
	
	protected CSResponse findResponsePayload(CSMessage responseMessage){

		Object payload = responseMessage.getPayload().getAny();
		if(payload instanceof CSResponse){
			return (CSResponse) payload;
		}
		if(payload instanceof JAXBElement<?>){
			Object innerPayload = ((JAXBElement<?>) payload).getValue();
			if(innerPayload instanceof CSResponse) {
				return (CSResponse) innerPayload;
			}
		}
		
		return null;
	}
	
	/**
	 * A request entry is used the the request map after a send message call i waiting
	 * for a response, contains a response PKI Message data.
	 * 
	 * @author Philip Vendil
	 *
	 */
	protected class RequestEntry{
		
		private CSMessage response;

		
		public CSMessage getResponse() {
			return response;
		}
		public void setResponse(CSMessage response) {
			this.response = response;
		}
	}
	


}
