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
package org.certificateservices.messages.pkimessages.manager;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;

import org.certificateservices.messages.MessageException;
import org.certificateservices.messages.pkimessages.DefaultPKIMessageParser;
import org.certificateservices.messages.pkimessages.PKIMessageParser;
import org.certificateservices.messages.pkimessages.constants.AvailableCredentialStatuses;
import org.certificateservices.messages.pkimessages.jaxb.Credential;
import org.certificateservices.messages.pkimessages.jaxb.IssueTokenCredentialsResponse;
import org.certificateservices.messages.pkimessages.jaxb.PKIMessage;
import org.certificateservices.messages.pkimessages.jaxb.PKIResponse;
import org.certificateservices.messages.pkimessages.jaxb.RequestStatus;
import org.certificateservices.messages.utils.MessageGenerateUtils;

/**
 * Message manager in charge of sending a request and waiting for the response for
 * a given time before a time out IOException is thrown.
 * <p>
 * If a IssueTokenRequest message is processed, but not returned in time is a 
 * revoke message sent back to the client.
 * 
 * @author Philip Vendil
 *
 */
@SuppressWarnings({ "deprecation" })
public class DefaultMessageManager implements MessageManager, MessageResponseCallback{
	
	private static Logger log = Logger.getLogger(DefaultMessageManager.class.getName());

	private  Map<String, RequestEntry> responseMap = new HashMap<String, RequestEntry>();
	  
	/**
	 * Setting indicating the time-out of a message in milli-seconds before IOException is thrown.
	 */
	public static final String SETTING_MESSAGE_TIMEOUT_MILLIS = "mq.message.timeout";
	public static final String DEFAULT_MESSAGE_TIMEOUT_MILLIS = "60000"; // 60 seconds 	
	
	/**
	 * Setting indicating the message handler to use to send and receive the messages.
	 */
	public static final String SETTING_MESSAGEHANDLER_CLASSPATH = "mq.messagehandler.impl";

	
	protected static String REVOKE_REASON_REASONINFORMATION_CESSATIONOFOPERATION = "5"; 
	
	protected static long SLEEP_INTERVAL_MILLIS = 100;
	protected PKIMessageParser parser;
	protected String destination;
	protected MessageHandler messageHandler;
	protected long timeout;
	
	/** 
	 * Method that initializes the message manager
	 * 
	 * @see org.certificateservices.messages.pkimessages.manager.MessageManager#init(Properties, PKIMessageParser, String)
	 */	
	public void init(Properties config, PKIMessageParser parser, String destination) throws IllegalArgumentException,
			IOException, MessageException {
		this.destination = destination;
		this.parser = parser;
		
		timeout = getTimeOutInMillis(config);
		
		this.messageHandler = getMessageHandler(config, parser);
		
	}

	/**
	 * Main method signaling sending a request with given id and waits for a response
	 * for a given time before a time-out IO exception is thrown.
	 */
	public PKIMessage sendMessage(String requestId, byte[] request) throws IllegalArgumentException,
			IOException, MessageException {
		PKIMessage retval = null;
		
		registerWaitForRequestId(requestId);
		messageHandler.sendMessage(requestId, request);
				
		long waitTime = 0;
		while(waitTime < timeout){
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
	 * Method called by the MessageHandler when receiving a message intended for this
	 * message manager.
	 */
	public void responseReceived(PKIMessage responseMessage){
		String requestId = findRequestId(responseMessage);
		if(requestId != null){
			boolean stillWaiting = populateResponseMapIfStillExist(requestId, responseMessage);
			if(!stillWaiting){
				IssueTokenCredentialsResponse itcr = responseMessage.getPayload().getIssueTokenCredentialsResponse();
				if(itcr != null){
					if(itcr.getStatus() == RequestStatus.SUCCESS){
						// Issuance was successful but request timed-out, sending revocation message.
						if( itcr.getCredentials() != null && itcr.getCredentials().getCredential() != null){
							for(Credential c : itcr.getCredentials().getCredential()){
								// Send revocation request
								try {
									String messageId = MessageGenerateUtils.generateRandomUUID();
									byte[] revokeMessage = parser.genChangeCredentialStatusRequest(messageId,destination, responseMessage.getOrganisation(), c.getIssuerId(), c.getSerialNumber(), AvailableCredentialStatuses.REVOKED, REVOKE_REASON_REASONINFORMATION_CESSATIONOFOPERATION, DefaultPKIMessageParser.getOriginatorFromRequest(responseMessage));
									messageHandler.sendMessage(messageId, revokeMessage);
								} catch (IOException e) {
									log.severe("Error revoking timed-out certificate, io exception: " + e.getMessage());
								} catch (MessageException e) {
									log.severe("Error revoking timed-out certificate, internal error: " + e.getMessage());
								} catch (IllegalArgumentException e) {
									log.severe("Error revoking timed-out certificate, illegal argument: " + e.getMessage());
								} 															
							}
						}
					}
				}
			}
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
	protected synchronized PKIMessage checkIfResponseIsReady(String requestId){
		PKIMessage retval = null;
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
	protected synchronized boolean populateResponseMapIfStillExist(String requestId, PKIMessage responseMessage){
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
	protected String findRequestId(PKIMessage responseMessage) {
		String retval = null;
		PKIResponse response = findResponsePayload(responseMessage);
		if(response != null){
			retval = response.getInResponseTo();
		}
		
		if(retval != null){
			retval = retval.trim();
		}
		
		return retval;
	}
	
	protected PKIResponse findResponsePayload(PKIMessage responseMessage){
		if(responseMessage.getPayload().getGetCredentialResponse() != null){
			return responseMessage.getPayload().getGetCredentialResponse();
		}
		if(responseMessage.getPayload().getFailureResponse() != null){
			return responseMessage.getPayload().getFailureResponse();
		}
		if(responseMessage.getPayload().getIssueTokenCredentialsResponse() != null){
			return responseMessage.getPayload().getIssueTokenCredentialsResponse();
		}
		if(responseMessage.getPayload().getChangeCredentialStatusResponse() != null){
			return responseMessage.getPayload().getChangeCredentialStatusResponse();
		}
		if(responseMessage.getPayload().getFetchHardTokenDataResponse() != null){
			return responseMessage.getPayload().getFetchHardTokenDataResponse();
		}
		if(responseMessage.getPayload().getGetCredentialStatusListResponse() != null){
			return responseMessage.getPayload().getGetCredentialStatusListResponse();
		}
		if(responseMessage.getPayload().getGetIssuerCredentialsResponse() != null){
			return responseMessage.getPayload().getGetIssuerCredentialsResponse();
		}
		if(responseMessage.getPayload().getIsIssuerResponse() != null){
			return responseMessage.getPayload().getIsIssuerResponse();
		}
		if(responseMessage.getPayload().getIssueCredentialStatusListResponse() != null){
			return responseMessage.getPayload().getIssueCredentialStatusListResponse();
		}
		if(responseMessage.getPayload().getRemoveCredentialResponse() != null){
			return responseMessage.getPayload().getRemoveCredentialResponse();
		}
		if(responseMessage.getPayload().getStoreHardTokenDataResponse() != null){
			return responseMessage.getPayload().getStoreHardTokenDataResponse();
		}
		
		return null;
	}


	/**
	 * Closes the underlying connection.
	 * @see MessageManager#close()
	 */
	public void close() throws IOException {
		messageHandler.close();
	}


	/**
	 * A request entry is used the the request map after a send message call i waiting
	 * for a response, contains a response PKI Message data.
	 * 
	 * @author Philip Vendil
	 *
	 */
	protected class RequestEntry{
		
		private PKIMessage response;

		
		public PKIMessage getResponse() {
			return response;
		}
		public void setResponse(PKIMessage response) {
			this.response = response;
		}
	}
	
	/**
	 * Returns the message handler to use, if not configured is the default message handler created and returned.
	 */
	protected MessageHandler getMessageHandler(Properties config, PKIMessageParser parser) throws MessageException, IllegalArgumentException, IOException{
		try{
			String classPath = config.getProperty(SETTING_MESSAGEHANDLER_CLASSPATH);
			if(classPath == null){
				throw new MessageException("Error no message handler configured with setting: " + SETTING_MESSAGEHANDLER_CLASSPATH);
			}			
			Class<?> c = Thread.currentThread().getContextClassLoader().loadClass(classPath);
			
			MessageHandler retval = (MessageHandler) c.newInstance();
			retval.init(config, parser, this);
			return retval;
		}catch(Exception e){
			if(e instanceof MessageException){
				throw (MessageException) e;
			}
			if(e instanceof IllegalArgumentException){
				throw (IllegalArgumentException) e;
			}
			if(e instanceof IOException){
				throw (IOException) e;
			}
			throw new MessageException("Error creating Message Handler: " + e.getMessage(),e);
		}
	}
	
	
	public static long getTimeOutInMillis(Properties config) throws MessageException{
		String timeout = config.getProperty(SETTING_MESSAGE_TIMEOUT_MILLIS, DEFAULT_MESSAGE_TIMEOUT_MILLIS);
		try{
			return Long.parseLong(timeout);
		}catch(Exception e){
			throw new MessageException("Invalid timout value in configuration, check setting: " + SETTING_MESSAGE_TIMEOUT_MILLIS);
		}
	}

	public Object getConnectionFactory() throws MessageException,
			IOException {
		return messageHandler.getConnectionFactory();		
	}

	public void connect() throws MessageException, IOException {
		messageHandler.connect();
		
	}

	public MessageHandler getMessageHandler() {
		return messageHandler;
	}

	public boolean isConnected() {
		return messageHandler.isConnected();
	}
}
