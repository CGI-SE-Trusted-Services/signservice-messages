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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.signatureservice.messages.MessageContentException;
import org.signatureservice.messages.MessageProcessingException;
import org.signatureservice.messages.credmanagement.CredManagementPayloadParser;
import org.signatureservice.messages.credmanagement.jaxb.ChangeCredentialStatusRequest;
import org.signatureservice.messages.credmanagement.jaxb.GetCredentialRequest;
import org.signatureservice.messages.credmanagement.jaxb.IssueTokenCredentialsRequest;
import org.signatureservice.messages.csmessages.CSMessageParser;
import org.signatureservice.messages.csmessages.PayloadParserRegistry;
import org.signatureservice.messages.csmessages.constants.AvailableCredentialStatuses;
import org.signatureservice.messages.csmessages.constants.AvailableCredentialTypes;
import org.signatureservice.messages.csmessages.constants.Constants;
import org.signatureservice.messages.csmessages.jaxb.CSMessage;
import org.signatureservice.messages.csmessages.jaxb.Credential;
import org.signatureservice.messages.csmessages.jaxb.CredentialRequest;
import org.signatureservice.messages.csmessages.jaxb.ObjectFactory;
import org.signatureservice.messages.utils.MessageGenerateUtils;


@SuppressWarnings("all")
public class DummyMessageHandler implements MessageHandler{

	
	
	
	private CSMessageParser parser;
	private CredManagementPayloadParser credManagementPayloadParser;
	private ObjectFactory of = new ObjectFactory();
	private long waitTime;	

	private HashMap<String, MessageComponent> components = new HashMap<String,MessageComponent>();
	
	public boolean revokeMessageRecieved = false;

	public static final String SETTING_WAITTIME = "dummy.waittime";

	public void init(Properties config) throws MessageProcessingException {
		
		waitTime = Long.parseLong(config.getProperty(SETTING_WAITTIME));

		
		credManagementPayloadParser = (CredManagementPayloadParser) PayloadParserRegistry.getParser(CredManagementPayloadParser.NAMESPACE);
	}

	public void connect() throws MessageProcessingException, IOException {


	}

	public void sendMessage(String componentName, String messageId, byte[] messageData, Map<String,String> messageAttributes) throws MessageProcessingException,
	IOException {
		try{
			byte[] response = null;	
			CSMessage request = parser.parseMessage(messageData);

			if(request.getPayload().getAny() instanceof GetCredentialRequest){
				GetCredentialRequest gcr = (GetCredentialRequest) request.getPayload().getAny();		


				Credential c = of.createCredential();
				c.setCredentialData(base64Decode(base64Cert));
				c.setCredentialSubType(gcr.getCredentialSubType());
				c.setCredentialType(AvailableCredentialTypes.CREDENTIAL_TYPE_X509CERTIFICATE);
				c.setDisplayName("SomeDisplayName");
				c.setExpireDate(MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1)));
				c.setIssueDate(MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(2)));
				c.setIssuerId("CN=SomeIssuerId");
				c.setSerialNumber("abc123");
				c.setStatus(100);
				c.setUniqueId("SomeUniqueId");
				c.setValidFromDate(MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(3)));



				response = credManagementPayloadParser.genGetCredentialResponse(Constants.RELATED_END_ENTITY_UNKNOWN,request, c, null).getResponseData();

			}
			if(request.getPayload().getAny() instanceof IssueTokenCredentialsRequest){
				IssueTokenCredentialsRequest itr = (IssueTokenCredentialsRequest) request.getPayload().getAny();

				CredentialRequest cr = itr.getTokenRequest().getCredentialRequests().getCredentialRequest().get(0);
				Credential c = of.createCredential();
				c.setCredentialData(base64Decode(base64Cert));
				c.setCredentialSubType(cr.getCredentialSubType());
				c.setCredentialType(AvailableCredentialTypes.CREDENTIAL_TYPE_X509CERTIFICATE);
				c.setDisplayName("SomeDisplayName");
				c.setExpireDate(MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1)));
				c.setIssueDate(MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(2)));
				c.setIssuerId("CN=SomeIssuerId");
				c.setSerialNumber("abc123");
				c.setStatus(100);
				c.setUniqueId("SomeUniqueId");
				c.setValidFromDate(MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(3)));

				List<Credential> credentials = new ArrayList<Credential>();
				credentials.add(c);
				response = credManagementPayloadParser.genIssueTokenCredentialsResponse(Constants.RELATED_END_ENTITY_UNKNOWN,request, credentials, null,null).getResponseData();
			}
			if(request.getPayload().getAny() instanceof ChangeCredentialStatusRequest){
				ChangeCredentialStatusRequest r = (ChangeCredentialStatusRequest) request.getPayload().getAny();
				if(r.getNewCredentialStatus() != AvailableCredentialStatuses.REVOKED){
					throw new IllegalArgumentException("Bad revoke status");
				}
				if(!r.getIssuerId().equals("CN=SomeIssuerId")){
					throw new IllegalArgumentException("Bad issuer id");
				}
				if(!r.getReasonInformation().equals("5")){
					throw new IllegalArgumentException("Bad reason information");
				}
				if(!r.getSerialNumber().equals("abc123")){
					throw new IllegalArgumentException("Bad serial number");
				}

				revokeMessageRecieved = true;
			}

			if(response != null){
				Thread t = new Thread(new WaitAndSend(response));
				t.start();
			}
		}catch(MessageContentException e){
			throw new MessageProcessingException(e.getMessage(),e);
		}
	}

	private class WaitAndSend implements Runnable{

		private byte[] responseMessage;

		public WaitAndSend(byte[] responseMessage){
			this.responseMessage = responseMessage;
		}

		public void run() {
			try {
				Thread.sleep(waitTime);
			} catch (InterruptedException e) {
			}	
			for(MessageComponent mc : components.values()){
				if(mc instanceof MessageListener){
					try {
						((MessageListener) mc).responseReceived(responseMessage, null);
					} catch (Exception e) {
						assert false;
					}
				}
			}
		}
	}


	public void close() throws IOException {


	}



	public static byte[] base64Cert =("MIIDLTCCAhWgAwIBAgIIYmVP6xQ/t3QwDQYJKoZIhvcNAQEFBQAwJDETMBEGA1UE" +
			"AwwKVGVzdCBlSURDQTENMAsGA1UECgwEVGVzdDAeFw0xMTEwMjExNDM2MzlaFw0z" +
			"MTEwMjExNDM2MzlaMCQxEzARBgNVBAMMClRlc3QgZUlEQ0ExDTALBgNVBAoMBFRl" +
			"c3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDecUf5if2UdWbV/HIj" +
			"h6U3XIymmh28wo8VVxPIbV1A8Yxz7QaMkP8vqaDwHnB1B6mHEjn4VyVogxWxI70I" +
			"wPudUL+Oxkc9ZL7H7zkbi6l2d/n85PjyZvdarCwcBzpEqIRsc+Wa3bGFKBpdZjwL" +
			"XjuuI4YWx+uUrQ96X+WusvFcb8C4Ru3w/K8Saf7yLJNvqmTJrgAOeKY49Jnp9V5x" +
			"9dGe+xpHR3t2xhJ5HXhm+SeUsrH5fHXky7/OVKvLPOXSve+1KHpyp+eOxxgYozTh" +
			"5k+viL0pP9G3AbEPp1mXtxCNzRjUgNlG0BDSIbowD5JciLkz8uYbamLzoUiz1KzZ" +
			"uCfXAgMBAAGjYzBhMB0GA1UdDgQWBBT6HyWgz7ykq9BxTCaULtOIjen3bDAPBgNV" +
			"HRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFPofJaDPvKSr0HFMJpQu04iN6fdsMA4G" +
			"A1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQUFAAOCAQEAbG7Y+rm82Gz1yIWVFKBf" +
			"XxDee7UwX2pyKdDfvRf9lFLxXv4LKBnuM5Zlb2RPdAAe7tTMtnYDwOWs4Uniy57h" +
			"YrCKU3v80u4uZoH8FNCG22APWQ+xa5UQtuq0yRf2xp2e4wjGZLQZlYUbePAZEjle" +
			"0E2YIa/kOrlvy5Z62sj24yczBL9uHfWpQUefA1+R9JpbOj0WEk+rAV0xJ2knmC/R" +
			"NzHWz92kL6UKUFzyBXBiBbY7TSVjO+bV/uPaTEVP7QhJk4Cahg1a7h8iMdF78ths" +
			"+xMeZX1KyiL4Dpo2rocZAvdL/C8qkt/uEgOjwOTdmoRVxkFWcm+DRNa26cclBQ4t" +
			"Vw==").getBytes();

	public Object getConnectionFactory() throws MessageProcessingException,
	IOException {
		throw new MessageProcessingException("Not implemented");
	}

	public boolean isConnected() {
		return true;
	}

	private byte[] base64Decode(byte[] data) throws MessageProcessingException{
		try {
			return Base64.decode(base64Cert);
		} catch (Base64DecodingException e) {
			throw new MessageProcessingException("Base64 Decoding Exception: " + e.getMessage(),e);
		}
	}

	@Override
	public void addSender(MessageSender sender) {
		components.put(sender.getName(), sender);
	}

	@Override
	public void addListener(MessageListener listener) {
		components.put(listener.getName(), listener);
	}

	@Override
	public MessageSender getMessageSender(String name)
			throws MessageProcessingException {
		MessageComponent retval = components.get(name);
		if(retval == null || !(retval instanceof MessageSender)){
			throw new MessageProcessingException("");
		}
		return (MessageSender) retval;
	}

	@Override
	public MessageListener getMessageListener(String name)
			throws MessageProcessingException {
		MessageComponent retval = components.get(name);
		if(retval == null || !(retval instanceof MessageListener)){
			throw new MessageProcessingException("");
		}
		return (MessageListener) retval;
	}

}
