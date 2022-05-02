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
package org.certificateservices.messages.pkimessages.manager;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.certificateservices.messages.MessageException;
import org.certificateservices.messages.pkimessages.PKIMessageGenerateUtils;
import org.certificateservices.messages.pkimessages.PKIMessageParser;
import org.certificateservices.messages.pkimessages.constants.AvailableCredentialStatuses;
import org.certificateservices.messages.pkimessages.constants.AvailableCredentialTypes;
import org.certificateservices.messages.pkimessages.constants.Constants;
import org.certificateservices.messages.pkimessages.jaxb.ChangeCredentialStatusRequest;
import org.certificateservices.messages.pkimessages.jaxb.Credential;
import org.certificateservices.messages.pkimessages.jaxb.CredentialRequest;
import org.certificateservices.messages.pkimessages.jaxb.GetCredentialRequest;
import org.certificateservices.messages.pkimessages.jaxb.IssueTokenCredentialsRequest;
import org.certificateservices.messages.pkimessages.jaxb.ObjectFactory;
import org.certificateservices.messages.pkimessages.jaxb.PKIMessage;


@SuppressWarnings({ "deprecation" })
public class DummyMessageHandler implements MessageHandler{

	private MessageResponseCallback callback;
	private PKIMessageParser parser;
	private ObjectFactory of = new ObjectFactory();
	private long waitTime;	
	
	public boolean revokeMessageRecieved = false;
	
	public static final String SETTING_WAITTIME = "dummy.waittime";
	
	public void init(Properties config, PKIMessageParser parser,
			MessageResponseCallback callback) throws MessageException {
		this.parser = parser;
		this.callback = callback;
		
		waitTime = Long.parseLong(config.getProperty(SETTING_WAITTIME));
		
	}

	public void connect() throws MessageException, IOException {
		
		
	}

	public void sendMessage(String messageId, byte[] messageData) throws MessageException,
	IOException {
		PKIMessage response = null;		
		PKIMessage request = parser.parseMessage(messageData);

		if(request.getPayload().getGetCredentialRequest() != null){
			GetCredentialRequest gcr = request.getPayload().getGetCredentialRequest();		


			Credential c = of.createCredential();
			c.setCredentialData(base64Decode(base64Cert));
			c.setCredentialSubType(gcr.getCredentialSubType());
			c.setCredentialType(AvailableCredentialTypes.CREDENTIAL_TYPE_X509CERTIFICATE);
			c.setDisplayName("SomeDisplayName");
			c.setExpireDate(PKIMessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1)));
			c.setIssueDate(PKIMessageGenerateUtils.dateToXMLGregorianCalendar(new Date(2)));
			c.setIssuerId("CN=SomeIssuerId");
			c.setSerialNumber("abc123");
			c.setStatus(100);
			c.setUniqueId("SomeUniqueId");
			c.setValidFromDate(PKIMessageGenerateUtils.dateToXMLGregorianCalendar(new Date(3)));

			response = parser.parseMessage(parser.genGetCredentialResponse(Constants.RELATED_END_ENTITY_UNKNOWN,request, c).getResponseData());

		}
		if(request.getPayload().getIssueTokenCredentialsRequest() != null){
			IssueTokenCredentialsRequest itr = request.getPayload().getIssueTokenCredentialsRequest();

			CredentialRequest cr = itr.getTokenRequest().getCredentialRequests().getCredentialRequest().get(0);
			Credential c = of.createCredential();
			c.setCredentialData(base64Decode(base64Cert));
			c.setCredentialSubType(cr.getCredentialSubType());
			c.setCredentialType(AvailableCredentialTypes.CREDENTIAL_TYPE_X509CERTIFICATE);
			c.setDisplayName("SomeDisplayName");
			c.setExpireDate(PKIMessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1)));
			c.setIssueDate(PKIMessageGenerateUtils.dateToXMLGregorianCalendar(new Date(2)));
			c.setIssuerId("CN=SomeIssuerId");
			c.setSerialNumber("abc123");
			c.setStatus(100);
			c.setUniqueId("SomeUniqueId");
			c.setValidFromDate(PKIMessageGenerateUtils.dateToXMLGregorianCalendar(new Date(3)));

			List<Credential> credentials = new ArrayList<Credential>();
			credentials.add(c);
			response = parser.parseMessage(parser.genIssueTokenCredentialsResponse(Constants.RELATED_END_ENTITY_UNKNOWN,request, credentials, null).getResponseData());
		}
		if(request.getPayload().getChangeCredentialStatusRequest() != null){
			ChangeCredentialStatusRequest r = request.getPayload().getChangeCredentialStatusRequest();
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
	}
	
	private class WaitAndSend implements Runnable{

		private PKIMessage responseMessage;

		public WaitAndSend(PKIMessage responseMessage){
			this.responseMessage = responseMessage;
		}

		public void run() {
			try {
				Thread.sleep(waitTime);
			} catch (InterruptedException e) {
			}				
			callback.responseReceived(responseMessage);	
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

	public Object getConnectionFactory() throws MessageException,
			IOException {
		throw new MessageException("Not implemented");
	}

	public boolean isConnected() {
		return true;
	}
	
	private byte[] base64Decode(byte[] data) throws MessageException{
		try {
			return Base64.decode(base64Cert);
		} catch (Base64DecodingException e) {
			throw new MessageException("Base64 Decoding Exception: " + e.getMessage(),e);
		}
	}

}
