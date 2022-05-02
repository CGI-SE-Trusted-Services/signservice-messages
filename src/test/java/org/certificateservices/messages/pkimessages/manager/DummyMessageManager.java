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
import org.certificateservices.messages.DummyMessageSecurityProvider;
import org.certificateservices.messages.MessageException;
import org.certificateservices.messages.MessageSecurityProvider;
import org.certificateservices.messages.pkimessages.PKIMessageGenerateUtils;
import org.certificateservices.messages.pkimessages.PKIMessageParser;
import org.certificateservices.messages.pkimessages.constants.AvailableCredentialTypes;
import org.certificateservices.messages.pkimessages.constants.Constants;
import org.certificateservices.messages.pkimessages.jaxb.Credential;
import org.certificateservices.messages.pkimessages.jaxb.CredentialRequest;
import org.certificateservices.messages.pkimessages.jaxb.GetCredentialRequest;
import org.certificateservices.messages.pkimessages.jaxb.IssueTokenCredentialsRequest;
import org.certificateservices.messages.pkimessages.jaxb.ObjectFactory;
import org.certificateservices.messages.pkimessages.jaxb.PKIMessage;
import org.certificateservices.messages.pkimessages.jaxb.RequestStatus;
import org.certificateservices.messages.pkimessages.manager.MessageManager;

/**
 * @author Philip Vendil
 *
 */
@SuppressWarnings({ "deprecation" })
public class DummyMessageManager implements MessageManager{

	PKIMessageParser messageParser;
	MessageSecurityProvider securityProvider = new DummyMessageSecurityProvider();
	ObjectFactory of = new ObjectFactory();

	public void init(Properties config, PKIMessageParser parser, String destination) throws IllegalArgumentException,
	IOException, MessageException {

		messageParser = parser;
		try {
			messageParser.init(securityProvider, config);
		} catch (MessageException e) {
			throw new MessageException(e.getMessage(),e);
		}

	}

	public PKIMessage sendMessage(String requestId, byte[] request) throws IllegalArgumentException,
	IOException, MessageException {
		try {
			PKIMessage rm = messageParser.parseMessage(request);
			if(rm.getPayload().getGetCredentialRequest() != null){
				GetCredentialRequest gcr = rm.getPayload().getGetCredentialRequest();
				if(gcr.getIssuerId().equals("CN=testissuer") && gcr.getSerialNumber().equals("123abc")){
					if(gcr.getCredentialSubType() == null){
						throw new IllegalArgumentException("Error no credential sub type set.");
					}
					Credential c = of.createCredential();
					c.setCredentialData(new byte[1]);
					c.setCredentialSubType(gcr.getCredentialSubType());
					c.setCredentialType(AvailableCredentialTypes.CREDENTIAL_TYPE_X509CERTIFICATE);
					c.setDisplayName("SomeDisplayName");
					c.setExpireDate(PKIMessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1)));
					c.setIssueDate(PKIMessageGenerateUtils.dateToXMLGregorianCalendar(new Date(2)));
					c.setIssuerId(gcr.getIssuerId());
					c.setSerialNumber(gcr.getSerialNumber());
					c.setStatus(100);
					c.setUniqueId("SomeUniqueId");
					c.setValidFromDate(PKIMessageGenerateUtils.dateToXMLGregorianCalendar(new Date(3)));


					return messageParser.parseMessage(messageParser.genGetCredentialResponse(Constants.RELATED_END_ENTITY_UNKNOWN,rm, c).getResponseData());

				}else{
					return messageParser.parseMessage(messageParser.genPKIResponse(Constants.RELATED_END_ENTITY_UNKNOWN,request, RequestStatus.ILLEGALARGUMENT, "some bad request", null).getResponseData());
				}
			}
			if(rm.getPayload().getIssueTokenCredentialsRequest() != null){
				IssueTokenCredentialsRequest itr = rm.getPayload().getIssueTokenCredentialsRequest();

				CredentialRequest cr = itr.getTokenRequest().getCredentialRequests().getCredentialRequest().get(0);
				Credential c = of.createCredential();
				c.setCredentialData(Base64.decode(base64Cert));
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
				return messageParser.parseMessage(messageParser.genIssueTokenCredentialsResponse(Constants.RELATED_END_ENTITY_UNKNOWN,rm, credentials, null).getResponseData());
			}

		} catch (MessageException e) {
			throw new MessageException(e.getMessage(),e);
		} catch (Base64DecodingException e) {
			throw new MessageException(e.getMessage(),e);
		}
		return null;
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
		return null;
	}

	public void connect() throws MessageException, IOException {
		
		
	}

	public MessageHandler getMessageHandler() {		
		return null;
	}

	public boolean isConnected() {
		return true;
	}

}
