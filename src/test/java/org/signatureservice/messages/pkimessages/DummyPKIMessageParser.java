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

import org.signatureservice.messages.MessageException;
import org.signatureservice.messages.MessageSecurityProvider;
import org.signatureservice.messages.pkimessages.jaxb.*;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Properties;

@SuppressWarnings("deprecation")
public class DummyPKIMessageParser  implements PKIMessageParser{

	public boolean initCalled = false;
	
	
	
	public void init(MessageSecurityProvider securityProvider,
			Properties config) throws MessageException {
		initCalled = true;
	}

	
	public PKIMessage parseMessage(byte[] messageData)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public byte[] genIssueTokenCredentialsRequest(String requestId, String destination, String organisation,
                                                  TokenRequest tokenRequest, Credential originator) throws IllegalArgumentException,
			MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public PKIMessageResponseData genIssueTokenCredentialsResponse(String relatedEndEntity, PKIMessage request,
			List<Credential> credentials, List<Credential> revokedCredentials) throws IllegalArgumentException,
			MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public byte[] genChangeCredentialStatusRequest(String requestId, String destination,String organisation,
			String issuerId, String serialNumber, int newCredentialStatus,
			String reasonInformation, Credential originator) throws IllegalArgumentException,
			MessageException {
		//  Auto-generated method stub
		return null;
	}

	


	
	public byte[] genGetCredentialRequest(String requestId, String destination,String organisation,
			String credentialSubType, String issuerId, String serialNumber, Credential originator)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public PKIMessageResponseData genGetCredentialResponse(String relatedEndEntity, PKIMessage request,
			Credential credential) throws IllegalArgumentException,
			MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public byte[] genGetCredentialStatusListRequest(String requestId, String destination,String organisation,
			String issuerId, Long serialNumber,
			String credentialStatusListType, Credential originator)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public PKIMessageResponseData genGetCredentialStatusListResponse(String relatedEndEntity,PKIMessage request,
			CredentialStatusList credentialStatusList)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public byte[] genGetIssuerCredentialsRequest(String requestId, String destination,String organisation,
			String issuerId, Credential originator) throws IllegalArgumentException,
			MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public PKIMessageResponseData genGetIssuerCredentialsResponse(String relatedEndEntity,PKIMessage request,
			Credential issuerCredential) throws IllegalArgumentException,
			MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public byte[] genIsIssuerRequest(String requestId, String destination, String organisation,String issuerId, Credential originator)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public PKIMessageResponseData genIsIssuerResponse(String relatedEndEntity,PKIMessage request, boolean isIssuer)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public byte[] genIssueCredentialStatusListRequest(String requestId, String destination,String organisation,
			String issuerId, String credentialStatusListType,
			Boolean force, Date requestedValidFromDate,
			Date requestedNotAfterDate, Credential originator) throws IllegalArgumentException,
			MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public PKIMessageResponseData genIssueCredentialStatusListResponse(String relatedEndEntity,PKIMessage request,
			CredentialStatusList credentialStatusList)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public byte[] genRemoveCredentialRequest(String requestId, String destination,String organisation,
			String issuerId, String serialNumber, Credential originator)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public PKIMessageResponseData genRemoveCredentialResponse(String relatedEndEntity,PKIMessage request)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public byte[] genFetchHardTokenDataRequest(String requestId, String destination,String organisation,
			String tokenSerial, String relatedCredentialSerialNumber,
			String relatedCredentialIssuerId, Credential adminCredential, Credential originator)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public PKIMessageResponseData genFetchHardTokenDataResponse(String relatedEndEntity,PKIMessage request,
			String tokenSerial, byte[] encryptedData)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public byte[] genStoreHardTokenDataRequest(String requestId, String destination,String organisation,
			String tokenSerial, String relatedCredentialSerialNumber,
			String relatedCredentialIssuerId, byte[] encryptedData, Credential originator)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public PKIMessageResponseData genStoreHardTokenDataResponse(String relatedEndEntity,PKIMessage request)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public PKIMessageResponseData genPKIResponse(String relatedEndEntity,byte[] request, RequestStatus status,
			String failureMessage, Credential originator) throws IllegalArgumentException,
			MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public PKIMessageResponseData genPKIResponse(String relatedEndEntity,byte[] request, RequestStatus status,
			String failureMessage, String destinationId, Credential originator)
			throws IllegalArgumentException, MessageException {
		//  Auto-generated method stub
		return null;
	}

	
	public X509Certificate getSigningCertificate(byte[] request)
			throws IllegalArgumentException, MessageException {
		return null;
	}


	public PKIMessageResponseData genIssueCredentialStatusListResponseWithoutRequest(
			String relatedEndEntity,String destination, String name, String organisation,
			CredentialStatusList credentialStatusList)
			throws IllegalArgumentException, MessageException {
		// Auto-generated method stub
		return null;
	}



	public PKIMessageResponseData genChangeCredentialStatusResponse(
			String relatedEndEntity, PKIMessage request, String issuerId,
			String serialNumber, int credentialStatus,
			String reasonInformation, Date revocationDate)
			throws IllegalArgumentException, MessageException {
		// Auto-generated method stub
		return null;
	}


	public PKIMessageResponseData genIssueCredentialStatusListResponseWithoutRequest(
			String relatedEndEntity, String destination, String requestName,
			String organisation, CredentialStatusList credentialStatusList,
			Credential originator) throws IllegalArgumentException,
			MessageException {
		//  Auto-generated method stub
		return null;
	}


	public byte[] marshallAndSignPKIMessage(PKIMessage pkiMessage)
			throws MessageException {
		return null;
	}
	
}
