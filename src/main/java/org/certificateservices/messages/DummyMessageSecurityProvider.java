/************************************************************************
*                                                                       *
*  Certificate Service - PKI Messages                                   *
*                                                                       *
*  This software is free software; you can redistribute it and/or       *
*  modify it under the terms of the GNU Lesser General Public License   *
*  License as published by the Free Software Foundation; either         *
*  version 3   of the License, or any later version.                    *
*                                                                       *
*  See terms of license at gnu.org.                                     *
*                                                                       *
*************************************************************************/
package org.certificateservices.messages;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.certificateservices.messages.utils.XMLEncrypter;


/**
 * Dummy PKI Message Security Provider returning a self-signed certificate used
 * for testing.
 * 
 * @author Philip Vendil
 *
 */
public class DummyMessageSecurityProvider implements
		ContextMessageSecurityProvider {

	private KeyStore dummyKS = null;
	private KeyStore encKeyStore = null;
	private String defaultEncKeyId;
	private Map<String,String> encKeyIdToAlias = new HashMap<String,String>();
	
	private boolean validCallDone = false;
	private String organisationCalled = null;
	
	private KeyStore getDummyKeystore() throws MessageProcessingException{
		if(dummyKS == null){
			try {
				dummyKS = KeyStore.getInstance("JKS");
				dummyKS.load(this.getClass().getResourceAsStream("/dummykeystore.jks"), "tGidBq0Eep".toCharArray());
			} catch (Exception e) {
				throw new MessageProcessingException("Error loading dummy key store: " + e.getMessage(),e);
			}
			
		}
		return dummyKS;
	}
	
	private KeyStore getEncKeystore() throws MessageProcessingException{
		if(encKeyStore == null){
			try {
				encKeyStore = KeyStore.getInstance("JKS");
				encKeyStore.load(this.getClass().getResourceAsStream("/decryptionks.jks"), "password".toCharArray());
				
				defaultEncKeyId = XMLEncrypter.generateKeyId(encKeyStore.getCertificate("key1").getPublicKey());
				encKeyIdToAlias.put(defaultEncKeyId, "key1");
				encKeyIdToAlias.put(XMLEncrypter.generateKeyId(encKeyStore.getCertificate("key2").getPublicKey()), "key2");
				encKeyIdToAlias.put(XMLEncrypter.generateKeyId(encKeyStore.getCertificate("key3").getPublicKey()), "key3");
				
			} catch (Exception e) {
				throw new MessageProcessingException("Error loading dummy enc key store: " + e.getMessage(),e);
			}
			
		}
		return encKeyStore;
	}
	
	/**
	 * Method fetching the signing key from the dummy keystore.
	 * 
	 * @see org.certificateservices.messages.MessageSecurityProvider#getSigningKey()
	 */
	public PrivateKey getSigningKey() throws MessageProcessingException {
		return getSigningKey(DEFAULT_CONTEXT);
	}


	@Override
	public PrivateKey getSigningKey(Context context) throws MessageProcessingException {
		try {
			return (PrivateKey) getDummyKeystore().getKey("test", "tGidBq0Eep".toCharArray());
		} catch (Exception e) {
			throw new MessageProcessingException("Error fetching dummy signing key: " + e.getMessage(),e);
		}
	}


	/**
	 * 
	 * @see org.certificateservices.messages.MessageSecurityProvider#getSigningCertificate()
	 */
	public X509Certificate getSigningCertificate()
			throws IllegalArgumentException, MessageProcessingException {
		return getSigningCertificate(DEFAULT_CONTEXT);
	}

	@Override
	public X509Certificate getSigningCertificate(Context context) throws MessageProcessingException {
		try {
			return (X509Certificate) getDummyKeystore().getCertificate("test");
		} catch (Exception e) {
			throw new MessageProcessingException("Error fetching dummy signing certificate: " + e.getMessage(),e);
		}
	}


	/**
	 * 
	 * @see org.certificateservices.messages.MessageSecurityProvider#isValidAndAuthorized(X509Certificate, String)
	 */
	public boolean isValidAndAuthorized(X509Certificate signCertificate, String organisation)
			throws IllegalArgumentException, MessageProcessingException {
		return isValidAndAuthorized(DEFAULT_CONTEXT,signCertificate,organisation);
	}

	@Override
	public boolean isValidAndAuthorized(Context context, X509Certificate signCertificate, String organisation) throws IllegalArgumentException, MessageProcessingException {
		if(signCertificate == null){
			throw new IllegalArgumentException("Error sign certificate cannot be null when validating.");
		}

		boolean[] keyUsage = signCertificate.getKeyUsage();
		if (keyUsage[0] == false) {
			return false;
		}

		validCallDone = true;
		organisationCalled = organisation;

		return true;
	}

	
	public void resetCounters(){
		validCallDone = false;
		organisationCalled = null;
	}
	
	public boolean getValidCallDone(){
		return validCallDone;
	}
	
	public String getOrganisationCalled(){
		return organisationCalled;
	}


	public PrivateKey getDecryptionKey(String keyId)
			throws MessageProcessingException {
		return getDecryptionKey(DEFAULT_CONTEXT,keyId);
	}

	@Override
	public PrivateKey getDecryptionKey(Context context, String keyId) throws MessageProcessingException {
		KeyStore encKeyStore = getEncKeystore();
		if(keyId == DEFAULT_DECRYPTIONKEY){
			keyId = defaultEncKeyId;
		}
		String alias =  encKeyIdToAlias.get(keyId);
		if(alias == null){
			throw new MessageProcessingException("Error no decryption key with key id; " + keyId + " found in message security provider");
		}
		try {
			return (PrivateKey) encKeyStore.getKey(alias, "password".toCharArray());
		} catch (Exception e) {
			throw new MessageProcessingException("Error no decryption key with key id; " + keyId + " found in message security provider");
		}
	}

	public X509Certificate getDecryptionCertificate(String keyId)
			throws MessageProcessingException {
		return getDecryptionCertificate(DEFAULT_CONTEXT,keyId);
	}

	@Override
	public X509Certificate getDecryptionCertificate(Context context, String keyId) throws MessageProcessingException {
		KeyStore encKeyStore = getEncKeystore();
		if(keyId == DEFAULT_DECRYPTIONKEY){
			keyId = defaultEncKeyId;
		}
		String alias =  encKeyIdToAlias.get(keyId);
		if(alias == null){
			throw new MessageProcessingException("Error no decryption key with key id; " + keyId + " found in message security provider");
		}
		try {
			return  (X509Certificate) encKeyStore.getCertificate(alias);
		} catch (Exception e) {
			throw new MessageProcessingException("Error no decryption key with key id; " + keyId + " found in message security provider");
		}
	}


	public X509Certificate[] getDecryptionCertificateChain(String keyId)
			throws MessageProcessingException {
		return getDecryptionCertificateChain(DEFAULT_CONTEXT,keyId);
	}

	@Override
	public X509Certificate[] getDecryptionCertificateChain(Context context, String keyId) throws MessageProcessingException {
		KeyStore encKeyStore = getEncKeystore();
		if(keyId == DEFAULT_DECRYPTIONKEY){
			keyId = defaultEncKeyId;
		}
		String alias =  encKeyIdToAlias.get(keyId);
		if(alias == null){
			throw new MessageProcessingException("Error no decryption key with key id; " + keyId + " found in message security provider");
		}
		try {
			Certificate[] certChain =  encKeyStore.getCertificateChain(alias);
			return (X509Certificate[]) Arrays.copyOf(certChain,certChain.length, X509Certificate[].class);
		} catch (Exception e) {
			throw new MessageProcessingException("Error no decryption key with key id; " + keyId + " found in message security provider");
		}
	}
	
	public Set<String> getDecryptionKeyIds() throws MessageProcessingException {
		return getDecryptionKeyIds(DEFAULT_CONTEXT);
	}

	@Override
	public Set<String> getDecryptionKeyIds(Context context) throws MessageProcessingException {
		getEncKeystore();
		return encKeyIdToAlias.keySet();
	}


	public EncryptionAlgorithmScheme getEncryptionAlgorithmScheme()
			throws MessageProcessingException {
		return getEncryptionAlgorithmScheme(DEFAULT_CONTEXT);
	}

	@Override
	public EncryptionAlgorithmScheme getEncryptionAlgorithmScheme(Context context) throws MessageProcessingException {
		return EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256;
	}

	public SigningAlgorithmScheme getSigningAlgorithmScheme()
			throws MessageProcessingException {
		return getSigningAlgorithmScheme(DEFAULT_CONTEXT);
	}

	/**
	 * Method to retrieve JCE provider that should be used with keys provided by this provider.
	 * @return name of an JCE Provider that should be installed prior to usage of this MessageSecurityProvider
	 * if null should the JRE configured list of security providers be used.
	 */
	@Override
	public String getProvider() {
		return "BC";
	}

	@Override
	public SigningAlgorithmScheme getSigningAlgorithmScheme(Context context) throws MessageProcessingException {
		return SigningAlgorithmScheme.RSAWithSHA256;
	}

	/**
	 * Method to retrieve JCE provider that should be used with keys provided by this provider.
	 * @return name of an JCE Provider that should be installed prior to usage of this MessageSecurityProvider
	 * if null should the JRE configured list of security providers be used.
	 */
	@Override
	public String getProvider(Context context) {
		return getProvider();
	}
}
