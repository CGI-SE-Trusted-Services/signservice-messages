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
package org.certificateservices.messages;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Set;


/**
 * PKI Message Security Provider used by the generator of messages to sign the PKI messages before 
 * they are sent.
 * 
 * @author Philip Vendil
 *
 */
public interface MessageSecurityProvider {
	
	public static final String DEFAULT_DECRYPTIONKEY = null;
	

	/**
	 * Fetches the signing key used to create the digital signatures of the XML file.
	 * @return the signing key used.
	 * @throws MessageProcessingException if key isn't accessible or activated.
	 */
	PrivateKey getSigningKey() throws MessageProcessingException;
	
	/**
	 * Fetches the signing certificate used to create the digital signatures of the XML file.
	 * @return the signing certificate used.
	 * @throws MessageProcessingException if certificate isn't accessible.
	 */
	X509Certificate getSigningCertificate()  throws MessageProcessingException;
	
	
	/**
	 * Fetches a private key given it's unique identifier.
	 * @param keyId unique identifier of the key, if null should a default key be retrieved
	 * @return the related decryption key.
	 * @throws MessageProcessingException
	 */
	PrivateKey getDecryptionKey(String keyId)  throws MessageProcessingException;
	
	/**
	 * Fetches the decryption certificate of related key id.
	 * @param keyId unique identifier of the key, if null should a default key certificate be retrieved
	 * @return the related decryption certificate.
	 * @throws MessageProcessingException if certificate isn't accessible.
	 */
	X509Certificate getDecryptionCertificate(String keyId)  throws MessageProcessingException;
	
	/**
	 * Fetches the decryption certificate chain of related key id can be one or more in size..
	 * @param keyId unique identifier of the key, if null should a default key certificate be retrieved
	 * @return the related decryption certificate chain
	 * @throws MessageProcessingException if certificate isn't accessible.
	 */
	X509Certificate[] getDecryptionCertificateChain(String keyId)  throws MessageProcessingException;
	
	/**
	 * Returns key identifiers of all available decryption keys.
	 * 
	 * @return key identifiers of all available decryption keys.
	 * @throws MessageProcessingException
	 */
	Set<String> getDecryptionKeyIds() throws MessageProcessingException;

	/**
	 * Method in charge of validating a certificate used to sign a PKI message
	 * and also check if the certificate is authorized to generate messages.
	 * @param signCertificate the certificate used to sign the message.
	 * @param organisation the related organisation to the message, null if no organisation lookup should be done.
	 * @return true if the sign certificate is valid and authorized to sign messages.
	 * @throws IllegalArgumentException if arguments were invalid.
	 * @throws MessageProcessingException if internal error occurred validating the certificate.
	 */
	boolean isValidAndAuthorized(X509Certificate signCertificate, String organisation) throws IllegalArgumentException, MessageProcessingException;
	
	/**
	 * Method to fetch the EncryptionAlgorithmScheme to use when encrypting messages.
	 * 
	 * @return Configured EncryptionAlgorithmScheme to use.
	 * @throws MessageProcessingException if internal error determining algorithm scheme to use
	 */
	EncryptionAlgorithmScheme getEncryptionAlgorithmScheme() throws MessageProcessingException;
	
	/**
	 * Method to fetch the SigningAlgorithmScheme to use when signing messages.
	 * 
	 * @return Configured SigningAlgorithmScheme to use.
	 * @throws MessageProcessingException if internal error determining algorithm scheme to use
	 */
	SigningAlgorithmScheme getSigningAlgorithmScheme() throws MessageProcessingException;

	/**
	 * Method to retrieve JCE provider that should be used with keys provided by this provider.
	 * @return name of an JCE Provider that should be installed prior to usage of this MessageSecurityProvider
	 * if null should the JRE configured list of security providers be used.
	 */
	String getProvider();
}
