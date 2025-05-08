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
package se.signatureservice.messages;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;


/**
 * Extended MessageSecurityProvider interface for enabling the context used by the caller
 * in order to use a specific signing/decryption key depending on related organsiation and or
 * use case.
 * <p>
 *     The interface basically adds a Context parameter to every method.
 * </p>
 * 
 * @author Philip Vendil
 *
 */
public interface ContextMessageSecurityProvider extends MessageSecurityProvider{

	/**
	 * Default context is null.
	 */
	Context DEFAULT_CONTEXT = null;
	

	/**
	 * Fetches the signing key used to create the digital signatures of the XML file.
	 * @param context the related context, null for default context.
	 * @return the signing key used.
	 * @throws MessageProcessingException if key isn't accessible or activated.
	 */
	PrivateKey getSigningKey(Context context) throws MessageProcessingException;
	
	/**
	 * Fetches the signing certificate used to create the digital signatures of the XML file.
	 * @param context the related context, null for default context.
	 * @return the signing certificate used.
	 * @throws MessageProcessingException if certificate isn't accessible.
	 */
	X509Certificate getSigningCertificate(Context context)  throws MessageProcessingException;
	
	
	/**
	 * Fetches a private key given it's unique identifier.
	 * @param context the related context, null for default context.
	 * @param keyId unique identifier of the key, if null should a default key be retrieved
	 * @return the related decryption key.
	 * @throws MessageProcessingException
	 */
	PrivateKey getDecryptionKey(Context context, String keyId)  throws MessageProcessingException;
	
	/**
	 * Fetches the decryption certificate of related key id.
	 * @param context the related context, null for default context.
	 * @param keyId unique identifier of the key, if null should a default key certificate be retrieved
	 * @return the related decryption certificate.
	 * @throws MessageProcessingException if certificate isn't accessible.
	 */
	X509Certificate getDecryptionCertificate(Context context, String keyId)  throws MessageProcessingException;
	
	/**
	 * Fetches the decryption certificate chain of related key id can be one or more in size.
	 * @param context the related context, null for default context.
	 * @param keyId unique identifier of the key, if null should a default key certificate be retrieved
	 * @return the related decryption certificate chain
	 * @throws MessageProcessingException if certificate isn't accessible.
	 */
	X509Certificate[] getDecryptionCertificateChain(Context context, String keyId)  throws MessageProcessingException;
	
	/**
	 * Returns key identifiers of all available decryption keys.
	 * @param context the related context, null for default context.
	 * @return key identifiers of all available decryption keys.
	 * @throws MessageProcessingException
	 */
	Set<String> getDecryptionKeyIds(Context context) throws MessageProcessingException;

	/**
	 * Method in charge of validating a certificate used to sign a PKI message
	 * and also check if the certificate is authorized to generate messages.
	 * @param context the related context, null for default context.
	 * @param signCertificate the certificate used to sign the message.
	 * @param organisation the related organisation to the message, null if no organisation lookup should be done.
	 * @return true if the sign certificate is valid and authorized to sign messages.
	 * @throws IllegalArgumentException if arguments were invalid.
	 * @throws MessageProcessingException if internal error occurred validating the certificate.
	 */
	boolean isValidAndAuthorized(Context context,X509Certificate signCertificate, String organisation) throws IllegalArgumentException, MessageProcessingException;
	
	/**
	 * Method to fetch the EncryptionAlgorithmScheme to use when encrypting messages.
	 * 
	 * @return Configured EncryptionAlgorithmScheme to use.
	 * @throws MessageProcessingException if internal error determining algorithm scheme to use
	 */
	EncryptionAlgorithmScheme getEncryptionAlgorithmScheme(Context context) throws MessageProcessingException;
	
	/**
	 * Method to fetch the SigningAlgorithmScheme to use when signing messages.
	 * @param context the related context, null for default context.
	 * @return Configured SigningAlgorithmScheme to use.
	 * @throws MessageProcessingException if internal error determining algorithm scheme to use
	 */
	SigningAlgorithmScheme getSigningAlgorithmScheme(Context context) throws MessageProcessingException;

	/**
	 * Method to retrieve JCE provider that should be used with keys provided by this provider.
	 * @return name of an JCE Provider that should be installed prior to usage of this MessageSecurityProvider
	 * if null should the JRE configured list of security providers be used.
	 */
	String getProvider(Context context);

	/**
	 * Class representing a context in which a ContextMessageSecurityProvider should
	 * determine keys and validation logic to return.
	 */
	class Context{

		private String usage;
		private String relatedOrganisation;
		private Map<String,Object> properties;

		/**
		 * Class representing a context in which a ContextMessageSecurityProvider should
		 * determine keys and validation logic to return.
		 *
		 * @param usage the usage, available usages is up to the calling application and provider
		 *              implementation to define, null for default. (For instance in a SAML application could
		 *              one usage be IDP Signer and another be MetaData Signer).
         */
		public Context(String usage) {
			this.usage = usage;
		}

		/**
		 * Class representing a context in which a ContextMessageSecurityProvider should
		 * determine keys and validation logic to return.
		 *
		 * @param usage the usage, available usages is up to the calling application and provider
		 *              implementation to define, null for default. (For instance in a SAML application could
		 *              one usage be IDP Signer and another be MetaData Signer).
		 * @param relatedOrganisation the related organisation, null for default.
         */
		public Context(String usage, String relatedOrganisation) {
			this.relatedOrganisation = relatedOrganisation;
			this.usage = usage;
		}

		/***
		 * Class representing a context in which a ContextMessageSecurityProvider should
		 * determine keys and validation logic to return.
		 *
		 * @param usage the usage, available usages is up to the calling application and provider
		 *              implementation to define, null for default. (For instance in a SAML application could
		 *              one usage be IDP Signer and another be MetaData Signer).
		 * @param relatedOrganisation the related organisation, null for default.
         * @param properties a map of provider specific properties which is up to the calling application
		 *                   and provider implementation to define.
         */
		public Context(String usage, String relatedOrganisation, Map<String, Object> properties) {
			this.usage = usage;
			this.relatedOrganisation = relatedOrganisation;
			this.properties = properties;
		}

		/**
		 *
		 * @return the usage, available usages is up to the calling application and provider
		 *         implementation to define, null for default. (For instance in a SAML application could
		 *         one usage be IDP Signer and another be MetaData Signer).
         */
		public String getUsage() {
			return usage;
		}

		/**
		 *
		 * @param usage the usage, available usages is up to the calling application and provider
		 *              implementation to define, null for default. (For instance in a SAML application could
		 *              one usage be IDP Signer and another be MetaData Signer).
         */
		public void setUsage(String usage) {
			this.usage = usage;
		}

		/**
		 *
		 * @return the related organisation, null for default.
         */
		public String getRelatedOrganisation() {
			return relatedOrganisation;
		}

		/**
		 *
		 * @param relatedOrganisation the related organisation, null for default.
         */
		public void setRelatedOrganisation(String relatedOrganisation) {
			this.relatedOrganisation = relatedOrganisation;
		}

		/**
		 *
		 * @return a map of provider specific properties which is up to the calling application
		 *                   and provider implementation to define. can be null if no properties
		 *                   is defined.
         */
		public Map<String, Object> getProperties() {
			if(properties == null){
				properties = new HashMap<String, Object>();
			}
			return properties;
		}

		/**
		 *
		 * @param properties a map of provider specific properties which is up to the calling application
		 *                   and provider implementation to define.
         */
		public void setProperties(Map<String, Object> properties) {
			this.properties = properties;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;

			Context context = (Context) o;

			if (usage != null ? !usage.equals(context.usage) : context.usage != null) return false;
			if (relatedOrganisation != null ? !relatedOrganisation.equals(context.relatedOrganisation) : context.relatedOrganisation != null)
				return false;
			return properties != null ? properties.equals(context.properties) : context.properties == null;

		}

		@Override
		public int hashCode() {
			int result = usage != null ? usage.hashCode() : 0;
			result = 31 * result + (relatedOrganisation != null ? relatedOrganisation.hashCode() : 0);
			result = 31 * result + (properties != null ? properties.hashCode() : 0);
			return result;
		}

		@Override
		public String toString() {
			return "Context{" +
					"usage='" + usage + '\'' +
					", relatedOrganisation='" + relatedOrganisation + '\'' +
					", properties=" + properties +
					'}';
		}
	}
}
