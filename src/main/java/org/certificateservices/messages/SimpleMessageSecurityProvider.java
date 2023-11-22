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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.certificateservices.messages.utils.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.*;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * Simple PKI Message provider that is configured with two soft key stores.
 * One key store used as a client key store signing messages and
 * 
 * One trust store where accepted end entity certificates are stored.
 * 
 * @author Philip Vendil
 *
 */
public class SimpleMessageSecurityProvider implements
		ContextMessageSecurityProvider {

	public static final String SETTING_PREFIX = "simplesecurityprovider";

	/**
	 * Setting indicating the path to the signing JKS key store (required) 
	 */
	public static final String SETTING_SIGNINGKEYSTORE_PATH = SETTING_PREFIX + ".signingkeystore.path";
	
	/**
	 * Setting indicating the password to the signing key store (required) 
	 */
	public static final String SETTING_SIGNINGKEYSTORE_PASSWORD = SETTING_PREFIX + ".signingkeystore.password";
	
	/**
	 * Setting indicating the alias of the certificate to use in the signing key store (required) 
	 */
	public static final String SETTING_SIGNINGKEYSTORE_ALIAS = SETTING_PREFIX + ".signingkeystore.alias";
	
	/**
	 * Setting indicating the path to the decrypt JKS key store (optional, if not set is signing keystore used for both signing and encryption) 
	 */
	public static final String SETTING_DECRYPTKEYSTORE_PATH =  SETTING_PREFIX + ".decryptkeystore.path";
	
	/**
	 * Setting indicating the password to the decrypt key store (required, if encrypt key store is specified.) 
	 */
	public static final String SETTING_DECRYPTKEYSTORE_PASSWORD = SETTING_PREFIX + ".decryptkeystore.password";
	
	/**
	 *  Setting indicating the alias of the decryption key to use if no specific key is known. (optional, if not set is same as signing keystore alias used.) 
	 */
	public static final String SETTING_DECRYPTKEYSTORE_DEFAULTKEY_ALIAS = SETTING_PREFIX + ".decryptkeystore.defaultkey.alias";

	/**
	 * Setting indicating the path to the trust JKS key store (required)
	 */
	public static final String SETTING_TRUSTKEYSTORE_PATH = SETTING_PREFIX + TruststoreHelper.SETTING_TRUSTKEYSTORE_PATH;

	/**
	 * Setting indicating the password to the trust JKS key store (required)
	 */
	public static final String SETTING_TRUSTKEYSTORE_PASSWORD = SETTING_PREFIX + TruststoreHelper.SETTING_TRUSTKEYSTORE_PASSWORD;


	/**
	 * Setting indicating the Signature algorithm scheme to use, possible values are:
	 * <li>RSAWithSHA256 (Default if not set).
	 */
	public static final String SETTING_SIGNATURE_ALGORITHM_SCHEME = SETTING_PREFIX +".signature.algorithm";
	public static final SigningAlgorithmScheme DEFAULT_SIGNATURE_ALGORITHM_SCHEME = SigningAlgorithmScheme.RSAWithSHA256;
	
	/**
	 * Setting indicating the Encryption algorithm scheme to use, possible values are:
	 * <li>RSA_OAEP_WITH_AES256 (Default if not set).
	 * <li>RSA_PKCS1_5_WITH_AES256
	 */
	public static final String SETTING_ENCRYPTION_ALGORITHM_SCHEME = SETTING_PREFIX + ".encryption.algorithm";
	public static final EncryptionAlgorithmScheme DEFAULT_ENCRYPTION_ALGORITHM_SCHEME = EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256;


	PrivateKey signPrivateKey = null;
	X509Certificate signCertificate = null;
	
	Map<String, PrivateKey> decryptionKeys = new HashMap<String, PrivateKey>();
	Map<String, X509Certificate[]> decryptionCertificates = new HashMap<String, X509Certificate[]>();
	String defaultDecryptionKeyId = null;
	
	private SigningAlgorithmScheme signingAlgorithmScheme;
	private EncryptionAlgorithmScheme encryptionAlgorithmScheme;

	protected TruststoreHelper truststoreHelper;


	/**
	 * Configures and set's up the security provider with truststore from configuration.
	 *
	 * @param config provider configuration.
	 * @throws MessageProcessingException if not all required settings were set correctly.
	 */
	public SimpleMessageSecurityProvider(Properties config) throws MessageProcessingException {
		this(config, getKeyStore(config, SETTING_PREFIX + TruststoreHelper.SETTING_TRUSTKEYSTORE_PATH, SETTING_PREFIX + TruststoreHelper.SETTING_TRUSTKEYSTORE_PASSWORD));
	}
	
	/**
	 * Configures and set's up the security provider with a given truststore.
	 * 
	 * @param config provider configuration.
	 * @throws MessageProcessingException if not all required settings were set correctly.
	 */
	public SimpleMessageSecurityProvider(Properties config, final KeyStore trustStore) throws MessageProcessingException{
			
		String signKeystorePath = SettingsUtils.getRequiredProperty(config, SETTING_SIGNINGKEYSTORE_PATH);
		String signKeystoreAlias = SettingsUtils.getRequiredProperty(config, SETTING_SIGNINGKEYSTORE_ALIAS);
		
		try{
			String signKeystorePassword = SettingsUtils.getRequiredProperty(config, SETTING_SIGNINGKEYSTORE_PASSWORD);
			KeyStore signKeystore = getSigningKeyStore(config);
			signCertificate = (X509Certificate) signKeystore.getCertificate(signKeystoreAlias);
			signPrivateKey = (PrivateKey) signKeystore.getKey(signKeystoreAlias, signKeystorePassword.toCharArray());

		} catch(Exception e){
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageProcessingException("Error loading signing keystore: " + e.getMessage(),e);
		}
		
		if(signCertificate == null || signPrivateKey == null){
			throw new MessageProcessingException("Error finding signing certificate and key for alias : " + signKeystoreAlias + ", in key store: " + signKeystorePath);
		}

		String decKeystorePath = SettingsUtils.getRequiredProperty(config, SETTING_DECRYPTKEYSTORE_PATH, SETTING_SIGNINGKEYSTORE_PATH);
		KeyStore decKS = getDecryptionKeyStore(config);
		String defaultDecryptionAlias = getDefaultDecryptionAlias(config);
		char[] decKeyStorePassword = getDecryptionKeyStorePassword(config);
		
		try{
		  Enumeration<String> aliases = decKS.aliases();
		  while(aliases.hasMoreElements()){
			  String alias = aliases.nextElement();
			  Key key = decKS.getKey(alias, decKeyStorePassword);
			  Certificate[] certChain = decKS.getCertificateChain(alias);
			  if(key != null && key instanceof PrivateKey && certChain != null && certChain.length > 0){
				  X509Certificate[] x509CertChain =  (X509Certificate[]) Arrays.copyOf(certChain,certChain.length, X509Certificate[].class);
				  String keyId = XMLEncrypter.generateKeyId(x509CertChain[0].getPublicKey());
				  decryptionKeys.put(keyId, (PrivateKey) key);
				  decryptionCertificates.put(keyId, x509CertChain);
			  }
		  }
		  
		  Certificate defaultDecryptCert = decKS.getCertificate(defaultDecryptionAlias);
		  if(defaultDecryptCert != null){
			  defaultDecryptionKeyId = XMLEncrypter.generateKeyId(defaultDecryptCert.getPublicKey());
		  }
		
		}catch(Exception e){
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageProcessingException("Error reading decryption keys and certificates from keystore: " + e.getMessage(),e);
		}
		
		
		if(decryptionKeys.size() == 0){
			throw new MessageProcessingException("Error no decryption keys found in decryption keystore: " + decKeystorePath);
		}
		
		if(decryptionKeys.get(defaultDecryptionKeyId) == null){
			throw new MessageProcessingException("Error no default decryption key with id (alias) :" + defaultDecryptionAlias + " found in decryption keystore: " + decKeystorePath);
		}

		signingAlgorithmScheme = SigningAlgorithmScheme.getByName(config.getProperty(SETTING_SIGNATURE_ALGORITHM_SCHEME));
		if(signingAlgorithmScheme == null){
			signingAlgorithmScheme = DEFAULT_SIGNATURE_ALGORITHM_SCHEME;
		}

		encryptionAlgorithmScheme = EncryptionAlgorithmScheme.getByName(config.getProperty(SETTING_ENCRYPTION_ALGORITHM_SCHEME));
		if(encryptionAlgorithmScheme == null){
			encryptionAlgorithmScheme = DEFAULT_ENCRYPTION_ALGORITHM_SCHEME;
		}

		truststoreHelper = new TruststoreHelper(config,trustStore, SETTING_PREFIX);
	}
	

	/**
	 * @see org.certificateservices.messages.MessageSecurityProvider#getSigningKey()
	 */
	public PrivateKey getSigningKey() throws MessageProcessingException {
		return getSigningKey(DEFAULT_CONTEXT);
	}

	/**
	 * Fetches the signing key used to create the digital signatures of the XML file.
	 *
	 * @param context  is currently ignored.
	 * @return the signing key used.
	 * @throws MessageProcessingException if key isn't accessible or activated.
	 */
	@Override
	public PrivateKey getSigningKey(Context context) throws MessageProcessingException {
		return signPrivateKey;
	}

	/**
	 * @see org.certificateservices.messages.MessageSecurityProvider#getSigningCertificate()
	 */
	public X509Certificate getSigningCertificate() throws MessageProcessingException {
		return getSigningCertificate(DEFAULT_CONTEXT);
	}

	/**
	 * Fetches the signing certificate used to create the digital signatures of the XML file.
	 *
	 * @param context  is currently ignored.
	 * @return the signing certificate used.
	 * @throws MessageProcessingException if certificate isn't accessible.
	 */
	@Override
	public X509Certificate getSigningCertificate(Context context) throws MessageProcessingException {
		return signCertificate;
	}

	/**
	 * Method that checks if a sign certificate is in the trust store, the certificate itself have
	 * to be imported and not just the CA certificate.
	 * <p>
	 * The certificate also have to have key usage digital signature
	 * <p>
	 * Organisation name is ignored
	 * <p>
	 * @see org.certificateservices.messages.MessageSecurityProvider#isValidAndAuthorized(java.security.cert.X509Certificate, java.lang.String)
	 */
	public boolean isValidAndAuthorized(X509Certificate signCertificate,
			String organisation) throws IllegalArgumentException,
			MessageProcessingException {
		return isValidAndAuthorized(DEFAULT_CONTEXT,signCertificate,organisation);

	}

	/**
	 * Method in charge of validating a certificate used to sign a PKI message
	 * and also check if the certificate is authorized to generate messages.
	 *
	 * @param context is currently ignored.
	 * @param signCertificate the certificate used to sign the message.
	 * @param organisation    the related organisation to the message, null if no organisation lookup should be done.
	 * @return true if the sign certificate is valid and authorized to sign messages.
	 * @throws IllegalArgumentException   if arguments were invalid.
	 * @throws MessageProcessingException if internal error occurred validating the certificate.
	 */
	@Override
	public boolean isValidAndAuthorized(Context context, X509Certificate signCertificate, String organisation) throws IllegalArgumentException, MessageProcessingException {
		if(!XMLSigner.checkBasicCertificateValidation(signCertificate)){
			return false;
		}

		return truststoreHelper.isTrusted(context,signCertificate);
	}

	/**
	 * @see org.certificateservices.messages.MessageSecurityProvider#getDecryptionKey(String)
	 */
	public PrivateKey getDecryptionKey(String keyId)
			throws MessageProcessingException {
		return getDecryptionKey(DEFAULT_CONTEXT,keyId);
	}

	/**
	 * Fetches a private key given it's unique identifier.
	 *
	 * @param context is currently ignored.
	 * @param keyId   unique identifier of the key, if null should a default key be retrieved
	 * @return the related decryption key.
	 * @throws MessageProcessingException
	 */
	@Override
	public PrivateKey getDecryptionKey(Context context, String keyId) throws MessageProcessingException {
		return decryptionKeys.get((keyId == null ? defaultDecryptionKeyId : keyId));
	}

	/**
	 * @see org.certificateservices.messages.MessageSecurityProvider#getDecryptionCertificate(String)
	 */
	public X509Certificate getDecryptionCertificate(String keyId)
			throws MessageProcessingException {
		return getDecryptionCertificate(DEFAULT_CONTEXT,keyId);
	}

	/**
	 * Fetches the decryption certificate of related key id.
	 *
	 * @param context is currently ignored.
	 * @param keyId   unique identifier of the key, if null should a default key certificate be retrieved
	 * @return the related decryption certificate.
	 * @throws MessageProcessingException if certificate isn't accessible.
	 */
	@Override
	public X509Certificate getDecryptionCertificate(Context context, String keyId) throws MessageProcessingException {
		return decryptionCertificates.get((keyId == null ? defaultDecryptionKeyId : keyId))[0];
	}

	/**
	 * @see org.certificateservices.messages.MessageSecurityProvider#getDecryptionCertificateChain(String)
	 */
	public X509Certificate[] getDecryptionCertificateChain(String keyId)
			throws MessageProcessingException {
		return getDecryptionCertificateChain(DEFAULT_CONTEXT,keyId);
	}

	/**
	 * Fetches the decryption certificate chain of related key id can be one or more in size..
	 *
	 * @param context is currently ignored.
	 * @param keyId   unique identifier of the key, if null should a default key certificate be retrieved
	 * @return the related decryption certificate chain
	 * @throws MessageProcessingException if certificate isn't accessible.
	 */
	@Override
	public X509Certificate[] getDecryptionCertificateChain(Context context, String keyId) throws MessageProcessingException {
		return decryptionCertificates.get((keyId == null ? defaultDecryptionKeyId : keyId));
	}

	/**
	 * @see org.certificateservices.messages.MessageSecurityProvider#getDecryptionKeyIds()
	 */
	public Set<String> getDecryptionKeyIds() throws MessageProcessingException {
		return getDecryptionKeyIds(DEFAULT_CONTEXT);
	}

	/**
	 * Returns key identifiers of all available decryption keys.
	 *
	 * @param context  is currently ignored.
	 * @return key identifiers of all available decryption keys.
	 * @throws MessageProcessingException
	 */
	@Override
	public Set<String> getDecryptionKeyIds(Context context) throws MessageProcessingException {
		return decryptionKeys.keySet();
	}

	/**
	 * @see org.certificateservices.messages.MessageSecurityProvider#getEncryptionAlgorithmScheme()
	 */
	public EncryptionAlgorithmScheme getEncryptionAlgorithmScheme()
			throws MessageProcessingException {
		return getEncryptionAlgorithmScheme(DEFAULT_CONTEXT);
	}

	/**
	 * Method to fetch the EncryptionAlgorithmScheme to use when encrypting messages.
	 *
	 * @param context is currently ignored.
	 * @return Configured EncryptionAlgorithmScheme to use.
	 * @throws MessageProcessingException if internal error determining algorithm scheme to use
	 */
	@Override
	public EncryptionAlgorithmScheme getEncryptionAlgorithmScheme(Context context) throws MessageProcessingException {
		return encryptionAlgorithmScheme;
	}

	/**
	 * @see org.certificateservices.messages.MessageSecurityProvider#getSigningAlgorithmScheme()
	 */
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

	/**
	 * Method to fetch the SigningAlgorithmScheme to use when signing messages.
	 *
	 * @param context is currently ignored.
	 * @return Configured SigningAlgorithmScheme to use.
	 * @throws MessageProcessingException if internal error determining algorithm scheme to use
	 */
	@Override
	public SigningAlgorithmScheme getSigningAlgorithmScheme(Context context) throws MessageProcessingException {
		return signingAlgorithmScheme;
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

	/**
	 * Method that that reads in the configured signing keystore.
	 * 
	 * @param config the provider configuration
	 * @return the specified keystore from configuration.
	 * @throws MessageProcessingException if configuration of security provider was faulty.
	 */
	protected KeyStore getSigningKeyStore(Properties config) throws MessageProcessingException {
		return getKeyStore(config, SETTING_SIGNINGKEYSTORE_PATH, SETTING_SIGNINGKEYSTORE_PASSWORD);
	}

	/**
	 * Method that that reads in the configured decryption keystore and if no specific decryption keystore
	 * is exists uses the singing keystore.
	 * 
	 * @param config the provider configuration
	 * @return the specified keystore from configuration.
	 * @throws MessageProcessingException if configuration of security provider was faulty.
	 */
	protected KeyStore getDecryptionKeyStore(Properties config) throws MessageProcessingException {
		String encryptPath = config.getProperty(SETTING_DECRYPTKEYSTORE_PATH);
		if(encryptPath == null || encryptPath.trim().equals("")){
			return getSigningKeyStore(config);
		}
		return getKeyStore(config, SETTING_DECRYPTKEYSTORE_PATH, SETTING_DECRYPTKEYSTORE_PASSWORD);
	}

	
	/**
	 * Method that that reads in the configured decryption keystore and if no specific decryption keystore
	 * is exists uses the singing keystore.
	 * 
	 * @param config the provider configuration
	 * @return the specified keystore from configuration.
	 * @throws MessageProcessingException if configuration of security provider was faulty.
	 */
	protected char[] getDecryptionKeyStorePassword(Properties config) throws MessageProcessingException {
		String encryptPath = config.getProperty(SETTING_DECRYPTKEYSTORE_PATH);
		if(encryptPath == null || encryptPath.trim().equals("")){
			return SettingsUtils.getRequiredProperty(config, SETTING_SIGNINGKEYSTORE_PASSWORD).toCharArray();
		}
		return SettingsUtils.getRequiredProperty(config, SETTING_DECRYPTKEYSTORE_PASSWORD).toCharArray();
	}
	
	/**
	 * Help method that reads default key alias and failbacks on signature keystore alias.
	 */
	protected String getDefaultDecryptionAlias(Properties config) throws MessageProcessingException {
		return SettingsUtils.getRequiredProperty(config, SETTING_DECRYPTKEYSTORE_DEFAULTKEY_ALIAS, SETTING_SIGNINGKEYSTORE_ALIAS);
	}
	
	/**
	 * Help method reading a JKS keystore from configuration and specified settings.
	 */
	public static KeyStore getKeyStore(Properties config, String pathSetting, String passwordSetting) throws MessageProcessingException {
		String keyStorePath = SettingsUtils.getRequiredProperty(config, pathSetting);
		
		InputStream keyStoreInputStream = SimpleMessageSecurityProvider.class.getClassLoader().getResourceAsStream(keyStorePath);
		if(keyStoreInputStream == null){
			File keyStoreFile = new File(keyStorePath);
			if(!keyStoreFile.canRead() || !keyStoreFile.exists() || !keyStoreFile.isFile()){
				throw new MessageProcessingException("Error reading keystore: " + keyStorePath + ", make sure it exists and is readable");
			}else{
				try {
					keyStoreInputStream = new FileInputStream(keyStoreFile);
				} catch (FileNotFoundException e) {
					throw new MessageProcessingException("Error keystore file: " + keyStoreFile + " not found.");
				}
			}
		}
		
		String keystorePassword = SettingsUtils.getRequiredProperty(config, passwordSetting);
		try{
		  KeyStore keyStore = KeyStore.getInstance("JKS");
		  keyStore.load(keyStoreInputStream, keystorePassword.toCharArray());
		  return keyStore;
		}catch(Exception e){
			throw new MessageProcessingException("Error reading keystore " + keyStorePath + ", make sure it is a JKS file and password is correct.");
		}
	}

}
