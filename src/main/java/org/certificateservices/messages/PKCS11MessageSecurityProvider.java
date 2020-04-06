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
package org.certificateservices.messages;

import org.apache.log4j.Logger;
import org.certificateservices.messages.utils.SettingsUtils;
import org.certificateservices.messages.utils.XMLEncrypter;
import org.certificateservices.messages.utils.XMLSigner;
import sun.security.pkcs11.SunPKCS11;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;

import java.io.*;
import java.lang.reflect.Constructor;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

public class PKCS11MessageSecurityProvider implements ContextMessageSecurityProvider {
    Logger log = Logger.getLogger(PKCS11MessageSecurityProvider.class);

    /**
     * Setting indicating the path to the PKCS#11 library to use (required)
     */
    static final String SETTING_PKCS11_LIBRARY = "pkcs11securityprovider.library.path";

    /**
     * Setting indicating the slot to use (required)
     */
    static final String SETTING_PKCS11_SLOT = "pkcs11securityprovider.slot";

    /**
     * Setting indicating the PKCS#11 pin/password for given slot (required)
     */
    static final String SETTING_PKCS11_SLOT_PASSWORD = "pkcs11securityprovider.password";

    /**
     * Setting indicating the alias of signing key to use (optional, if not set the first key entry found will be used)
     */
    static final String SETTING_SIGNINGKEY_ALIAS = "pkcs11securityprovider.signingkey.alias";

    /**
     * Setting indicating the default alias of decryption key to use (optional, if not set the signing key entry is used for both signing and decryption)
     */
    static final String SETTING_DECRYPTKEY_DEFAULT_ALIAS = "pkcs11securityprovider.decryptkey.default.alias";

    /**
     * Setting indicating the truststore to use (optional, if not set the pkcs11 token is used as truststore)
     */
    static final String SETTING_TRUSTSTORE_PATH = "pkcs11securityprovider.truststore.path";

    /**
     * Setting indicating the password of truststore to use.
     */
    static final String SETTING_TRUSTSTORE_PASSWORD = "pkcs11securityprovider.truststore.password";


    /**
     * Setting indicating the Signature algorithm scheme to use, possible values are:
     * <li>RSAWithSHA256 (Default if not set).
     */
    static final String SETTING_SIGNATURE_ALGORITHM_SCHEME = "pkcs11securityprovider.signature.algorithm";
    static final SigningAlgorithmScheme DEFAULT_SIGNATURE_ALGORITHM_SCHEME = SigningAlgorithmScheme.RSAWithSHA256;

    /**
     * Setting indicating the Encryption algorithm scheme to use, possible values are:
     * <li>RSA_OAEP_WITH_AES256 (Default if not set).
     * <li>RSA_PKCS1_5_WITH_AES256
     */
    static final String SETTING_ENCRYPTION_ALGORITHM_SCHEME = "pkcs11securityprovider.encryption.algorithm";
    static final EncryptionAlgorithmScheme DEFAULT_ENCRYPTION_ALGORITHM_SCHEME = EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256;

    private KeyStore pkcs11Keystore;
    private KeyStore trustStore;
    private String pkcs11Password;

    private SigningAlgorithmScheme signingAlgorithmScheme;
    private EncryptionAlgorithmScheme encryptionAlgorithmScheme;

    private X509Certificate signingCertificate;
    private PrivateKey signingKey;

    private Map<String, X509Certificate[]> decryptionCertificates = new HashMap<String, X509Certificate[]>();
    private Map<String, PrivateKey> decryptionKeys = new HashMap<String, PrivateKey>();
    private String defaultDecryptionKeyId = null;

    private PKCS11ProviderManager providerManager = null;

    public PKCS11MessageSecurityProvider(Properties config) throws MessageProcessingException {
        this(config, new DefaultPKCS11ProviderManager());
    }

    public PKCS11MessageSecurityProvider(Properties config, PKCS11ProviderManager providerManager) throws MessageProcessingException{
        String pkcs11Library = SettingsUtils.getRequiredProperty(config, SETTING_PKCS11_LIBRARY);
        int pkcs11Slot = Integer.parseInt(SettingsUtils.getRequiredProperty(config, SETTING_PKCS11_SLOT));
        pkcs11Password = SettingsUtils.getRequiredProperty(config, SETTING_PKCS11_SLOT_PASSWORD);
        String signingKeyAlias = config.getProperty(SETTING_SIGNINGKEY_ALIAS);
        String decryptKeyDefaultAlias = config.getProperty(SETTING_DECRYPTKEY_DEFAULT_ALIAS);
        String trustStorePath = config.getProperty(SETTING_TRUSTSTORE_PATH);
        String trustStorePassword = config.getProperty(SETTING_TRUSTSTORE_PASSWORD);

        try {
            this.providerManager = providerManager;
            pkcs11Keystore = getPKCS11Keystore(pkcs11Library, pkcs11Slot, pkcs11Password);
            if(signingKeyAlias == null){
                // Use first key entry found if no alias is specified.
                log.debug("Signing key alias not specified. Trying to find available key.");
                Enumeration<String> aliases = pkcs11Keystore.aliases();
                while(aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    if(pkcs11Keystore.isKeyEntry(alias) && signingKeyAlias == null){
                        log.debug("Using signing key alias: " + alias);
                        signingKeyAlias = alias;
                    }
                }
            }

            signingCertificate = (X509Certificate) pkcs11Keystore.getCertificate(signingKeyAlias);
            signingKey = (PrivateKey)pkcs11Keystore.getKey(signingKeyAlias, pkcs11Password.toCharArray());
        } catch(Exception e){
            if(e instanceof MessageProcessingException){
                throw (MessageProcessingException) e;
            }
            throw new MessageProcessingException("Error loading signing keystore: " + e.getMessage(), e);
        }

        if(signingCertificate == null || signingKey == null){
            throw new MessageProcessingException("Error finding signing certificate and key for alias: " + signingKeyAlias + ", in PKCS#11 slot: " + pkcs11Slot);
        }

        if(decryptKeyDefaultAlias == null){
            log.debug("Default decryption key alias not specified, using signing key alias: " + signingKeyAlias);
            decryptKeyDefaultAlias = signingKeyAlias;
        }

        try{
            Enumeration<String> aliases = pkcs11Keystore.aliases();
            while(aliases.hasMoreElements()){
                String alias = aliases.nextElement();
                Key key = pkcs11Keystore.getKey(alias, pkcs11Password.toCharArray());
                Certificate[] certChain = pkcs11Keystore.getCertificateChain(alias);
                if(key != null && key instanceof PrivateKey && certChain != null && certChain.length > 0){
                    X509Certificate[] x509CertChain = Arrays.copyOf(certChain,certChain.length, X509Certificate[].class);
                    String keyId = XMLEncrypter.generateKeyId(x509CertChain[0].getPublicKey());
                    decryptionKeys.put(keyId, (PrivateKey) key);
                    decryptionCertificates.put(keyId, x509CertChain);
                }
            }

            Certificate defaultDecryptCert = pkcs11Keystore.getCertificate(decryptKeyDefaultAlias);
            if(defaultDecryptCert != null){
                defaultDecryptionKeyId = XMLEncrypter.generateKeyId(defaultDecryptCert.getPublicKey());
            }

        } catch(Exception e){
            if(e instanceof MessageProcessingException){
                throw (MessageProcessingException) e;
            }
            throw new MessageProcessingException("Unable to read decryption keys and certificates from token: " + e.getMessage(), e);
        }


        if(decryptionKeys.size() == 0){
            throw new MessageProcessingException("No decryption keys found in token");
        }

        if(decryptionKeys.get(defaultDecryptionKeyId) == null){
            throw new MessageProcessingException("Error no default decryption key with alias:" + decryptKeyDefaultAlias + " found in token");
        }

        signingAlgorithmScheme = SigningAlgorithmScheme.getByName(config.getProperty(SETTING_SIGNATURE_ALGORITHM_SCHEME));
        if(signingAlgorithmScheme == null){
            signingAlgorithmScheme = DEFAULT_SIGNATURE_ALGORITHM_SCHEME;
        }

        encryptionAlgorithmScheme = EncryptionAlgorithmScheme.getByName(config.getProperty(SETTING_ENCRYPTION_ALGORITHM_SCHEME));
        if(encryptionAlgorithmScheme == null){
            encryptionAlgorithmScheme = DEFAULT_ENCRYPTION_ALGORITHM_SCHEME;
        }

        if(trustStorePath != null){
            try {
                log.debug("Using truststore: " + trustStorePath);
                trustStore = KeyStore.getInstance("JKS");
                trustStore.load(new FileInputStream(trustStorePath), trustStorePassword.toCharArray());
            } catch(Exception e){
                log.error("Failed to load truststore: " + trustStorePath, e);
            }
        }
    }

    /**
     * Fetches the signing key used to create the digital signatures of the XML file.
     * @return the signing key used.
     * @throws MessageProcessingException if key isn't accessible or activated.
     */
    @Override
    public PrivateKey getSigningKey() throws MessageProcessingException {
        return getSigningKey(DEFAULT_CONTEXT);
    }

    /**
     * Fetches the signing key used to create the digital signatures of the XML file.
     *
     * @param context the related context, null for default context. (Parameter is currently ignored)
     * @return the signing key used.
     * @throws MessageProcessingException if key isn't accessible or activated.
     */
    @Override
    public PrivateKey getSigningKey(Context context) throws MessageProcessingException {
        return signingKey;
    }

    /**
     * Fetches the signing certificate used to create the digital signatures of the XML file.
     * @return the signing certificate used.
     * @throws MessageProcessingException if certificate isn't accessible.
     */
    @Override
    public X509Certificate getSigningCertificate() throws MessageProcessingException {
        return getSigningCertificate(DEFAULT_CONTEXT);
    }

    /**
     * Fetches the signing certificate used to create the digital signatures of the XML file.
     *
     * @param context the related context, null for default context. (Parameter is currently ignored)
     * @return the signing certificate used.
     * @throws MessageProcessingException if certificate isn't accessible.
     */
    @Override
    public X509Certificate getSigningCertificate(Context context) throws MessageProcessingException {
        return signingCertificate;
    }

    /**
     * Fetches a private key given it's unique identifier.
     * @param keyId unique identifier of the key, if null should a default key be retrieved
     * @return the related decryption key.
     * @throws MessageProcessingException
     */
    @Override
    public PrivateKey getDecryptionKey(String keyId) throws MessageProcessingException {
        return getDecryptionKey(DEFAULT_CONTEXT, keyId);
    }

    /**
     * Fetches a private key given it's unique identifier.
     *
     * @param context the related context, null for default context. (Parameter is currently ignored)
     * @param keyId   unique identifier of the key, if null should a default key be retrieved
     * @return the related decryption key.
     * @throws MessageProcessingException
     */
    @Override
    public PrivateKey getDecryptionKey(Context context, String keyId) throws MessageProcessingException {
        return decryptionKeys.get((keyId == null ? defaultDecryptionKeyId : keyId));
    }

    /**
     * Fetches the decryption certificate of related key id.
     * @param keyId unique identifier of the key, if null should a default key certificate be retrieved
     * @return the related decryption certificate.
     * @throws MessageProcessingException if certificate isn't accessible.
     */
    @Override
    public X509Certificate getDecryptionCertificate(String keyId) throws MessageProcessingException {
        return getDecryptionCertificate(DEFAULT_CONTEXT, keyId);
    }

    /**
     * Fetches the decryption certificate of related key id.
     *
     * @param context the related context, null for default context. (Parameter is currently ignored)
     * @param keyId   unique identifier of the key, if null should a default key certificate be retrieved
     * @return the related decryption certificate.
     * @throws MessageProcessingException if certificate isn't accessible.
     */
    @Override
    public X509Certificate getDecryptionCertificate(Context context, String keyId) throws MessageProcessingException {
        return decryptionCertificates.get((keyId == null ? defaultDecryptionKeyId : keyId))[0];
    }

    /**
     * Fetches the decryption certificate chain of related key id can be one or more in size..
     * @param keyId unique identifier of the key, if null should a default key certificate be retrieved
     * @return the related decryption certificate chain
     * @throws MessageProcessingException if certificate isn't accessible.
     */
    @Override
    public X509Certificate[] getDecryptionCertificateChain(String keyId) throws MessageProcessingException {
        return getDecryptionCertificateChain(DEFAULT_CONTEXT, keyId);
    }

    /**
     * Fetches the decryption certificate chain of related key id can be one or more in size.
     *
     * @param context the related context, null for default context. (Parameter is currently ignored)
     * @param keyId   unique identifier of the key, if null should a default key certificate be retrieved
     * @return the related decryption certificate chain
     * @throws MessageProcessingException if certificate isn't accessible.
     */
    @Override
    public X509Certificate[] getDecryptionCertificateChain(Context context, String keyId) throws MessageProcessingException {
        return decryptionCertificates.get((keyId == null ? defaultDecryptionKeyId : keyId));
    }

    /**
     * Returns key identifiers of all available decryption keys.
     *
     * @return key identifiers of all available decryption keys.
     * @throws MessageProcessingException
     */
    @Override
    public Set<String> getDecryptionKeyIds() throws MessageProcessingException {
        return getDecryptionKeyIds(DEFAULT_CONTEXT);
    }

    /**
     * Returns key identifiers of all available decryption keys.
     *
     * @param context the related context, null for default context. (Parameter is currently ignored)
     * @return key identifiers of all available decryption keys.
     * @throws MessageProcessingException
     */
    @Override
    public Set<String> getDecryptionKeyIds(Context context) throws MessageProcessingException {
        return decryptionKeys.keySet();
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
    @Override
    public boolean isValidAndAuthorized(X509Certificate signCertificate,
                                        String organisation) throws IllegalArgumentException, MessageProcessingException {
        return isValidAndAuthorized(DEFAULT_CONTEXT,signCertificate,organisation);
    }

    /**
     * Method in charge of validating a certificate used to sign a PKI message
     * and also check if the certificate is authorized to generate messages.
     * @param context the related context, null for default context. (Parameter is currently ignored)
     * @param signCertificate the certificate used to sign the message.
     * @param organisation the related organisation to the message, null if no organisation lookup should be done.
     * @return true if the sign certificate is valid and authorized to sign messages.
     * @throws IllegalArgumentException if arguments were invalid.
     * @throws MessageProcessingException if internal error occurred validating the certificate.
     */
    @Override
    public boolean isValidAndAuthorized(Context context, X509Certificate signCertificate, String organisation) throws IllegalArgumentException, MessageProcessingException {
        log.debug("Checking if valid and authorized: " + signCertificate.getSubjectDN().getName());

        if(!XMLSigner.checkBasicCertificateValidation(signCertificate)){
            return false;
        }

        KeyStore ks = (trustStore != null ? trustStore : pkcs11Keystore);
        boolean foundMatching = false;

        try {
            Enumeration<String> aliases = ks.aliases();
            while(aliases.hasMoreElements()){
                X509Certificate trustedCertificate = (X509Certificate)ks.getCertificate(aliases.nextElement());
                if(isEqual(signCertificate, trustedCertificate)){
                    log.debug("Found signing certificate in truststore");
                    foundMatching = true;
                    break;
                }
            }
        } catch(CertificateEncodingException e){
            throw new MessageProcessingException("Error reading certificates from truststore: " + e.getMessage());
        } catch (KeyStoreException e) {
            throw new MessageProcessingException("Error reading certificates from truststore: " + e.getMessage());
        }

        return foundMatching;
    }

    /**
     * Method to fetch the EncryptionAlgorithmScheme to use when encrypting messages.
     *
     * @return Configured EncryptionAlgorithmScheme to use.
     * @throws MessageProcessingException if internal error determining algorithm scheme to use
     */
    @Override
    public EncryptionAlgorithmScheme getEncryptionAlgorithmScheme() throws MessageProcessingException {
        return getEncryptionAlgorithmScheme(DEFAULT_CONTEXT);
    }

    /**
     * Method to fetch the EncryptionAlgorithmScheme to use when encrypting messages.
     *
     * @param context (Parameter is currently ignored)
     * @return Configured EncryptionAlgorithmScheme to use.
     * @throws MessageProcessingException if internal error determining algorithm scheme to use
     */
    @Override
    public EncryptionAlgorithmScheme getEncryptionAlgorithmScheme(Context context) throws MessageProcessingException {
        return encryptionAlgorithmScheme;
    }

    /**
     * Method to fetch the SigningAlgorithmScheme to use when signing messages.
     *
     * @return Configured SigningAlgorithmScheme to use.
     * @throws MessageProcessingException if internal error determining algorithm scheme to use
     */
    @Override
    public SigningAlgorithmScheme getSigningAlgorithmScheme() throws MessageProcessingException {
        return getSigningAlgorithmScheme(DEFAULT_CONTEXT);
    }

    /**
     * Method to fetch the SigningAlgorithmScheme to use when signing messages.
     *
     * @param context the related context, null for default context. (Parameter is currently ignored)
     * @return Configured SigningAlgorithmScheme to use.
     * @throws MessageProcessingException if internal error determining algorithm scheme to use
     */
    @Override
    public SigningAlgorithmScheme getSigningAlgorithmScheme(Context context) throws MessageProcessingException {
        return signingAlgorithmScheme;
    }

    /**
     * Method to check if two certificates are equal.
     *
     * @param certificate Certificate to compare against another certifcate.
     * @param anotherCertificate Another certificate to compare against.
     * @return true if both certificates are equal, otherwise false.
     * @throws CertificateEncodingException If an encoding error occurs while processing certificates.
     */
    static boolean isEqual(X509Certificate certificate, X509Certificate anotherCertificate) throws CertificateEncodingException{
        return certificate != null && anotherCertificate != null && Arrays.equals(certificate.getEncoded(), anotherCertificate.getEncoded());
    }

    /**
     * Create Sun PKCS#11 keystore with given parameters.
     *
     * @param pkcs11Library PKCS#11 library to use when accessing the token
     * @param slot PKCS#11 Slot to use when accessing the token
     * @param slotPassword Password that protects the slot
     * @return PKCS#11 keystore instance.
     * @throws IOException If library could not be found or could not be accessible due to invalid password
     * @throws KeyStoreException If there were problems creating the keystore
     * @throws NoSuchAlgorithmException If the algorithm used to check the integrity of the keystore cannot be found
     * @throws CertificateException If any of the certificates in the keystore could not be loaded
     */
    protected KeyStore getPKCS11Keystore(String pkcs11Library, int slot, String slotPassword) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, PKCS11Exception {
        if(!new File(pkcs11Library).exists()){
            throw new IOException("PKCS#11 library does not exist: " + pkcs11Library);
        }

        KeyStore keyStore;
        InputStream configStream;

        StringBuffer pkcs11Config = new StringBuffer();
        pkcs11Config.append("name = CSMsgSecProv\n");
        pkcs11Config.append("library = " + pkcs11Library + "\n");
        pkcs11Config.append("slot = " + slot + "\n");

        if (log.isDebugEnabled()) {
            PKCS11 p11 = PKCS11.getInstance(pkcs11Library, "C_GetFunctionList", null, false);
            long[] slots = p11.C_GetSlotList(true);
            for (long s : slots) {
                log.debug("Found available PKCS#11 slot: " + s);
            }
        }

        log.debug("Using PKCS#11 configuration: " + pkcs11Config.toString());
        configStream = new ByteArrayInputStream(pkcs11Config.toString().getBytes("UTF-8"));
        providerManager.addPKCS11Provider(configStream);
        keyStore = providerManager.loadPKCS11Keystore(slotPassword == null ? null : slotPassword.toCharArray());

        log.debug("PKCS#11 Keystore successfully loaded");

        if (log.isDebugEnabled()) {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                log.debug("Found keystore alias: " + alias);
            }
        }

        return keyStore;
    }
}
