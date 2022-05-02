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
import org.certificateservices.messages.utils.*;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.*;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Helper class containing parsing methods for managing trust in MessageSecurityProviders, providing a in common way
 * to handle trust stores between for instance SimpleMessageSecurityProvider and PKCS11MessageSecurityProvider
 *
 * @author Philip Vendil 2021-06-01
 */
public class TruststoreHelper {

    Logger log = Logger.getLogger(TruststoreHelper.class.getName());

    protected SystemTime systemTime = new DefaultSystemTime();

    public static String TRUSTKEYSTORE_TYPE_ENDENTITY = "ENDENTITY";
    public static String TRUSTKEYSTORE_TYPE_CA = "CA";

    /**
     * Setting defining the type of trust store used, can be either CA or ENDENTITY depending on trust policy used.
     * If CA should the trust store contain the issuer of a received signing certificate (from other parties) and
     * if ENDENTITY it should contain the actual trusted signing certificates.
     * <br>
     * If CA is used should settings: simplesecurityprovider.trustkeystore.matchdnfield and
     * simplesecurityprovider.trustkeystore.matchdnvalue be set to authorize who can send messages.
     *
     * Default value: ENDENTITY
     */
    public static final String SETTING_TRUSTKEYSTORE_TYPE = ".trustkeystore.type";
    public static final String DEFAULT_TRUSTKEYSTORE_TYPE = TRUSTKEYSTORE_TYPE_ENDENTITY;

    /**
     * Setting indicating the path to the trust JKS key store (required)
     */
    public static final String SETTING_TRUSTKEYSTORE_PATH = ".trustkeystore.path";

    /**
     * Setting indicating the password to the trust JKS key store (required)
     */
    public static final String SETTING_TRUSTKEYSTORE_PASSWORD = ".trustkeystore.password";

    /**
     * Setting used if truststore type is CA and indicates that a subject DN check should be added to authorize the
     * sender. If setting below is false will all messages that is issued by any trusted CA by the configuration be accepted.
     * Default: true
     */
    public static final String SETTING_TRUSTKEYSTORE_MATCHSUBJECT = ".trustkeystore.matchsubject";
    public static final String DEFAULT_TRUSTKEYSTORE_MATCHSUBJECT = "true";

    /**
     * Setting indicating which field in client certificate subject dn that should be matched.
     * Example "OU","O" or "CN".
     *
     * Required if truststore type is CA and matchsubject is true
     */
    public static final String SETTING_TRUSTKEYSTORE_MATCHDNFIELD = ".trustkeystore.matchdnfield";

    /**
     * Setting indicating the value that should be matched (case-sensitive) in the subject dn.
     * Example if set to "frontend" and matchdnfield is "OU" only systems that have a trusted client
     * certificate with a subjectdn containing "OU=frontend" will be accepted.
     *
     * Required if truststore type is CA and matchsubject is true
     */
    public static final String SETTING_TRUSTKEYSTORE_MATCHDNVALUE = ".trustkeystore.matchdnvalue";


    private KeyStore trustStore;
    private final String trustStoreType;
    private boolean trustStoreMatchSubject;
    private String trustStoreMatchFieldName;
    private ASN1ObjectIdentifier trustStoreMatchField;
    private String trustStoreMatchValue;

    /**
     * Constructor of TruststoreHelper parsing settings.
     * @param config the message security provider settings.
     * @param trustStore related truststore keystore.
     * @param settingPrefix prefix setting used by related provider.
     * @throws MessageProcessingException if missconfigration found.
     */
    public TruststoreHelper(Properties config, KeyStore trustStore, String settingPrefix) throws MessageProcessingException{
        this.trustStore = trustStore;
        trustStoreType = getTrustStoreType(config,settingPrefix);
        if(trustStoreType.equals(TRUSTKEYSTORE_TYPE_CA)) {
            trustStoreMatchSubject = useSubjectMatch(config, settingPrefix);
            if(trustStoreMatchSubject) {
                trustStoreMatchFieldName = SettingsUtils.getRequiredProperty(config, settingPrefix + SETTING_TRUSTKEYSTORE_MATCHDNFIELD).trim().toUpperCase();
                trustStoreMatchField = getMatchSubjectField(trustStoreMatchFieldName,settingPrefix);
                trustStoreMatchValue = getMatchSubjectValue(config,settingPrefix);
            }
        }
    }

    /**
     * Method in charge of validating a certificate is trusted by the message security provider
     *
     * @param context is currently ignored.
     * @param signCertificate the certificate used to sign the message.
     * @return true if the sign certificate is valid and authorized to sign messages.
     * @throws IllegalArgumentException   if arguments were invalid.
     * @throws MessageProcessingException if internal error occurred validating the certificate.
     */
    public boolean isTrusted(ContextMessageSecurityProvider.Context context, X509Certificate signCertificate) throws IllegalArgumentException, MessageProcessingException {
        if(trustStoreType.equals(TRUSTKEYSTORE_TYPE_ENDENTITY)) {
            return checkCertificateMatchFromTruststore(signCertificate);
        }else{
            return validateCertificateChain(signCertificate) && matchCertificateField(signCertificate);
        }
    }


    /**
     * Help method to parse truststore type used.
     *
     * @param config the message security provider configuration
     * @param settingPrefix prefix setting used by related provider.
     * @return one of accepted type CA or ENDENTIY
     * @throws MessageProcessingException if invalid type configuration was found.
     */
    protected String getTrustStoreType(Properties config, String settingPrefix) throws MessageProcessingException {
        String type = config.getProperty(settingPrefix + SETTING_TRUSTKEYSTORE_TYPE,DEFAULT_TRUSTKEYSTORE_TYPE).trim().toUpperCase();
        if(type.equals(TRUSTKEYSTORE_TYPE_CA) || type.equals(TRUSTKEYSTORE_TYPE_ENDENTITY)){
            return type;
        }
        throw new MessageProcessingException("Invalid setting for simple message security provider, setting " + settingPrefix + SETTING_TRUSTKEYSTORE_TYPE + " should have a value of either " + TRUSTKEYSTORE_TYPE_CA + " or " + TRUSTKEYSTORE_TYPE_ENDENTITY + " not: " + type);
    }

    /**
     * Help method to parse truststore subject match should be used.
     *
     * @param config the message security provider configuration
     * @param settingPrefix prefix setting used by related provider.
     * @return true if subject match should be used.
     * @throws MessageProcessingException if invalid type configuration was found.
     */
    protected boolean useSubjectMatch(Properties config, String settingPrefix) throws MessageProcessingException {
        String val = config.getProperty(settingPrefix + SETTING_TRUSTKEYSTORE_MATCHSUBJECT,DEFAULT_TRUSTKEYSTORE_MATCHSUBJECT).trim().toLowerCase();
        if(val.equals("true") || val.equals("false")){
            return Boolean.parseBoolean(val);
        }
        throw new MessageProcessingException("Invalid setting for simple message security provider, setting " + settingPrefix+SETTING_TRUSTKEYSTORE_MATCHSUBJECT + " should have a value of either true or false not: " + val);
    }

    /**
     * Help method to fetch configured match subject field from configuration.
     * @param trustStoreMatchFieldName the configured subject dn name value.
     * @param settingPrefix prefix setting used by related provider.
     * @return the configured dn value to use when matching subject.
     * @throws MessageProcessingException if setting wasn't set of invalid value.
     */
    protected ASN1ObjectIdentifier getMatchSubjectField(String trustStoreMatchFieldName, String settingPrefix) throws MessageProcessingException{
        try {
            return new SubjectDNMatcher.AvailableDNFields().getIdentifier(trustStoreMatchFieldName);
        }catch(IllegalArgumentException e){
            throw new MessageProcessingException("Invalid DN field " + trustStoreMatchFieldName + " configured in setting " + settingPrefix+SETTING_TRUSTKEYSTORE_MATCHDNFIELD + ".");
        }
    }

    /**
     * Help method to fetch configured match subject value from configuration.
     * @param config the message security provider configuration
     * @param settingPrefix prefix setting used by related provider.
     * @return the configured dn value to use when matching subject.
     * @throws MessageProcessingException if setting wasn't set of invalid value.
     */
    protected String getMatchSubjectValue(Properties config, String settingPrefix) throws MessageProcessingException{
        return SettingsUtils.getRequiredProperty(config, settingPrefix + SETTING_TRUSTKEYSTORE_MATCHDNVALUE).trim();
    }

    /**
     * Help method to validate the certificate chain related to
     * @param certificate the certificate to validate against the trust store.
     * @return true if chain validates successfully.
     */
    protected boolean validateCertificateChain(X509Certificate certificate) {
        try {
            CertPath path = CertUtils.getCertificateFactory().generateCertPath(Collections.singletonList(certificate));
            CertPathValidator validator = CertPathValidator.getInstance("PKIX","BC");
            PKIXParameters params = new PKIXParameters(trustStore);
            params.setDate(systemTime.getSystemTime());
            params.setRevocationEnabled(false);
            params.setCertPathCheckers(Collections.singletonList(new ExtendedKeyUsageChecker()));
            validator.validate(path, params);
            return true;
        }catch(Exception e){
            log.log(Level.SEVERE,"Error validating certificate chain of CSMessage signing certificate: " + e.getMessage(),e);
        }
        return false;
    }


    /**
     * Help method to check if a certificate contains a specific field value.
     * @param certificate the certificate to match against configuration.
     * @return true if fields match
     */
    protected boolean matchCertificateField(X509Certificate certificate) {
        if(trustStoreMatchSubject){
            List<String> fieldValues = CertUtils.getSubjectDNFields(CertUtils.getSubject(certificate), trustStoreMatchField);
            boolean result =  fieldValues.contains(trustStoreMatchValue);
            if(!result){
                log.severe("Error validating certificate " + certificate.getSubjectDN().toString() + ", does not match configured truststore value of " + trustStoreMatchFieldName + " = " + trustStoreMatchValue);
            }
            return result;
        }else{
            return true;
        }
    }

    /**
     * Method to check that given certificate exist in related trust store. Used
     * if truststore mode is ENDENTITY.
     * @param certificate the certificate to lookup.
     * @return true if the certificate exists in trust store.
     * @throws MessageProcessingException if problems detected checking the trust store.
     */
    protected boolean checkCertificateMatchFromTruststore(X509Certificate certificate) throws MessageProcessingException{
        boolean foundMatching = false;
        try {
            Enumeration<String> aliases = trustStore.aliases();
            while (aliases.hasMoreElements()) {
                if (PKCS11MessageSecurityProvider.isEqual(certificate, (X509Certificate) trustStore.getCertificate(aliases.nextElement()))) {
                    foundMatching = true;
                    break;
                }
            }
        } catch (CertificateEncodingException e) {
            throw new MessageProcessingException("Error reading certificates from truststore: " + e.getMessage());
        } catch (KeyStoreException e) {
            throw new MessageProcessingException("Error reading certificates from truststore: " + e.getMessage());
        }

        return foundMatching;
    }

    /**
     * Special class for handling certificate validation of chains that contains critical extended key usage.
     *
     * This implementation accepts all extended key usages if marked as critical.
     *
     * @author philip 2021-06-01
     */
    public static class ExtendedKeyUsageChecker extends PKIXCertPathChecker {

        private static final String OID_EXTENDED_KEY_USAGE = "2.5.29.37";

        @Override
        public void init(boolean forward) throws CertPathValidatorException {
        }

        @Override
        public boolean isForwardCheckingSupported() {
            return true;
        }

        @Override
        public Set<String> getSupportedExtensions() {
            return Collections.singleton(OID_EXTENDED_KEY_USAGE);
        }

        @Override
        public void check(Certificate cert, Collection<String> unresolvedCritExts) throws CertPathValidatorException {
            unresolvedCritExts.remove(OID_EXTENDED_KEY_USAGE);
        }
    }
}
