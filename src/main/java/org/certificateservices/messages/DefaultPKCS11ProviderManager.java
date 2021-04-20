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

import sun.security.pkcs11.SunPKCS11;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;

/**
 * PKCS#11 provider manager in charge of creating, adding and loading
 * a java PKCS#11 keystore, using Sun PKCS#11.
 */
public class DefaultPKCS11ProviderManager implements PKCS11ProviderManager {
    /**
     * Create and add a PKCS#11 provider to the system
     *
     * @param config Configuration to use when creating the provider
     * @return the name of the created provider.
     * @throws NullPointerException If an empty provider was created based on the configuration.
     * @throws SecurityException If a security manager exists and its SecurityManager.checkSecurityAccess method denies access to add a new provider
     * @throws ProviderException If error occurred when creating the provider.
     */
    public String addPKCS11Provider(InputStream config) throws SecurityException, NullPointerException, ProviderException {
        SunPKCS11 pkcs11Provider = new SunPKCS11(config);
        if(pkcs11Provider != null){
            Security.addProvider(pkcs11Provider);
        }
        return pkcs11Provider.getName();
    }

    /**
     * Load the PKCS#11 keystore and make it available for use.
     *
     * @param password PKCS#11 Password to use when loading keystore
     * @return Java PKCS#11 keystore
     * @throws KeyStoreException If error occurred when instantiating the keystore.
     * @throws CertificateException If any of the certificates in the keystore could not be loaded.
     * @throws NoSuchAlgorithmException if the algorithm used to check the integrity of the keystore cannot be found
     * @throws IOException If there was a problem loading the keystore (not found or incorrect password).
     */
    public KeyStore loadPKCS11Keystore(char[] password) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance("PKCS11");
        keyStore.load(null, password);
        return keyStore;
    }
}
