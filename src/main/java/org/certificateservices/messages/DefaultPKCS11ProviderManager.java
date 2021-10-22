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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.*;
import java.security.cert.CertificateException;

/**
 * PKCS#11 provider manager in charge of creating, adding and loading
 * a java PKCS#11 keystore, using Sun PKCS#11.
 */
public class DefaultPKCS11ProviderManager implements PKCS11ProviderManager {

    private Provider pkcs11Provider = null;

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
        try {
            if(isJavaVersion9OrHigher()){
                Provider prototypeProvider = Security.getProvider("SunPKCS11");
                String configString = readInputStream(config);
                Method configureMethod = prototypeProvider.getClass().getDeclaredMethod("configure", String.class);
                pkcs11Provider = (Provider)configureMethod.invoke(prototypeProvider, "--" + configString);
            } else {
                Class SunPKCS11 = DefaultPKCS11ProviderManager.class.getClassLoader().loadClass("sun.security.pkcs11.SunPKCS11");
                Constructor<Provider> constructor = SunPKCS11.getConstructor(InputStream.class);
                pkcs11Provider = constructor.newInstance(config);
            }
        } catch(Exception e){
            throw new ProviderException("Failed to create instance of SunPKCS11: " + e.getMessage(), e);
        }

        if(pkcs11Provider != null){
            Security.addProvider(pkcs11Provider);
            return pkcs11Provider.getName();
        }
        return null;
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
        KeyStore keyStore = KeyStore.getInstance("PKCS11", pkcs11Provider);
        keyStore.load(null, password);
        return keyStore;
    }

    /**
     * Check if current JRE running on the system is
     * Java version 9 or higher.
     *
     * @return true if java version is >= 9 otherwise false.
     */
    private boolean isJavaVersion9OrHigher(){
        String version = System.getProperty("java.version");
        return (Integer.parseInt(version.split("\\.")[0]) >= 9);
    }

    /**
     * Read all bytes from an input stream into a UTF-8 string
     *
     * @param inputStream Input stream to read from
     * @return UTF-8 string based on all bytes from the input stream.
     * @throws IOException If error occured when reading from the input stream.
     */
    private String readInputStream(InputStream inputStream) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        for (int length; (length = inputStream.read(buffer)) != -1; ) {
            result.write(buffer, 0, length);
        }
        return result.toString("UTF-8");
    }
}
