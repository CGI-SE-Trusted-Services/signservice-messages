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
package org.certificateservices.messages

import org.apache.xml.security.utils.Base64
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.certificateservices.messages.utils.XMLEncrypter
import org.certificateservices.messages.utils.XMLSigner
import spock.lang.Specification
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey

import static org.certificateservices.messages.PKCS11MessageSecurityProvider.SETTING_DECRYPTKEY_DEFAULT_ALIAS
import static org.certificateservices.messages.PKCS11MessageSecurityProvider.SETTING_PKCS11_LIBRARY
import static org.certificateservices.messages.PKCS11MessageSecurityProvider.SETTING_PKCS11_SLOT
import static org.certificateservices.messages.PKCS11MessageSecurityProvider.SETTING_PKCS11_SLOT_PASSWORD
import static org.certificateservices.messages.PKCS11MessageSecurityProvider.SETTING_TRUSTSTORE_PATH
import static org.certificateservices.messages.PKCS11MessageSecurityProvider.SETTING_TRUSTSTORE_PASSWORD
import static org.certificateservices.messages.PKCS11MessageSecurityProvider.SETTING_ENCRYPTION_ALGORITHM_SCHEME

/**
 * Unit tests for PKCS11MessageSecurityProvider
 *
 * @author Tobias
 */
class PKCS11MessageSecurityProviderSpec extends Specification {
    def mockedProviderManager
    PKCS11MessageSecurityProvider prov
    Properties config
    X509Certificate testCert
    X509Certificate testCertWithKeyUsage
    KeyStore dummyKeyStore
    String signKeyId

    def setupSpec(){
        Security.addProvider(new BouncyCastleProvider())
    }

    def setup(){
        CertificateFactory cf = CertificateFactory.getInstance("X.509","BC")

        testCert = cf.generateCertificate(new ByteArrayInputStream(Base64.decode(TestData.base64Cert)))
        testCertWithKeyUsage = cf.generateCertificate(new ByteArrayInputStream(Base64.decode(TestData.base64CertWithKeyUsage)))

        config = new Properties();
        config.setProperty(SETTING_PKCS11_LIBRARY, "src/test/resources/dummyp11.jks")
        config.setProperty(SETTING_PKCS11_SLOT, "0")
        config.setProperty(SETTING_PKCS11_SLOT_PASSWORD, "foo123")
        config.setProperty(SETTING_TRUSTSTORE_PATH, this.getClass().getResource("/testtruststore.jks").getPath())
        config.setProperty(SETTING_TRUSTSTORE_PASSWORD, "foo123")
        config.setProperty(SETTING_ENCRYPTION_ALGORITHM_SCHEME, " RSA_pkcs1_5_WITH_AES256 ")

        dummyKeyStore = KeyStore.getInstance("JKS")
        dummyKeyStore.load(new FileInputStream("src/test/resources/dummyp11.jks"), "foo123".toCharArray())

        mockedProviderManager = Mock(PKCS11ProviderManager)
        mockedProviderManager.addPKCS11Provider(_) >> {InputStream config ->
            Properties providerConfig = new Properties()
            providerConfig.load(config)

            // Verify provider is initialized with correct configuration.
            assert providerConfig.getProperty("name") == "CSMsgSecProv"
            assert providerConfig.getProperty("library") == "src/test/resources/dummyp11.jks"
            assert providerConfig.getProperty("slot") == "0"
        }
        mockedProviderManager.loadPKCS11Keystore(_) >> {List<Character> password ->
            // Verify provider keystore is loaded with correct password from configuration.
            assert password.toString() == "[foo123]"
            return dummyKeyStore
        }

        prov = new PKCS11MessageSecurityProvider(config, mockedProviderManager)
        signKeyId = XMLEncrypter.generateKeyId(prov.getSigningCertificate().getPublicKey())
    }

    def "Verify that provider is initialized properly"(){
        expect:
        prov.signingAlgorithmScheme == SigningAlgorithmScheme.RSAWithSHA256
        prov.encryptionAlgorithmScheme == EncryptionAlgorithmScheme.RSA_PKCS1_5_WITH_AES256
    }

    def "Test that getSigningKey() returns a valid signing key"(){
        when:
        PrivateKey key = prov.getSigningKey();
        then:
        assert key != null
        assert key instanceof RSAPrivateKey
    }

    def "Test that getSigningCertificate() returns a valid signing certificate"(){
        when:
        X509Certificate cert = prov.getSigningCertificate();
        then:
        assert cert != null
        assert cert instanceof X509Certificate
    }


    def "Test that isValidAndAuthorized() trust a trusted certificate"(){
        setup:
        XMLSigner.systemTime = TestUtils.mockSystemTime("2018-11-17")
        when:
        X509Certificate cert = prov.getSigningCertificate();
        then:
        prov.isValidAndAuthorized(cert, "someorg")
    }


    def "Test that isValidAndAuthorized() does not trust an untrusted certificate"(){
        setup:
        XMLSigner.systemTime = TestUtils.mockSystemTime("2017-12-01")
        expect:
        !prov.isValidAndAuthorized(testCertWithKeyUsage, "someorg")
    }

    def "Test that isValidAndAuthorized() does accept certificate with wrong key usage"(){
        setup:
        XMLSigner.systemTime = TestUtils.mockSystemTime("2013-10-01")
        expect:
        !prov.isValidAndAuthorized(testCert, "someorg")
    }

    def "Test that isValidAndAuthorized() does not trust an expired certificate"(){
        setup:
        XMLSigner.systemTime = TestUtils.mockSystemTime("2038-10-01")
        when:
        X509Certificate cert = prov.getSigningCertificate();
        then:
        !prov.isValidAndAuthorized(cert, "someorg")
    }


    def "Test that isValidAndAuthorized() does not trust an not yet valid certificate"(){
        setup:
        XMLSigner.systemTime = TestUtils.mockSystemTime("2001-10-01")
        when:
        X509Certificate cert = prov.getSigningCertificate();
        then:
        !prov.isValidAndAuthorized(cert, "someorg")
    }

    def "Verify that signature key is used as decryption key if no decrytion key has been specified."(){
        expect:
        prov.defaultDecryptionKeyId == signKeyId
        prov.getDecryptionKeyIds().size() == 2
        prov.getDecryptionKeyIds().iterator().next() == signKeyId
        prov.getDecryptionCertificate(null) == prov.getSigningCertificate()
        prov.getDecryptionCertificateChain(null).length == 2
        prov.getDecryptionCertificateChain(null)[0] == prov.getSigningCertificate()
        prov.getDecryptionKey(null) == prov.getSigningKey()

    }

    def "Verify that if separate default encryption alias is specified the signing key is not used"(){
        setup:
        config.setProperty(SETTING_DECRYPTKEY_DEFAULT_ALIAS, "dummy encryptor")
        prov = new PKCS11MessageSecurityProvider(config, mockedProviderManager)
        def encKeyId = XMLEncrypter.generateKeyId(dummyKeyStore.getCertificate("dummy encryptor").publicKey)

        expect:
        encKeyId != signKeyId
        prov.defaultDecryptionKeyId == encKeyId
        prov.getDecryptionKeyIds().size() == 2
        prov.getDecryptionKeyIds().contains(encKeyId)

        prov.getDecryptionCertificate(null) == dummyKeyStore.getCertificate("dummy encryptor")
        prov.getDecryptionCertificateChain(null).length == 2
        prov.getDecryptionCertificateChain(null)[0] == dummyKeyStore.getCertificate("dummy encryptor")
        prov.getDecryptionKey(null) == dummyKeyStore.getKey("dummy encryptor","foo123".toCharArray())
    }

    def "Verify isEqual"() {
        setup:
        X509Certificate cert1 = (X509Certificate)dummyKeyStore.getCertificate("dummy encryptor")
        X509Certificate cert2 = (X509Certificate)dummyKeyStore.getCertificate("dummy signer")

        expect:
        prov.isEqual(cert1, cert2) == false
        prov.isEqual(cert1, cert1) == true
        prov.isEqual(cert2, cert2) == true
        prov.isEqual(cert2, cert1) == false
        prov.isEqual(null, cert1) == false
        prov.isEqual(cert1, null) == false
    }
}
