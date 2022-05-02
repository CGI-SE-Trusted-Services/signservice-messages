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
package org.certificateservices.messages

import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.certificateservice.testutils.TestPKIA
import org.certificateservices.messages.utils.DefaultSystemTime
import org.certificateservices.messages.utils.XMLSigner
import spock.lang.Shared
import spock.lang.Unroll

import java.security.Security
import java.util.logging.Level
import java.util.logging.Logger

import static org.certificateservices.messages.SimpleMessageSecurityProvider.*
import static org.certificateservices.messages.TruststoreHelper.*

import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey

import org.apache.xml.security.utils.Base64
import org.certificateservices.messages.utils.XMLEncrypter

import spock.lang.Specification


/**
 * Unit tests for SimplePKIMessageSecurityProvider
 */
class SimplePKIMessageSecurityProviderSpec extends Specification {
	
	SimpleMessageSecurityProvider prov
	
	@Shared X509Certificate testCert
	@Shared X509Certificate testCertWithKeyUsage
	@Shared X509Certificate untrustedCert

	@Shared X509Certificate rootCA
	@Shared X509Certificate policyCA
	@Shared X509Certificate serverCA
	@Shared X509Certificate serverCert
	Properties config
	String signKeyKeyId

	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		CertificateFactory cf = CertificateFactory.getInstance("X.509","BC")
		testCert = cf.generateCertificate(new ByteArrayInputStream(Base64.decode(TestData.base64Cert)))
		testCertWithKeyUsage = cf.generateCertificate(new ByteArrayInputStream(Base64.decode(TestData.base64CertWithKeyUsage)))
		untrustedCert = cf.generateCertificate(new ByteArrayInputStream(Base64.decode(TestPKIA.TEST_OCSP_POLICY_CA_CERT_BASE64)))
		rootCA = cf.generateCertificate(new ByteArrayInputStream(Base64.decode(TestPKIA.TEST_ROOT_CA_CERT_BASE64)))
		policyCA = cf.generateCertificate(new ByteArrayInputStream(Base64.decode(TestPKIA.TEST_POLICY_CA_CERT_BASE64)))
		serverCA = cf.generateCertificate(new ByteArrayInputStream(Base64.decode(TestPKIA.TEST_SERVER_CA_CERT_BASE64)))
		serverCert = cf.generateCertificate(new ByteArrayInputStream(Base64.decode(TestPKIA.TEST_SERVER_CERT_BASE64)))
	}
	def setup(){


		prov = newSimpleMessageSecurityProvider([:])
		
		signKeyKeyId = XMLEncrypter.generateKeyId(prov.getSigningCertificate().getPublicKey())
	}

	def cleanupSpec(){
		XMLSigner.systemTime = new DefaultSystemTime()
	}
	
	def "Verify that provider is initialized properly"(){
		expect:
		prov.signingAlgorithmScheme == SigningAlgorithmScheme.RSAWithSHA256
		prov.encryptionAlgorithmScheme == EncryptionAlgorithmScheme.RSA_PKCS1_5_WITH_AES256
	}

	def "Verify that if truststore type is CA the provider throws MessageProcessingException, if match subject is true but trust store match field or match value settings"(){
		when:
		newSimpleMessageSecurityProvider([(SETTING_TRUSTKEYSTORE_TYPE): TRUSTKEYSTORE_TYPE_CA,
										  (SETTING_TRUSTKEYSTORE_MATCHSUBJECT): "true",
										  (SETTING_TRUSTKEYSTORE_MATCHDNVALUE): "Tommy"])
		then:
		def e = thrown(MessageProcessingException)
		e.message == "Error required configuration property simplesecurityprovider.trustkeystore.matchdnfield not set."
		when:
		newSimpleMessageSecurityProvider([(SETTING_TRUSTKEYSTORE_TYPE): TRUSTKEYSTORE_TYPE_CA,
										  (SETTING_TRUSTKEYSTORE_MATCHSUBJECT): "true",
										  (SETTING_TRUSTKEYSTORE_MATCHDNFIELD): "CN"])
		then:
		e = thrown(MessageProcessingException)
		e.message == "Error required configuration property simplesecurityprovider.trustkeystore.matchdnvalue not set."
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
		XMLSigner.systemTime = TestUtils.mockSystemTime("2013-10-01")
		when:
		X509Certificate cert = prov.getSigningCertificate();
		then:
		prov.isValidAndAuthorized(cert, "someorg")
	}
	
	
	def "Test that isValidAndAuthorized() does not trust an untrusted certificate for mode ENDENTITY."(){
		setup:
		XMLSigner.systemTime = TestUtils.mockSystemTime("2019-12-01")
		expect:
		!prov.isValidAndAuthorized(untrustedCert, "someorg")
	}

	def "Test that isValidAndAuthorized() does accept certificate with wrong key usage"(){
		setup:
		XMLSigner.systemTime = TestUtils.mockSystemTime("2013-10-01")
		expect:
		!prov.isValidAndAuthorized(testCert, "someorg")
	}
	
	def "Test that isValidAndAuthorized() does not trust an expired certificate"(){
		setup:
		XMLSigner.systemTime = TestUtils.mockSystemTime("2017-10-01")
		when:
		X509Certificate cert = prov.getSigningCertificate();
		then:
		!prov.isValidAndAuthorized(cert, "someorg")
	}
	
	
	def "Test that isValidAndAuthorized() does not trust an not yet valid certificate for mode ENDENTITY."(){
		setup:
		XMLSigner.systemTime = TestUtils.mockSystemTime("2001-10-01")
		when:
		X509Certificate cert = prov.getSigningCertificate();
		then:
		!prov.isValidAndAuthorized(cert, "someorg")
	}

	def "Verify that isValidAndAuthorized in mode CA accepts trusted certificates by issuer and matches dn"(){
		setup:
		XMLSigner.systemTime = TestUtils.mockSystemTime("2021-01-01")
		prov = newSimpleMessageSecurityProvider([(SETTING_TRUSTKEYSTORE_TYPE): TRUSTKEYSTORE_TYPE_CA,
												 (SETTING_TRUSTKEYSTORE_MATCHDNFIELD): "CN",
												 (SETTING_TRUSTKEYSTORE_MATCHDNVALUE): "server.dummy.org",
												 (SETTING_TRUSTKEYSTORE_PATH): genTrustStore()])
		expect:
		prov.isValidAndAuthorized(serverCert, "someorg")
	}

	def "Verify that isValidAndAuthorized in mode CA does not accepts trusted certificates with invalid certificate match"(){
		setup:
		XMLSigner.systemTime = TestUtils.mockSystemTime("2021-01-01")
		prov = newSimpleMessageSecurityProvider([(SETTING_TRUSTKEYSTORE_TYPE): TRUSTKEYSTORE_TYPE_CA,
												 (SETTING_TRUSTKEYSTORE_MATCHDNFIELD): "CN",
												 (SETTING_TRUSTKEYSTORE_MATCHDNVALUE): "sometest",
												 (SETTING_TRUSTKEYSTORE_PATH): genTrustStore()])
		prov.truststoreHelper.systemTime = TestUtils.mockSystemTime("2021-01-01")
		prov.truststoreHelper.log = Mock(Logger)
		when:
		def result = prov.isValidAndAuthorized(serverCert, "someorg")
		then:
		!result
		1 * prov.truststoreHelper.log.severe("Error validating certificate CN=server.dummy.org,L=Kista,O=Certificate Services,OU=Security, does not match configured truststore value of CN = sometest")
	}

	def "Verify that isValidAndAuthorized in mode CA does not accepts untrusted certificates."(){
		setup:
		prov = newSimpleMessageSecurityProvider([(SETTING_TRUSTKEYSTORE_TYPE): TRUSTKEYSTORE_TYPE_CA,
												 (SETTING_TRUSTKEYSTORE_MATCHDNFIELD): "CN",
												 (SETTING_TRUSTKEYSTORE_MATCHDNVALUE): "sometest",
												 (SETTING_TRUSTKEYSTORE_PATH): genTrustStore()])
		XMLSigner.systemTime = TestUtils.mockSystemTime("2019-01-01")
		prov.truststoreHelper.systemTime = TestUtils.mockSystemTime("2019-01-01")
		prov.truststoreHelper.log = Mock(Logger)
		when:
		def result = prov.isValidAndAuthorized(testCertWithKeyUsage, "someorg")
		then:
		!result
		1 * prov.truststoreHelper.log.log(Level.SEVERE,"Error validating certificate chain of CSMessage signing certificate: Trust anchor for certification path not found.",_)
	}
	
	def "Verify that signature key is used as decryption key if no decryption key has been specified."(){
		expect:
		prov.defaultDecryptionKeyId == signKeyKeyId
		prov.getDecryptionKeyIds().size() == 1
		prov.getDecryptionKeyIds().iterator().next() == signKeyKeyId
		prov.getDecryptionCertificate(null) == prov.getSigningCertificate()
		prov.getDecryptionCertificateChain(null).length == 2
		prov.getDecryptionCertificateChain(null)[0] == prov.getSigningCertificate()
		prov.getDecryptionKey(null) == prov.getSigningKey()
		
	}
	
	def "Verify that if separate encryption keystore is loaded its keys are separate from signing keystores"(){
		setup:
		config.setProperty(SETTING_DECRYPTKEYSTORE_PATH, this.getClass().getResource("/decryptionks.jks").getPath())
		config.setProperty(SETTING_DECRYPTKEYSTORE_PASSWORD, "password")
		config.setProperty(SETTING_DECRYPTKEYSTORE_DEFAULTKEY_ALIAS, "key1")
		
		prov = new SimpleMessageSecurityProvider(config);
		def ks = prov.getDecryptionKeyStore(config)
		
		def keyId1 = XMLEncrypter.generateKeyId(ks.getCertificate("key1").publicKey)
		def keyId2 = XMLEncrypter.generateKeyId(ks.getCertificate("key2").publicKey)
		def keyId3 = XMLEncrypter.generateKeyId(ks.getCertificate("key3").publicKey)
		
		expect:
		keyId1 != signKeyKeyId
		prov.defaultDecryptionKeyId == keyId1
		prov.getDecryptionKeyIds().size() == 3
		prov.getDecryptionKeyIds().contains(keyId1)
		prov.getDecryptionKeyIds().contains(keyId2)
		prov.getDecryptionKeyIds().contains(keyId3)
		
		prov.getDecryptionCertificate(null) == ks.getCertificate("key1")
		prov.getDecryptionCertificateChain(null).length == 1
		prov.getDecryptionCertificateChain(null)[0] == ks.getCertificate("key1")
		prov.getDecryptionKey(null) == ks.getKey("key1","password".toCharArray())
		
		prov.getDecryptionCertificate(keyId1) == ks.getCertificate("key1")
		prov.getDecryptionCertificateChain(keyId1).length == 1
		prov.getDecryptionCertificateChain(keyId1)[0] == ks.getCertificate("key1")
		prov.getDecryptionKey(keyId1) == ks.getKey("key1","password".toCharArray())
		
		prov.getDecryptionCertificate(keyId2) == ks.getCertificate("key2")
		prov.getDecryptionCertificateChain(keyId2).length == 1
		prov.getDecryptionCertificateChain(keyId2)[0] == ks.getCertificate("key2")
		prov.getDecryptionKey(keyId2) == ks.getKey("key2","password".toCharArray())
		
		prov.getDecryptionCertificate(keyId3) == ks.getCertificate("key3")
		prov.getDecryptionCertificateChain(keyId3).length == 1
		prov.getDecryptionCertificateChain(keyId3)[0] == ks.getCertificate("key3")
		prov.getDecryptionKey(keyId3) == ks.getKey("key3","password".toCharArray())
		
	}
	
	def "Verify that getDecryptionKeyStore fetches separate encryption keystore if configured otherwise returns signature keystore"(){
		expect: "Sign keystore has only two entries"
		prov.getDecryptionKeyStore(config).size() == 2
		when:
		config.setProperty(SETTING_DECRYPTKEYSTORE_PATH, this.getClass().getResource("/decryptionks.jks").getPath())
		config.setProperty(SETTING_DECRYPTKEYSTORE_PASSWORD, "password")
		then:
		prov.getDecryptionKeyStore(config).size() == 3
	}
	
	def "Verify that getDecryptionKeyStorePassword() that fetches the correct password depending on weither simplesecurityprovider.decryptkeystore.path is set or not."(){
		expect: "Verify that sign keystore password is returned if no decryptkeystore path is set."
		new String(prov.getDecryptionKeyStorePassword(config)) == "tGidBq0Eep"
		when:
		Properties config = new Properties()
		config.setProperty(SETTING_DECRYPTKEYSTORE_PATH, "somepath")
		config.setProperty(SETTING_DECRYPTKEYSTORE_PASSWORD, "somepassword")
		then:
		new String(prov.getDecryptionKeyStorePassword(config)) == "somepassword"
		when:
		prov.getDecryptionKeyStorePassword(new Properties())
		then:
		thrown MessageProcessingException
	}
	
	def "Verify that getDefaultDecryptionAlias first checks for setting simplesecurityprovider.encryptkeystore.defaultkey.alias then fallbacks to simplesecurityprovider.signingkeystore.alias before throwing MessageProcessingException"(){
		setup:
		Properties config = new Properties()
		config.setProperty(SETTING_DECRYPTKEYSTORE_DEFAULTKEY_ALIAS, "somedefaultkey")
		config.setProperty(SETTING_SIGNINGKEYSTORE_ALIAS, "somesignalias")
		expect:
		prov.getDefaultDecryptionAlias(config) ==  "somedefaultkey"
		when:
		config.remove(SETTING_DECRYPTKEYSTORE_DEFAULTKEY_ALIAS)
		then:
		prov.getDefaultDecryptionAlias(config) ==  "somesignalias"
		when:
		config.remove(SETTING_SIGNINGKEYSTORE_ALIAS)
		prov.getDefaultDecryptionAlias(config)
		then:
		thrown MessageProcessingException
	}
	
	def "Verify getKeyStore() returns a valid JKS keystore, or throws exception if key store couldn't be read"(){
		expect:
		prov.getKeyStore(config, SETTING_SIGNINGKEYSTORE_PATH, SETTING_SIGNINGKEYSTORE_PASSWORD) instanceof KeyStore
		when:
		config.setProperty(SETTING_SIGNINGKEYSTORE_PATH, "invalid")
		prov.getKeyStore(config, SETTING_SIGNINGKEYSTORE_PATH, SETTING_SIGNINGKEYSTORE_PASSWORD)
		then:
		thrown MessageProcessingException
		
		when:
		config.setProperty(SETTING_SIGNINGKEYSTORE_PATH, this.getClass().getResource("/dummykeystore.jks").getPath())
		config.setProperty(SETTING_SIGNINGKEYSTORE_PASSWORD, "INVALID")
		prov.getKeyStore(config, SETTING_SIGNINGKEYSTORE_PATH, SETTING_SIGNINGKEYSTORE_PASSWORD)
		then:
		thrown MessageProcessingException
		
	}

	def newSimpleMessageSecurityProvider(Map m) {
		config = new Properties()
		config.setProperty(SETTING_SIGNINGKEYSTORE_PATH, this.getClass().getResource("/dummykeystore.jks").getPath())
		config.setProperty(SETTING_SIGNINGKEYSTORE_PASSWORD, "tGidBq0Eep")
		config.setProperty(SETTING_SIGNINGKEYSTORE_ALIAS, "test")

		if(m[SETTING_TRUSTKEYSTORE_TYPE]){
			config.setProperty(SETTING_PREFIX + SETTING_TRUSTKEYSTORE_TYPE, m[SETTING_TRUSTKEYSTORE_TYPE])
		}
		config.setProperty(SETTING_TRUSTKEYSTORE_PATH, (String) (m[SETTING_TRUSTKEYSTORE_PATH] ? m[SETTING_TRUSTKEYSTORE_PATH] : this.getClass().getResource("/testtruststore.jks").getPath()))
		config.setProperty(SETTING_TRUSTKEYSTORE_PASSWORD, "foo123")
		if(m[SETTING_TRUSTKEYSTORE_MATCHSUBJECT]){
			config.setProperty(SETTING_PREFIX + SETTING_TRUSTKEYSTORE_MATCHSUBJECT, m[SETTING_TRUSTKEYSTORE_MATCHSUBJECT])
		}
		if(m[SETTING_TRUSTKEYSTORE_MATCHDNFIELD]){
			config.setProperty(SETTING_PREFIX + SETTING_TRUSTKEYSTORE_MATCHDNFIELD, m[SETTING_TRUSTKEYSTORE_MATCHDNFIELD])
		}
		if(m[SETTING_TRUSTKEYSTORE_MATCHDNVALUE]){
			config.setProperty(SETTING_PREFIX + SETTING_TRUSTKEYSTORE_MATCHDNVALUE, m[SETTING_TRUSTKEYSTORE_MATCHDNVALUE])
		}
		config.setProperty(SETTING_ENCRYPTION_ALGORITHM_SCHEME, " RSA_pkcs1_5_WITH_AES256 ")
		return  new SimpleMessageSecurityProvider(config)
	}

	String genTrustStore(){
		File tempFile = new File("build/tmp/testtruststore.jks")
		KeyStore keyStore = KeyStore.getInstance("JKS")
		keyStore.load(null,null)
		keyStore.setCertificateEntry("rootca", rootCA)
		keyStore.setCertificateEntry("policyCA", policyCA)
		keyStore.setCertificateEntry("serverCA", serverCA)
		keyStore.store(new FileOutputStream(tempFile), "foo123".toCharArray())
		return tempFile.getPath()
	}
}
