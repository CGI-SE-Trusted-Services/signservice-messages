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

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.certificateservices.messages.utils.XMLSigner

import java.security.Security

import static org.certificateservices.messages.SimpleMessageSecurityProvider.*

import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey
import java.text.SimpleDateFormat

import org.apache.xml.security.utils.Base64
import org.certificateservices.messages.utils.SystemTime
import org.certificateservices.messages.utils.XMLEncrypter

import spock.lang.Specification

class SimplePKIMessageSecurityProviderSpec extends Specification {
	
	SimpleMessageSecurityProvider prov
	
	X509Certificate testCert
	X509Certificate testCertWithKeyUsage
	Properties config
	String signKeyKeyId

	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
	}
	def setup(){

		CertificateFactory cf = CertificateFactory.getInstance("X.509","BC")
		testCert = cf.generateCertificate(new ByteArrayInputStream(Base64.decode(TestData.base64Cert)))
		testCertWithKeyUsage = cf.generateCertificate(new ByteArrayInputStream(Base64.decode(TestData.base64CertWithKeyUsage)))
		
		config = new Properties();
		config.setProperty(SETTING_SIGNINGKEYSTORE_PATH, this.getClass().getResource("/dummykeystore.jks").getPath())
		config.setProperty(SETTING_SIGNINGKEYSTORE_PASSWORD, "tGidBq0Eep")
		config.setProperty(SETTING_SIGNINGKEYSTORE_ALIAS, "test")
		
		config.setProperty(SETTING_TRUSTKEYSTORE_PATH, this.getClass().getResource("/testtruststore.jks").getPath())
		config.setProperty(SETTING_TRUSTKEYSTORE_PASSWORD, "foo123")
		config.setProperty(SETTING_ENCRYPTION_ALGORITHM_SCHEME, " RSA_pkcs1_5_WITH_AES256 ")
		prov = new SimpleMessageSecurityProvider(config);
		
		signKeyKeyId = XMLEncrypter.generateKeyId(prov.getSigningCertificate().getPublicKey())
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
		XMLSigner.systemTime = TestUtils.mockSystemTime("2013-10-01")
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
		XMLSigner.systemTime = TestUtils.mockSystemTime("2017-10-01")
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
}
