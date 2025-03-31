package org.signatureservice.messages.csmessages.examples

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.signatureservice.messages.TestUtils
import org.signatureservice.messages.utils.XMLSigner

import java.security.Security
import java.security.cert.X509Certificate

import org.signatureservice.messages.MessageSecurityProvider;
import org.signatureservice.messages.SimpleMessageSecurityProvider;
import org.signatureservice.messages.csmessages.CSMessageParserManager

import spock.lang.Shared

/**
 * Examples on how to use the API when encrypting and decryting encrypted CS Messages.
 * <p>
 * This example only deals with the message generation aspects of the workflow. 
 * 
 * @author Philip Vendil
 *
 */
class EncryptedCSMessageWorkflowExampleSpec extends ExampleSpecification {
	
	// Simplest configuration using signing and encryption keystore with same key.
	// The KEYSTORELOCATION and TRUSTSTORE locations is replaeced in this script for the test to run.
	static def exampleConfig = """
simplesecurityprovider.signingkeystore.path=KEYSTORELOCATION
simplesecurityprovider.signingkeystore.password=tGidBq0Eep
simplesecurityprovider.signingkeystore.alias=test
simplesecurityprovider.trustkeystore.path=TRUSTSTORELOCATION
simplesecurityprovider.trustkeystore.password=foo123

csmessage.sourceid=SomeClientSystem
"""


	@Shared X509Certificate recepient
	
	
	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Properties config = getConfig(exampleConfig)
		
		// Required initialization code, only needed once for an application.
		
		// Start with setting up MessageSecurityProvider, one implementation is SimpleMessageSecurityProvider
		// using Java key stores to store it's signing and encryption keys.
		SimpleMessageSecurityProvider secProv = new SimpleMessageSecurityProvider(config);
		// This mocking is for testing only (to avoid failure due to expired certificates)
		XMLSigner.systemTime = TestUtils.mockSystemTime("2013-10-01")

		
		// Create and initialize the Default Message Provider with the security provider.
		// For client should the usually not need a reference to the CSMessageParser, use the PayloadParser
		// from PayloadParserRegistry should have all the necessary functions.
		CSMessageParserManager.initCSMessageParser(secProv, config)
		
		
		
		// Receipient key of more sensitive in-bound systems that might want to audit who approved a request. 
		recepient = secProv.getDecryptionCertificate(MessageSecurityProvider.DEFAULT_DECRYPTIONKEY)
		
	}
}
