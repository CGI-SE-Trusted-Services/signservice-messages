package org.signatureservice.messages.csmessages.examples

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.signatureservice.messages.utils.XMLSigner

import java.security.Security
import java.security.cert.X509Certificate

import org.signatureservice.messages.MessageSecurityProvider;
import org.signatureservice.messages.SimpleMessageSecurityProvider;
import org.certificateservices.messages.TestUtils
import org.signatureservice.messages.credmanagement.CredManagementPayloadParser
import org.signatureservice.messages.csmessages.CSMessageParserManager
import org.signatureservice.messages.csmessages.PayloadParserRegistry
import org.signatureservice.messages.csmessages.jaxb.CSMessage
import org.signatureservice.messages.encryptedcsmessage.EncryptedCSMessagePayloadParser
import org.signatureservice.messages.utils.MessageGenerateUtils;

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
	

	
	def "Example of Encrypted CS Message Workflow"(){
		setup: "For this example we will need the credential management and assertion payload parser"
		CredManagementPayloadParser cmpp = PayloadParserRegistry.getParser(CredManagementPayloadParser.NAMESPACE);
		EncryptedCSMessagePayloadParser encpp = PayloadParserRegistry.getParser(EncryptedCSMessagePayloadParser.NAMESPACE);
		when: "Step 1: Try to generate plain text CS Request"
		// On Client:
		byte[] plainTextRequest = cmpp.genChangeCredentialStatusRequest(MessageGenerateUtils.generateRandomUUID(), "SomeServerSystem", "SomeOrg", "CN=SomeIssuerId", "1234", 100, "10", null, null);
		// Then encrypt this message to the receipient on the server
		byte[] encryptedRequest = encpp.genEncryptedCSMessage(plainTextRequest, [recepient])
		// Then send the encrypted request to the server
		
		
		// On Server:
		// Use the encrypted payload parser to support encryted message, but unencrypted messages can be parsed as well in the same way as the other payload parsers
		CSMessage requestMessage = encpp.parseMessage(encryptedRequest)
		// If decryption key isn't found is MessageContentException thrown with a cause of NoDecryptionKeyFoundException
		// A plain text message works just as well
		CSMessage requestMessage2 = encpp.parseMessage(plainTextRequest)
		
		then:
		requestMessage.getID() == requestMessage2.getID()
	}
	

}
