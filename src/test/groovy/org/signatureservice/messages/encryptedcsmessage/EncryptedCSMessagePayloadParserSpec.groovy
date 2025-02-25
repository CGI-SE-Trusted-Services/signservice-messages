package org.signatureservice.messages.encryptedcsmessage

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.signatureservice.messages.csmessages.CSMessageParserManager

import java.security.Security;
import java.security.cert.X509Certificate;
import org.apache.xml.security.Init;
import org.signatureservice.messages.MessageSecurityProvider;
import org.signatureservice.messages.csmessages.PayloadParserRegistry;
import org.signatureservice.messages.csmessages.jaxb.CSMessage;
import org.signatureservice.messages.csmessages.jaxb.IsApprovedRequest;
import org.signatureservice.messages.encryptedcsmessage.jaxb.ObjectFactory;
import org.signatureservice.messages.utils.MessageGenerateUtils;
import org.signatureservice.messages.utils.SystemTime;
import org.w3c.dom.Document;

import spock.lang.Specification

class EncryptedCSMessagePayloadParserSpec extends Specification {
	
	EncryptedCSMessagePayloadParser pp;
	ObjectFactory of = new ObjectFactory()
	org.signatureservice.messages.csmessages.jaxb.ObjectFactory csMessageOf = new org.signatureservice.messages.csmessages.jaxb.ObjectFactory()
	X509Certificate recipient

	def TimeZone currentTimeZone;

	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Init.init();
	}
	
	def setup(){
		currentTimeZone = TimeZone.getDefault()
		TimeZone.setDefault(TimeZone.getTimeZone("Europe/Stockholm"))
		setupRegisteredPayloadParser();
		
		pp = PayloadParserRegistry.getParser(EncryptedCSMessagePayloadParser.NAMESPACE);
		
		recipient = CSMessageParserManager.getCSMessageParser().messageSecurityProvider.getDecryptionCertificate(MessageSecurityProvider.DEFAULT_DECRYPTIONKEY)
		
		pp.systemTime = Mock(SystemTime)
		pp.systemTime.getSystemTime() >> new Date(1436279213000L)
	}

	def cleanup(){
		TimeZone.setDefault(currentTimeZone)
	}

	
	def "Verify that JAXBPackage(), getNameSpace(), getSchemaAsInputStream(), getSupportedVersions(), getDefaultPayloadVersion() returns the correct values"(){
		expect:
		pp.getJAXBPackage() == null
		pp.getNameSpace() == "http://certificateservices.org/xsd/encrypted_csmessages2_0"
		pp.getSchemaAsInputStream("2.0") == null
		pp.getDefaultPayloadVersion() == "2.0"
		pp.getSupportedVersions() == ["2.0"] as String[]
	}

	def "Verify that calling getResponseStatus() throws IllegalStateException"(){
		when:
		pp.getResponseStatus(null)
		then:
		thrown IllegalStateException
	}
	
	def "Verify that calling generateGetApprovalRequest() throws IllegalStateException"(){
		when:
		pp.generateGetApprovalRequest(null,null,null,null,null,null)
		then:
		thrown IllegalStateException
	}
	
	def "Verify that calling generateIsApprovedRequest() throws IllegalStateException"(){
        when:
		pp.generateIsApprovedRequest(null,null,null,null,null,null)
		then:
		thrown IllegalStateException
	}
	
	def "Verify that calling getPayload() throws IllegalStateException"(){
		when:
		pp.getPayload(null)
		then:
		thrown IllegalStateException
	}
	
	def "Verify that generateGetAvailableKeyStoreInfoRequest() generates a valid xml message and generateGetAvailableKeyStoreInfoResponse() generates a valid CSMessageResponseData"(){
		setup:
		String requestId = MessageGenerateUtils.generateRandomUUID()
		byte[] req = genCSMessage(requestId)
		when:
		byte[] requestMessage = pp.genEncryptedCSMessage(req, [recipient])
		String message = new String(requestMessage, "UTF-8")
        //printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		then:
		message =~ 'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"'
		message =~ 'xmlns:xenc="http://www.w3.org/2001/04/xmlenc#'
		message =~ 'xmlns:enccs="http://certificateservices.org/xsd/encrypted_csmessages2_0"'
		xml.@ID != requestId
		xml.@timeStamp == "2015-07-07T16:26:53.000+02:00"
		xml.@version =="2.0"
		xml.EncryptedData.size() == 1
		
		when: "Try to generate message with a specified version"
		requestMessage = pp.genEncryptedCSMessage(req, "SomeVersion",[recipient])
		//printXML(requestMessage)
	    xml = slurpXml(requestMessage)
		then:
		xml.@version =="SomeVersion"

		
	}
	
	def "Verify that isEncryptedCSMessage() returns null for a plain text messages"(){
		setup:
		byte[] req = genCSMessage(MessageGenerateUtils.generateRandomUUID())
		expect:
		pp.isEncryptedCSMessage(req) == null
	}
	
	def "Verify that isEncryptedCSMessage() returns encrypted Doc for an encrypted message and that decryptDoc() returns a decrypted message with signature unbroken."(){
		setup:
		byte[] req = genCSMessage(MessageGenerateUtils.generateRandomUUID())
		byte[] encMessage = pp.genEncryptedCSMessage(req, [recipient])
		when:
		Document encDoc = pp.isEncryptedCSMessage(encMessage)
		then:
		encDoc != null
		when:
		byte[] req2 = pp.decryptDoc(encDoc)
		then:
		req == req2
		req2 != encMessage
		when: "Verify that the signature verifies"
		CSMessage csMessage = pp.parseMessage(req2)
		then:
		csMessage.getSignature() != null
	}

	def "Verify that parseMessage parses an encrypted CS message into a CS Message"(){
		setup:
		String requestId = MessageGenerateUtils.generateRandomUUID()
		byte[] req = genCSMessage(requestId)
		byte[] requestMessage = pp.genEncryptedCSMessage(req, [recipient])
		
		when:
		CSMessage message = pp.parseMessage(requestMessage)
		then:
		message.getPayload().getAny() instanceof IsApprovedRequest
	}
	
	def "Verify that parseMessage parses an plaintext CS message into a CS Message"(){
		setup:
		String requestId = MessageGenerateUtils.generateRandomUUID()
		byte[] req = genCSMessage(requestId)
		
		when:
		CSMessage message = pp.parseMessage(req)
		then:
		message.getPayload().getAny() instanceof IsApprovedRequest
	}
	
	

	private byte[] genCSMessage(String requestId){
		return CSMessageParserManager.getCSMessageParser().generateIsApprovedRequest(requestId, "SomeDestination", "SomeOrg", "12345", null, null)
	}
}
