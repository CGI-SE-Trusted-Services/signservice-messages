package org.signatureservice.messages.assertion

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.signatureservice.messages.csmessages.CSMessageParserManager

import java.security.Security
import java.security.cert.X509Certificate;

import javax.xml.bind.JAXBElement;

import org.apache.xml.security.Init
import org.signatureservice.messages.MessageSecurityProvider;
import org.signatureservice.messages.saml2.assertion.jaxb.AssertionType;
import org.signatureservice.messages.csmessages.PayloadParserRegistry;
import org.signatureservice.messages.csmessages.jaxb.ApproverType;
import org.signatureservice.messages.utils.SystemTime;

import spock.lang.Shared;
import spock.lang.Specification

class ApprovalAssertionDataSpec extends Specification {

	@Shared AssertionPayloadParser assertionPayloadParser
	@Shared X509Certificate cert
	
	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Init.init()
		setupRegisteredPayloadParser();
		
		assertionPayloadParser = PayloadParserRegistry.getParser(AssertionPayloadParser.NAMESPACE);
		assertionPayloadParser.systemTime = Mock(SystemTime)
		assertionPayloadParser.systemTime.getSystemTime() >> new Date(1436279213000)
		assertionPayloadParser.samlAssertionMessageParser.systemTime = assertionPayloadParser.systemTime
		
		cert = CSMessageParserManager.getCSMessageParser().messageSecurityProvider.getDecryptionCertificate(MessageSecurityProvider.DEFAULT_DECRYPTIONKEY)
	}
	
	def "Verify that parse sets all fields and getters retieves correct data"(){
		setup:
		def assertion = genApprovalAssertion()
		
		when:
		ApprovalAssertionData ad = assertionPayloadParser.parseAndDecryptAssertion(assertion)
		
		then:
		ad.getId() == assertion.value.getID()
		ad.approvalId == "1234"
		ad.approvalRequests == ["abcdef", "defcva"]
		ad.destinationId == AssertionPayloadParser.ANY_DESTINATION
		ad.approvers == null
		when:
		ad = assertionPayloadParser.parseAndDecryptAssertion(genApprovalAssertion("SomeDest"))
		then:
		ad.destinationId == "SomeDest"
		when: "Verify that if approvers exists are approvers set"
		ad = assertionPayloadParser.parseAndDecryptAssertion(genApprovalAssertion("SomeDest", true))
		then:
		ad.approvers.size() == 2
		ad.approvers[0].type == ApproverType.MANUAL
		ad.approvers[1].type == ApproverType.AUTOMATIC
		
		when: "Verify that parsing the assertion without decryption doesn't set the approvers field"
		List ads = assertionPayloadParser.parseAssertions([genApprovalAssertion("SomeDest", true)])
		then:
		ads.size() == 1		
		ads[0].approvalId == "1234"
		ads[0].approvalRequests == ["abcdef", "defcva"]
		ads[0].destinationId ==  "SomeDest"
		ads[0].approvers == null
	}
	
	
	def "Verify that toString returns a string"(){
		setup:
		ApprovalAssertionData ad = assertionPayloadParser.parseAndDecryptAssertion(genApprovalAssertion())
		
		expect:
		ad.toString() != null
	}

	private JAXBElement<AssertionType> genApprovalAssertion(String destinationId=null, boolean withApproverData=false){
		def approvers = null
		def recipents = null
		if(withApproverData){
			approvers = AssertionPayloadParserSpec.genApprovers()
			recipents = [cert]
		}
		
		
		byte[] ticketData = assertionPayloadParser.genApprovalTicket("someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject","1234",["abcdef", "defcva"], destinationId, approvers, recipents)
		def assertion = assertionPayloadParser.parseApprovalTicket(ticketData)
	}

}
