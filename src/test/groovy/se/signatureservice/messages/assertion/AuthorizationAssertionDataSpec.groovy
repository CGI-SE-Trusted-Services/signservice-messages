package se.signatureservice.messages.assertion

import org.bouncycastle.jce.provider.BouncyCastleProvider
import se.signatureservice.messages.csmessages.CSMessageParserManager

import java.security.Security
import java.security.cert.X509Certificate;

import jakarta.xml.bind.JAXBElement;

import org.apache.xml.security.Init
import se.signatureservice.messages.MessageSecurityProvider;
import se.signatureservice.messages.saml2.assertion.jaxb.AssertionType;
import se.signatureservice.messages.csmessages.PayloadParserRegistry;
import se.signatureservice.messages.utils.SystemTime;

import spock.lang.Shared;
import spock.lang.Specification

import static se.signatureservice.messages.TestUtils.*

class AuthorizationAssertionDataSpec extends Specification {
	
	 
	
	@Shared X509Certificate cert
	@Shared AssertionPayloadParser assertionPayloadParser
	
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
	
	def "Verify that constructor sets all fields and getters retieves correct data"(){
		when:
		JAXBElement<AssertionType> assertion = genAuthorizationAssertion(false)
		AuthorizationAssertionData ad = assertionPayloadParser.parseAndDecryptAssertion(assertion)
		then:
		ad instanceof AuthorizationAssertionData
		ad.getId() == assertion.value.getID()
		ad.getRoles() == ["role1","role2"]
		ad.getDepartments() == null
		when:
		assertion = genAuthorizationAssertion(true)
		ad = assertionPayloadParser.parseAndDecryptAssertion(assertion)
		then:
		ad instanceof AuthorizationAssertionData
		ad.getId() == assertion.value.getID()
		ad.getRoles() == ["role1","role2"]
		ad.getDepartments() == ["department 1", "department 2"]
	}

	
	def "Verify that toString returns a string"(){
		setup:
		AuthorizationAssertionData ad = assertionPayloadParser.parseAndDecryptAssertion(genAuthorizationAssertion(false))
		expect:
		ad.toString() != null
		assertionPayloadParser.parseAndDecryptAssertion(genAuthorizationAssertion(true)).toString() != null
	}
	
	private JAXBElement<AssertionType> genAuthorizationAssertion(boolean useDepartments=false){
		List<String> deps = null;
		if(useDepartments){
			deps = ["department 1", "department 2"]
		}
		byte[] ticketData = assertionPayloadParser.genDistributedAuthorizationTicket("_123456789", "someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject",["role1", "role2"],deps, [cert])
		JAXBElement<AssertionType> assertion = assertionPayloadParser.getAssertionFromResponseType(assertionPayloadParser.parseAttributeQueryResponse(ticketData))
	}

}
