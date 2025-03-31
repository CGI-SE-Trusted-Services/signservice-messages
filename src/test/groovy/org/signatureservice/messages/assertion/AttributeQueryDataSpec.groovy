package org.signatureservice.messages.assertion

import org.bouncycastle.jce.provider.BouncyCastleProvider

import java.security.Security

import org.apache.xml.security.Init
import org.signatureservice.messages.csmessages.PayloadParserRegistry;
import org.signatureservice.messages.utils.DefaultSystemTime
import spock.lang.Shared;
import spock.lang.Specification

import static AttributeQueryTypeEnum.*
import static org.signatureservice.messages.TestUtils.*

class AttributeQueryDataSpec extends Specification {
	
	
	
	@Shared AssertionPayloadParser assertionPayloadParser
	
	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Init.init()
		setupRegisteredPayloadParser();
		
		assertionPayloadParser = PayloadParserRegistry.getParser(AssertionPayloadParser.NAMESPACE);

	}
	
	def setup(){
		assertionPayloadParser.systemTime = new DefaultSystemTime()
	}

	def "Verify that parse() method sets all fields propely for type: AUTHORIZATION_TICKET"(){
		when:
		AttributeQueryData aqd  = assertionPayloadParser.parseAttributeQuery(genAttributeQuery(AttributeQueryTypeEnum.AUTHORIZATION_TICKET, "SomeSubject"))
		
		then:
		aqd.getID() != null
		aqd.getSubjectId() == "SomeSubject"
		aqd.getType() == AttributeQueryTypeEnum.AUTHORIZATION_TICKET
	}
	
	def "Verify that parse() method sets all fields propely for type: USER_DATA"(){
		when:
		AttributeQueryData aqd  = assertionPayloadParser.parseAttributeQuery(genAttributeQuery(AttributeQueryTypeEnum.USER_DATA, "SomeSubject"))
		
		then:
		aqd.getID() != null
		aqd.getSubjectId() == "SomeSubject"
		aqd.getType() == AttributeQueryTypeEnum.USER_DATA
		aqd.getTokenType() == "SomeTokenType"
	}
	
	def "Verify that hashCode() and equals() only compares id"(){
		setup:
		AttributeQueryData aqd1 = assertionPayloadParser.parseAttributeQuery(genAttributeQuery(AUTHORIZATION_TICKET, "SomeSubject1"))
		aqd1.id = "123"
		AttributeQueryData aqd2 = assertionPayloadParser.parseAttributeQuery(genAttributeQuery(USER_DATA, "SomeSubject2"))
		aqd2.id = "123"
		AttributeQueryData aqd3 = assertionPayloadParser.parseAttributeQuery(genAttributeQuery(AUTHORIZATION_TICKET, "SomeSubject1"))
		aqd3.id = "124"
		expect:

		aqd1.hashCode() == aqd2.hashCode()
		aqd2.hashCode() != aqd3.hashCode()
		aqd1 == aqd2
		aqd3 != aqd2
		
	}
	
	def "verify that toString() generates a string"(){
		expect:
		assertionPayloadParser.parseAttributeQuery(genAttributeQuery(AUTHORIZATION_TICKET, "SomeSubject1")).toString() instanceof String
	}


	private byte[] genAttributeQuery(AttributeQueryTypeEnum type, String subjectId){
		switch(type){
			case AUTHORIZATION_TICKET:
			 return assertionPayloadParser.genDistributedAuthorizationRequest(subjectId)
			 case USER_DATA: 
			 return assertionPayloadParser.genUserDataRequest(subjectId, "SomeTokenType")
		}
		return null
	}

}
