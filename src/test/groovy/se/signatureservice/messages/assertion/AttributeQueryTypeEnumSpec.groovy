package se.signatureservice.messages.assertion

import spock.lang.Specification
import spock.lang.Unroll;
import static AttributeQueryTypeEnum.*


class AttributeQueryTypeEnumSpec extends Specification {
	
	@Unroll
	def "verify that AttributeQueryTypeEnum #type has assertion value #value"(){
		expect:
		type.attributeValue == value
		where:
		type                  | value                        
		AUTHORIZATION_TICKET  | AssertionPayloadParser.ATTRIBUTE_NAME_ROLES           
		USER_DATA             | AssertionPayloadParser.ATTRIBUTE_NAME_USERDATA
	}

}
