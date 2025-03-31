package org.signatureservice.messages.assertion

import spock.lang.Specification
import spock.lang.Unroll;
import static AssertionTypeEnum.*

class AssertionTypeEnumSpec extends Specification {
	
	@Unroll
	def "verify that AssertionTypeEnum #type has assertion value #value"(){
		expect:
		type.attributeValue == value
		type.assertionDataClass == assertionDataClass
		where:
		type                  | value                       | assertionDataClass 
		APPROVAL_TICKET       | "APPROVAL_TICKET"           | ApprovalAssertionData.class
		USER_DATA             | "USER_DATA"                 | UserDataAssertionData.class
		AUTHORIZATION_TICKET  | "AUTHORIZATION_TICKET"      | AuthorizationAssertionData.class
	}

}
