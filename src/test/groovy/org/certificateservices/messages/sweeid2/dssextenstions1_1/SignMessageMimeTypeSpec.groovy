package org.certificateservices.messages.sweeid2.dssextenstions1_1

import spock.lang.Specification
import spock.lang.Unroll

import static org.certificateservices.messages.sweeid2.dssextenstions1_1.SignMessageMimeType.*;

class SignMessageMimeTypeSpec extends Specification {


	@Unroll
	def "Verify that SignMessageMimeType returns value #value for type #type"(){
		expect:
		type.getMimeType() == value
		where:
		type            | value
		HTML 			| "text/html"
		TEXT   			| "text"
		MARKDOWN 		| "text/markdown"
	}

}
