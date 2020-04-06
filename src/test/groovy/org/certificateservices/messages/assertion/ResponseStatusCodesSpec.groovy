package org.certificateservices.messages.assertion;

import spock.lang.Specification;
import spock.lang.Unroll;

import static org.certificateservices.messages.assertion.ResponseStatusCodes.*
public class ResponseStatusCodesSpec extends Specification{
	
	@Unroll
	def "Verify that status code #statuscode has uri value: #urivalue"(){
		expect:
		statuscode.getURIValue() == urivalue
		where:
		statuscode                   | urivalue
		SUCCESS                      | "urn:oasis:names:tc:SAML:2.0:status:Success"  
		REQUESTER                    | "urn:oasis:names:tc:SAML:2.0:status:Requester"
		RESPONDER                    | "urn:oasis:names:tc:SAML:2.0:status:Responder"
		VERSION_MISMATCH             | "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
	}

}
