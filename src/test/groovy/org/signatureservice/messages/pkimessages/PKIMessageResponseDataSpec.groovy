package org.signatureservice.messages.pkimessages

import org.signatureservice.messages.pkimessages.constants.Constants;
import spock.lang.Specification

@SuppressWarnings("deprecation")
class PKIMessageResponseDataSpec extends Specification {
	
	
	def "Test isForwardable works correctly"(){
		setup:
		Set<String> excluded = ["DEST1", "DEST2"]
		expect:
		!new PKIMessageResponseData(null,null,null, "DEST1", null, true).isForwardable(excluded)
		!new PKIMessageResponseData(null,null,null, "DEST2", null, true).isForwardable(excluded)
		!new PKIMessageResponseData(null,null,null, "DEST3", null, false).isForwardable(excluded)
		new PKIMessageResponseData(null,null,null, "DEST3", null, true).isForwardable(excluded)
	}
	
	def "Test that getRelatedEndEntity returns UNKNOWN if not set"(){
		expect:
		new PKIMessageResponseData(null,null,null, null, null, true).getRelatedEndEntity() == Constants.RELATED_END_ENTITY_UNKNOWN
		new PKIMessageResponseData(null,null,"SomeEntity", null, null, true).getRelatedEndEntity() == "SomeEntity"
	}
	
	def "Test getMessageProperties doesn't return null"(){
		expect:
		new PKIMessageResponseData(null,null,null, null, null, true).getMessageProperties() != null		
	}
	




}
