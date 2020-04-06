package org.certificateservices.messages.pkimessages

import java.security.PrivateKey
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import org.certificateservices.messages.pkimessages.constants.Constants;
import org.certificateservices.messages.pkimessages.jaxb.IsIssuerRequest
import org.certificateservices.messages.pkimessages.jaxb.IsIssuerResponse
import org.certificateservices.messages.pkimessages.jaxb.ObjectFactory;
import org.certificateservices.messages.pkimessages.jaxb.PKIMessage;
import org.certificateservices.messages.pkimessages.jaxb.PKIResponse
import org.certificateservices.messages.DummyMessageSecurityProvider;
import org.certificateservices.messages.pkimessages.PKIMessageResponseData;
import org.junit.BeforeClass;
import org.junit.Test;

import spock.lang.Specification


@SuppressWarnings("deprecation")
class PKIMessageResponseDataSpec extends Specification {
	
	
	@Test
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
