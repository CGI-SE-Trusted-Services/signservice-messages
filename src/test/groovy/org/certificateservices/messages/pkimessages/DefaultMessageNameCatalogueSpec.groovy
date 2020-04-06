package org.certificateservices.messages.pkimessages

import java.security.PrivateKey
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import org.certificateservices.messages.pkimessages.jaxb.IsIssuerRequest
import org.certificateservices.messages.pkimessages.jaxb.IsIssuerResponse
import org.certificateservices.messages.pkimessages.jaxb.ObjectFactory;
import org.certificateservices.messages.pkimessages.jaxb.PKIMessage;
import org.certificateservices.messages.pkimessages.jaxb.PKIResponse
import org.certificateservices.messages.DummyMessageSecurityProvider;
import org.certificateservices.messages.pkimessages.DefaultMessageNameCatalogue;
import org.certificateservices.messages.pkimessages.MessageNameCatalogue;
import org.junit.BeforeClass;
import org.junit.Test;

import spock.lang.Specification


@SuppressWarnings("deprecation")
public class DefaultMessageNameCatalogueSpec extends Specification {
	

	static MessageNameCatalogue messageNameCatalogue;
	

	def setupSpec(){		
		Properties config = new Properties();
		config.setProperty(DefaultMessageNameCatalogue.SETTING_MESSAGE_NAME_PREFIX + "isissuerrequest", "SomeOtherName");
		messageNameCatalogue = new DefaultMessageNameCatalogue();
		messageNameCatalogue.init(config);
	}

	
	@Test
	def "Test default name is returned as the simple name of the payload element class."(){
		expect:
		messageNameCatalogue.lookupName(null, new IsIssuerResponse()) == "IsIssuerResponse"
	}
	
	@Test
	def "Test that overriden name is returned when setting for payload element exists."(){
		expect:
		messageNameCatalogue.lookupName(null,new IsIssuerRequest()) == "SomeOtherName"
	}
	
	@Test
	def "Test that by default is 'FailureResponse' returned for a PKIResponse."(){
		expect:
		messageNameCatalogue.lookupName(null,new PKIResponse()) == "FailureResponse"
	}


}
