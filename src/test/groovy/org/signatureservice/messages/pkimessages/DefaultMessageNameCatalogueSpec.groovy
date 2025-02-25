package org.signatureservice.messages.pkimessages

import org.signatureservice.messages.pkimessages.jaxb.IsIssuerRequest
import org.signatureservice.messages.pkimessages.jaxb.IsIssuerResponse
import org.signatureservice.messages.pkimessages.jaxb.PKIResponse
import spock.lang.Specification


@SuppressWarnings("deprecation")
class DefaultMessageNameCatalogueSpec extends Specification {
	

	static MessageNameCatalogue messageNameCatalogue;
	

	def setupSpec(){		
		Properties config = new Properties();
		config.setProperty(DefaultMessageNameCatalogue.SETTING_MESSAGE_NAME_PREFIX + "isissuerrequest", "SomeOtherName");
		messageNameCatalogue = new DefaultMessageNameCatalogue();
		messageNameCatalogue.init(config);
	}

	
	def "Test default name is returned as the simple name of the payload element class."(){
		expect:
		messageNameCatalogue.lookupName(null, new IsIssuerResponse()) == "IsIssuerResponse"
	}
	
	def "Test that overriden name is returned when setting for payload element exists."(){
		expect:
		messageNameCatalogue.lookupName(null,new IsIssuerRequest()) == "SomeOtherName"
	}
	
	def "Test that by default is 'FailureResponse' returned for a PKIResponse."(){
		expect:
		messageNameCatalogue.lookupName(null,new PKIResponse()) == "FailureResponse"
	}


}
