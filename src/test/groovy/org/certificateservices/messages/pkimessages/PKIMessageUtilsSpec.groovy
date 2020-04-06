package org.certificateservices.messages.pkimessages

import static org.certificateservices.messages.pkimessages.TestMessages.*

import java.lang.reflect.Method;

import org.certificateservices.messages.DummyMessageSecurityProvider;
import org.certificateservices.messages.pkimessages.jaxb.ObjectFactory;
import org.certificateservices.messages.pkimessages.jaxb.PKIMessage;
import org.certificateservices.messages.pkimessages.jaxb.PKIMessage.Payload;
import org.certificateservices.messages.pkimessages.jaxb.PKIResponse;
import org.junit.After;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

class PKIMessageUtilsSpec extends Specification{
	
	PKIMessageParser parser = new DefaultPKIMessageParser();
	@Shared ObjectFactory of = new ObjectFactory();
	DummyMessageSecurityProvider secprov = new DummyMessageSecurityProvider();
	
	
	def setup(){
		Properties config = new Properties();
		config.setProperty(DefaultPKIMessageParser.SETTING_SOURCEID, "SOMESOURCEID");
		parser.init(secprov, config)
		
	}
		
	@Unroll
	def "Verify that getInResponseTo fetches in reply to for a pki response of type #name"(){
		setup:
		PKIMessage message = createMessage(payloadResponse, "123-123-123")
		expect:
		PKIMessageUtils.getInResponseTo(message) == "123-123-123"
		where:
		name                               | payloadResponse
		"FetchHardTokenDataResponse"       | of.createChangeCredentialStatusResponse()
		"GetCredentialResponse"            | of.createGetCredentialResponse()
		"GetCredentialStatusListResponse"  | of.createGetCredentialStatusListResponse()
		"GetIssuerCredentialsResponse"     | of.createGetIssuerCredentialsResponse()
		"IsIssuerResponse"                 | of.createIsIssuerResponse()
		"IssueTokenCredentialsResponse"    | of.createIssueTokenCredentialsResponse()
		"RemoveCredentialResponse"         | of.createRemoveCredentialResponse()
		"StoreHardTokenDataResponse"       | of.createStoreHardTokenDataResponse()
		"FailureResponse"                  | of.createPKIResponse()		
	}
	
	def "Verify that getInResponseTo returns null if no reply id is found"(){
		expect:
		PKIMessageUtils.getInResponseTo(createMessage(of.createChangeCredentialStatusResponse(), null)) == null
		PKIMessageUtils.getInResponseTo(createMessage(of.createChangeCredentialStatusResponse(), " ")) == null
		when:
		PKIMessage message = new PKIMessage();
		Payload payload = of.createPKIMessagePayload()		
		payload.setChangeCredentialStatusRequest(of.createChangeCredentialStatusRequest())
		message.setPayload(payload)		
		then:
		PKIMessageUtils.getInResponseTo(message) == null
	}

	private PKIMessage createMessage(PKIResponse payloadData, String inResponseTo){
		PKIMessage message = new PKIMessage();
		
		payloadData.inResponseTo = inResponseTo
		
		Payload payload = of.createPKIMessagePayload()
		if(payloadData instanceof PKIResponse){
			payload.setFailureResponse(payloadData)
		}else{
			for(Method m : payload.getClass().methods){
				if(m.name == "set" + payloadData.getClass().getSimpleName()){
					m.invoke(payload, payloadData)
					break
				}
			}
		}
		message.setPayload(payload)
		return message
	}
}
