package org.signatureservice.messages.csmessages.manager

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.signatureservice.messages.csmessages.CSMessageParserManager

import java.security.Security;
import org.signatureservice.messages.DummyMessageSecurityProvider;
import org.signatureservice.messages.MessageContentException;
import org.signatureservice.messages.MessageProcessingException;
import org.signatureservice.messages.credmanagement.CredManagementPayloadParser;
import org.signatureservice.messages.csmessages.CSMessageParser;
import org.signatureservice.messages.credmanagement.jaxb.GetCredentialResponse;
import org.signatureservice.messages.csmessages.DefaultCSMessageParser;
import org.signatureservice.messages.csmessages.PayloadParserRegistry;
import org.signatureservice.messages.csmessages.jaxb.CSMessage;
import org.signatureservice.messages.csmessages.jaxb.CredentialRequest;
import org.signatureservice.messages.csmessages.jaxb.ObjectFactory;
import org.signatureservice.messages.csmessages.jaxb.TokenRequest;
import spock.lang.Shared
import spock.lang.Specification


class AutoRevokeReqRespManagerSpec extends Specification{

	@Shared AutoRevokeReqRespManager arrrm;
		
	@Shared ObjectFactory of = new ObjectFactory()
	@Shared org.signatureservice.messages.credmanagement.jaxb.ObjectFactory credOf = new org.signatureservice.messages.credmanagement.jaxb.ObjectFactory()
	
	@Shared DefaultCSMessageParser parser = new DefaultCSMessageParser()
	@Shared CredManagementPayloadParser credManagementPayloadParser;
	
	@Shared Properties config
	
	private static final String TEST_ID = "12345678-1234-4444-8000-123456789012"
	final String DESTINATION = "SOME.DESTINATION"

	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		config = new Properties();
        config.setProperty(DefaultCSMessageParser.SETTING_SOURCEID, "somesourceId");
		config.setProperty(DummyMessageHandler.SETTING_WAITTIME, "100")

		CSMessageParserManager.initCSMessageParser(new DummyMessageSecurityProvider(), config)
		parser = CSMessageParserManager.getCSMessageParser()
		credManagementPayloadParser = PayloadParserRegistry.getParser(CredManagementPayloadParser.NAMESPACE)
	}

	def cleanupSpec(){
		CSMessageParserManager.config = null
		CSMessageParserManager.parser = null
	}

	def setup(){
		DummyMessageHandler dmh = new DummyMessageHandler()
		dmh.init(config)
		dmh.parser = parser
		
		dmh.addSender(new TestMessageSender())
		dmh.addListener(new TestMessageListener(parser))
				
		arrrm = new AutoRevokeReqRespManager(parser, credManagementPayloadParser, 5000, dmh, "TestSender1","TestListener1")
	}
	
	def "Verify that init sets private fields and registers callback in message handler correctly"(){
		expect:
		arrrm.messageHandler.components["TestListener1"].callbacks.get(DefaultReqRespManager.CALLBACK_ALIAS) == arrrm
		arrrm.timeOut == 5000
		arrrm.messageSenderName == "TestSender1"
		arrrm.messageListenerName == "TestListener1"
		arrrm.messageHandler != null
		arrrm.csMessageParser == parser
		arrrm.credManagementPayloadParser == credManagementPayloadParser
	}	

	def "Test to send a simple get credential request message and expect a get credential response"(){
		setup:
		byte[] request = credManagementPayloadParser.genGetCredentialRequest(TEST_ID, "somedestination", "someorg", "someCredentialSubType", "CN=someIssuerId", "12345678",null,null)
		when:
		CSMessage response = arrrm.sendRequest(TEST_ID, request)
		then:
		assert response != null;
		assert response.getPayload().getAny() instanceof GetCredentialResponse
	}
		

	def "Check that time out expeption is thrown when message takes longer time than set timeout."(){
		setup:
		((DummyMessageHandler) arrrm.messageHandler).waitTime = 10000
		arrrm.timeOut = 200
		byte[] request = credManagementPayloadParser.genGetCredentialRequest(TEST_ID, "somedestination", "someorg", "someCredentialSubType", "CN=someIssuerId", "12345678",null,null)
		when:
		arrrm.sendRequest(TEST_ID, request)
		then:
		thrown(IOException)
		cleanup:
		((DummyMessageHandler) arrrm.messageHandler).waitTime = 100
		arrrm.timeOut = 10000
	}

	def "Check that revoce message is sent for issue token request responses where wait thread has timed out."(){
		setup:
		((DummyMessageHandler) arrrm.messageHandler).waitTime = 1000
		arrrm.timeOut = 200
		byte[] request = credManagementPayloadParser.genIssueTokenCredentialsRequest(TEST_ID, "somedestination", "someorg", createDummyTokenRequest(),null,null,null,null)
		when:
		arrrm.sendRequest(TEST_ID, request)
		then:
		thrown(IOException)
		when:
		
		while(!((DummyMessageHandler) arrrm.messageHandler).revokeMessageRecieved){
			System.out.println("Waiting for revoce message to be sent ...");
			Thread.sleep(1000);
		}
		System.out.println("Waiting sent successfully");
		then:
		assert ((DummyMessageHandler) arrrm.messageHandler).revokeMessageRecieved
		cleanup:
		((DummyMessageHandler) arrrm.messageHandler).waitTime = 100
		arrrm.timeOut = 10000
	}
	


	


	private TokenRequest createDummyTokenRequest(){
		TokenRequest retval = of.createTokenRequest();
		retval.user = "someuser";
		retval.tokenContainer = "SomeTokenContainer"
		retval.tokenType = "SomeTokenType"
		retval.tokenClass = "SomeTokenClass"
		
		CredentialRequest cr = of.createCredentialRequest();
		cr.credentialRequestId = 123
		cr.credentialType = "SomeCredentialType"
		cr.credentialSubType = "SomeCredentialSubType"
		cr.x509RequestType = "SomeX509RequestType"
		cr.credentialRequestData = "12345ABC"
		
		retval.setCredentialRequests(new TokenRequest.CredentialRequests())
		retval.getCredentialRequests().getCredentialRequest().add(cr)

		return retval
	}
	
	class TestMessageSender implements MessageSender{

		@Override
		public String getName() {
			return "TestSender1";
		}

		@Override
		public void sendMessage(String requestId, byte[] message, Map<String,String> attributes)
				throws IOException, MessageProcessingException,
				MessageContentException {
			
		}
		
	}
	
	class TestMessageListener implements MessageListener{
		
		
		
		Map callbacks = [:]
		CSMessageParser parser;

		TestMessageListener(CSMessageParser parser){
		   this.parser = parser
	    }
		
		@Override
		public String getName() {
			return "TestListener1";
		}

		@Override
		public void registerCallback(String alias,
				MessageResponseCallback callback) {
			callbacks[alias] = callback
			
		}

		@Override
		public Set<String> getCallbackAliases() {
			callbacks.keySet()
		}

		@Override
		public void unregisterCallback(String alias) {
			callbacks.remove(alias)
		}

		@Override
		public void responseReceived(byte[] responseMessage, Map<String, String> messageAttributes)
				throws IOException, MessageProcessingException,
				MessageContentException {
			for(MessageResponseCallback c : callbacks.values()){
				c.responseReceived(responseMessage, parser.parseMessage(responseMessage), messageAttributes)
			}
			
		}
		
	}

}
