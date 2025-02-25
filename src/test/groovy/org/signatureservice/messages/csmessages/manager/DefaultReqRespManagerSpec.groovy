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
import org.signatureservice.messages.csmessages.jaxb.CSResponse;
import org.signatureservice.messages.csmessages.jaxb.CredentialRequest;
import org.signatureservice.messages.csmessages.jaxb.ObjectFactory;
import org.signatureservice.messages.csmessages.jaxb.TokenRequest;
import org.signatureservice.messages.utils.MessageGenerateUtils;
import spock.lang.Shared
import spock.lang.Specification


class DefaultReqRespManagerSpec extends Specification{

	@Shared DefaultReqRespManager drrm;
		
	@Shared ObjectFactory of = new ObjectFactory()
	@Shared org.signatureservice.messages.credmanagement.jaxb.ObjectFactory credOf = new org.signatureservice.messages.credmanagement.jaxb.ObjectFactory()
	
	@Shared DefaultCSMessageParser parser = new DefaultCSMessageParser()
	@Shared CredManagementPayloadParser credManagementPayloadParser;
	
	@Shared Properties config
	
	private static final String TEST_ID = "12345678-1234-4444-8000-123456789012"
	
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
				
		drrm = new DefaultReqRespManager(5000, dmh, "TestSender1","TestListener1")
	}
	
	def "Verify that init sets private fields and registers callback in message handler correctly"(){
		expect:
		drrm.messageHandler.components["TestListener1"].callbacks.get(DefaultReqRespManager.CALLBACK_ALIAS) == drrm
		drrm.timeOut == 5000
		drrm.messageSenderName == "TestSender1"
		drrm.messageListenerName == "TestListener1"
		drrm.messageHandler != null
	}	

	def "Test to send a simple get credential request message and expect a get credential response"(){
		setup:
		byte[] request = credManagementPayloadParser.genGetCredentialRequest(TEST_ID, "somedestination", "someorg", "someCredentialSubType", "CN=someIssuerId", "12345678",null,null)
		when:
		CSMessage response = drrm.sendRequest(TEST_ID, request)
		then:
		assert response != null;
		assert response.getPayload().getAny() instanceof GetCredentialResponse

	}
	

	def "Test to 20 concurrent request and verify all responses are ok"(){
		final int numberOfConcurrentRequests = 20
		when:
		System.out.println("Generating " + numberOfConcurrentRequests + " concurrent request with a responsetime between 100 and 3100 millis");
		
		for(int i=0;i<numberOfConcurrentRequests;i++){
			String requestId = MessageGenerateUtils.generateRandomUUID();
			byte[] request = credManagementPayloadParser.genGetCredentialRequest(requestId, "somedestination", "someorg", "someCredentialSubType", "CN=someIssuerId", "12345678",null,null)
			new Thread(new SendRandomRequest(drrm,requestId,request, 100,300)).start()
		}
		
		int lastEntry = 0;
		int numberOfSame = 0;
		
		while(SendRandomRequest.numberOfCompletedRequests < numberOfConcurrentRequests){
			System.out.println("number of completed : " + SendRandomRequest.numberOfCompletedRequests);
			Thread.sleep(1000);
			if(lastEntry == SendRandomRequest.numberOfCompletedRequests){
				numberOfSame++
				if(numberOfSame > 20){
					assert false
				}
			}else{		
			  lastEntry = SendRandomRequest.numberOfCompletedRequests
			  numberOfSame = 0
			}
		}
		System.out.println("number of completed : " + SendRandomRequest.numberOfCompletedRequests);
		
		then:
		assert true;
	}
	

	def "Check that time out exception is thrown when message takes longer time than set timeout."(){
		setup:
		((DummyMessageHandler) drrm.messageHandler).waitTime = 10000
		drrm.timeOut = 200
		byte[] request = credManagementPayloadParser.genGetCredentialRequest(TEST_ID, "somedestination", "someorg", "someCredentialSubType", "CN=someIssuerId", "12345678",null,null)
		when:
		drrm.sendRequest(TEST_ID, request)
		then:
		thrown(IOException)
		cleanup:
		((DummyMessageHandler) drrm.messageHandler).waitTime = 100
		drrm.timeOut = 10000
	}


	def "Check findRequestId returns the correct request id from the message"(){
		when:
		CSResponse response = of.createCSResponse();
		response.setInResponseTo(TEST_ID);		
		CSMessage csMessage = parser.genCSMessage(DefaultCSMessageParser.CSMESSAGE_VERSION_2_0,"2.0",null, null, "somedest", "someorg", null,response,null)
		then:
		assert drrm.findRequestId(csMessage) == TEST_ID
		when:
		response = credOf.createIssueTokenCredentialsResponse();
		response.setInResponseTo(TEST_ID);
		csMessage = parser.genCSMessage(DefaultCSMessageParser.CSMESSAGE_VERSION_2_0,"2.0",null,null, "somedest", "someorg", null,response,null)
		then:
		assert drrm.findRequestId(csMessage) == TEST_ID
		when:
		response = credOf.createGetCredentialResponse();
		response.setInResponseTo(TEST_ID);
		csMessage = parser.genCSMessage(DefaultCSMessageParser.CSMESSAGE_VERSION_2_0,"2.0",null,null, "somedest", "someorg", null,response,null)
		then:
		assert drrm.findRequestId(csMessage) == TEST_ID
		when:
		response = credOf.createIsIssuerResponse();
		response.setInResponseTo(TEST_ID);
		csMessage = parser.genCSMessage(DefaultCSMessageParser.CSMESSAGE_VERSION_2_0,"2.0",null,null, "somedest", "someorg", null,response,null)
		then:
		assert drrm.findRequestId(csMessage) == TEST_ID
		when:
		csMessage = parser.genCSMessage(DefaultCSMessageParser.CSMESSAGE_VERSION_2_0,"2.0",null,null, "somedest", "someorg", null,credOf.createIsIssuerRequest(),null)
		then:
		assert drrm.findRequestId(csMessage) == null


	}
	
	
	private class SendRandomRequest implements Runnable{
	
		private static Random random = new Random();
			
		public static int numberOfCompletedRequests = 0;
		
		private String requestId
		private byte[] requestData
		private ReqRespManager rrm
		
		int minTime
		int randomTime
		
		private SendRandomRequest(ReqRespManager rrm, String requestId, byte[] requestData, int minTime, int maxTime){
			this.requestId = requestId
			this.requestData = requestData;
			this.minTime = minTime;
			this.randomTime =  maxTime- minTime;
			this.rrm = rrm;
		}

		@Override
		public void run() {
			long waitTime = minTime;
			if(randomTime > 0){
				waitTime += random.nextInt(randomTime)
			}
			Thread.sleep(waitTime);
			
			def result = rrm.sendRequest(requestId, requestData)
			assert result != null;	
			
			synchronized (numberOfCompletedRequests) {
				numberOfCompletedRequests++;
			}		
		}
		
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
		public void sendMessage(String requestId, byte[] message, Map<String,String> messageAttributes)
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
