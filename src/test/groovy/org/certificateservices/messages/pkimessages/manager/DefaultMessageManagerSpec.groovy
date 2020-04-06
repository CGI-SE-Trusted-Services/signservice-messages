package org.certificateservices.messages.pkimessages.manager

import org.certificateservices.messages.pkimessages.DefaultPKIMessageParser
import org.certificateservices.messages.DummyMessageSecurityProvider
import org.certificateservices.messages.MessageException;
import org.certificateservices.messages.pkimessages.jaxb.CredentialRequest
import org.certificateservices.messages.pkimessages.jaxb.ObjectFactory
import org.certificateservices.messages.pkimessages.jaxb.PKIMessage
import org.certificateservices.messages.pkimessages.jaxb.PKIResponse
import org.certificateservices.messages.pkimessages.jaxb.TokenRequest;
import org.certificateservices.messages.utils.MessageGenerateUtils;
import org.certificateservices.messages.pkimessages.manager.DefaultMessageManager;
import org.certificateservices.messages.pkimessages.manager.DummyMessageHandler;
import org.certificateservices.messages.pkimessages.manager.MessageManager;
import org.junit.BeforeClass
import org.junit.Test

import spock.lang.Shared
import spock.lang.Specification

@SuppressWarnings("deprecation")
class DefaultMessageManagerSpec extends Specification{

	@Shared DefaultMessageManager mm = new DefaultMessageManager()
		
	@Shared ObjectFactory of = new ObjectFactory()
	
	@Shared DefaultPKIMessageParser parser = new DefaultPKIMessageParser()
	
	@Shared Properties config
	
	private static final String TEST_ID = "12345678-1234-4444-8000-123456789012"

	def setupSpec(){
        config = new Properties();
		config.setProperty(DefaultPKIMessageParser.SETTING_SOURCEID, "somesourceId");		
		config.setProperty(DefaultMessageManager.SETTING_MESSAGEHANDLER_CLASSPATH, DummyMessageHandler.class.getName());		
		config.setProperty(DummyMessageHandler.SETTING_WAITTIME, "100");
		
		parser.init(new DummyMessageSecurityProvider(), config);
		mm.init(config,parser, "SomeDestination");
	}
	
	
	@Test
	def "Test to send a simple get credential request message and expect a get credential response"(){
		setup:
		byte[] request = parser.genGetCredentialRequest(TEST_ID, "somedestination", "someorg", "someCredentialSubType", "CN=someIssuerId", "12345678",null)
		when:
		PKIMessage response = mm.sendMessage(TEST_ID, request)
		then:
		assert response != null;
		assert response.getPayload().getGetCredentialResponse() != null;
	}
	
	@Test
	def "Test to 100 concurrent request and verify all responses are ok"(){
		final int numberOfConcurrentRequests = 100
		when:
		System.out.println("Generating " + numberOfConcurrentRequests + " concurrent request with a responsetime between 100 and 3100 millis");
		
		for(int i=0;i<numberOfConcurrentRequests;i++){
			String requestId = MessageGenerateUtils.generateRandomUUID();
			byte[] request = parser.genGetCredentialRequest(requestId, "somedestination", "someorg", "someCredentialSubType", "CN=someIssuerId", "12345678",null)
			new Thread(new SendRandomRequest(mm,requestId,request, 100,300)).start()
		}
		
		int lastEntry = 0;
		int numberOfSame = 0;
		
		while(SendRandomRequest.numberOfCompletedRequests < numberOfConcurrentRequests){
			System.out.println("number of completed : " + SendRandomRequest.numberOfCompletedRequests);
			Thread.sleep(1000);		
			
			if(lastEntry == SendRandomRequest.numberOfCompletedRequests){
				numberOfSame++
				if(numberOfSame > 6){
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
	
	@Test
	def "Check that time out expeption is thrown when message takes longer time than set timeout."(){
		setup:
		((DummyMessageHandler) mm.messageHandler).waitTime = 10000
		mm.timeout = 200
		byte[] request = parser.genGetCredentialRequest(TEST_ID, "somedestination", "someorg", "someCredentialSubType", "CN=someIssuerId", "12345678",null)
		when:
		mm.sendMessage(TEST_ID, request)
		then:
		thrown(IOException)
		cleanup:
		((DummyMessageHandler) mm.messageHandler).waitTime = 100
		mm.timeout = 10000
	}
	
	@Test
	def "Check that revoce message is sent for issue token request responses where wait thread has timed out."(){
		setup:
		((DummyMessageHandler) mm.messageHandler).waitTime = 1000
		mm.timeout = 200
		byte[] request = parser.genIssueTokenCredentialsRequest(TEST_ID, "somedestination", "someorg", createDummyTokenRequest(),null)
		when:
		mm.sendMessage(TEST_ID, request)
		then:
		thrown(IOException)
		when:
		
		while(!((DummyMessageHandler) mm.messageHandler).revokeMessageRecieved){
			System.out.println("Waiting for revoce message to be sent ...");
			Thread.sleep(1000);
		}
		System.out.println("Waiting sent successfully");
		then:
		assert ((DummyMessageHandler) mm.messageHandler).revokeMessageRecieved
		cleanup:
		((DummyMessageHandler) mm.messageHandler).waitTime = 100
		mm.timeout = 10000
	}
	

	
	@Test
	def "Check findRequestId returns the correct request id from the message"(){
		when:
		PKIResponse response = of.createPKIResponse();
		response.setInResponseTo(TEST_ID);		
		PKIMessage pkiMessage = parser.genPKIMessage(DefaultPKIMessageParser.PKIMESSAGE_VERSION_1_1,null, "somedest", "someorg", null,response)
		then:
		assert mm.findRequestId(pkiMessage) == TEST_ID
		when:
		response = of.createIssueTokenCredentialsResponse();
		response.setInResponseTo(TEST_ID);
		pkiMessage = parser.genPKIMessage(DefaultPKIMessageParser.PKIMESSAGE_VERSION_1_1,null, "somedest", "someorg", null,response)
		then:
		assert mm.findRequestId(pkiMessage) == TEST_ID
		when:
		response = of.createGetCredentialResponse();
		response.setInResponseTo(TEST_ID);
		pkiMessage = parser.genPKIMessage(DefaultPKIMessageParser.PKIMESSAGE_VERSION_1_1,null, "somedest", "someorg", null,response)
		then:
		assert mm.findRequestId(pkiMessage) == TEST_ID
		when:
		response = of.createIsIssuerResponse();
		response.setInResponseTo(TEST_ID);
		pkiMessage = parser.genPKIMessage(DefaultPKIMessageParser.PKIMESSAGE_VERSION_1_1,null, "somedest", "someorg", null,response)
		then:
		assert mm.findRequestId(pkiMessage) == TEST_ID
		when:
		pkiMessage = parser.genPKIMessage(DefaultPKIMessageParser.PKIMESSAGE_VERSION_1_1,null, "somedest", "someorg", null,of.createIsIssuerRequest())
		then:
		assert mm.findRequestId(pkiMessage) == null


	}
	

	@Test
	def "Check getTimeOutInMillis verifies the responses properly"(){
		when:
		Properties config = new Properties();
		config.setProperty(DefaultMessageManager.SETTING_MESSAGE_TIMEOUT_MILLIS, "123")
		then:
		assert mm.getTimeOutInMillis(config) == 123
		when:
		config.setProperty(DefaultMessageManager.SETTING_MESSAGE_TIMEOUT_MILLIS, "abc")
		mm.getTimeOutInMillis(config)
		then:
		thrown (MessageException)
		when:
		config = new Properties();		
		then:
		assert mm.getTimeOutInMillis(config) == 60000L

	}
	
	
	
	private class SendRandomRequest implements Runnable{
	
		private static Random random = new Random();
			
		public static int numberOfCompletedRequests = 0;
		
		private String requestId
		private byte[] requestData
		private MessageManager mm
		
		int minTime
		int randomTime
		
		private SendRandomRequest(MessageManager mm, String requestId, byte[] requestData, int minTime, int maxTime){
			this.requestId = requestId
			this.requestData = requestData;
			this.minTime = minTime;
			this.randomTime =  maxTime- minTime;
			this.mm = mm;
		}

		@Override
		public void run() {
			long waitTime = minTime;
			if(randomTime > 0){
				waitTime += random.nextInt(randomTime)
			}
			Thread.sleep(waitTime);
			
			assert mm.sendMessage(requestId, requestData)  != null;	
			
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

}
