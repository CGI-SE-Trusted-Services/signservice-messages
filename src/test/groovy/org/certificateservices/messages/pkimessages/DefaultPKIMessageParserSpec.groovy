package org.certificateservices.messages.pkimessages

import groovy.xml.XmlSlurper
import groovy.xml.slurpersupport.GPathResult

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import javax.xml.crypto.dsig.XMLSignature
import javax.xml.crypto.dsig.XMLSignatureFactory
import javax.xml.crypto.dsig.dom.DOMValidateContext
import javax.xml.datatype.DatatypeFactory;
import javax.xml.parsers.DocumentBuilder
import javax.xml.parsers.DocumentBuilderFactory;

import org.certificateservices.messages.pkimessages.jaxb.Attribute
import org.certificateservices.messages.pkimessages.jaxb.ChangeCredentialStatusRequest
import org.certificateservices.messages.pkimessages.jaxb.Credential;
import org.certificateservices.messages.pkimessages.jaxb.CredentialRequest;
import org.certificateservices.messages.pkimessages.jaxb.CredentialStatusList
import org.certificateservices.messages.pkimessages.jaxb.FetchHardTokenDataRequest
import org.certificateservices.messages.pkimessages.jaxb.GetCredentialRequest
import org.certificateservices.messages.pkimessages.jaxb.GetCredentialStatusListRequest
import org.certificateservices.messages.pkimessages.jaxb.GetIssuerCredentialsRequest
import org.certificateservices.messages.pkimessages.jaxb.IsIssuerRequest;
import org.certificateservices.messages.pkimessages.jaxb.IsIssuerResponse
import org.certificateservices.messages.pkimessages.jaxb.IssueCredentialStatusListRequest
import org.certificateservices.messages.pkimessages.jaxb.IssueTokenCredentialsRequest;
import org.certificateservices.messages.pkimessages.jaxb.ObjectFactory;
import org.certificateservices.messages.pkimessages.jaxb.PKIMessage;
import org.certificateservices.messages.pkimessages.jaxb.RemoveCredentialRequest
import org.certificateservices.messages.pkimessages.jaxb.RequestStatus;
import org.certificateservices.messages.pkimessages.jaxb.StoreHardTokenDataRequest
import org.certificateservices.messages.pkimessages.jaxb.TokenRequest
import org.certificateservices.messages.DummyMessageSecurityProvider;
import org.certificateservices.messages.MessageException;
import org.w3c.dom.Document
import org.w3c.dom.Element
import org.xml.sax.InputSource

import spock.lang.Specification


@SuppressWarnings("deprecation")
class DefaultPKIMessageParserSpec extends Specification {
	
	static DefaultPKIMessageParser mp = new DefaultPKIMessageParser();
	static ObjectFactory of = new ObjectFactory();
	static DummyMessageSecurityProvider secprov = new DummyMessageSecurityProvider();
	
	static final String TEST_ID = "12345678-1234-4444-8000-123456789012"

	
	def setupSpec(){
		
		Properties config = new Properties();
		config.setProperty(DefaultPKIMessageParser.SETTING_SOURCEID, "SOMESOURCEID");
		mp.init(secprov, config)		
	}


	def TimeZone currentTimeZone;
	def setup() {
		currentTimeZone = TimeZone.getDefault()
		TimeZone.setDefault(TimeZone.getTimeZone("Europe/Stockholm"))
	}

	def cleanup(){
		TimeZone.setDefault(currentTimeZone)
	}

	def "Verify that the init method creates all marshallers and unmarshallers"(){
		when:
		for(String version : DefaultPKIMessageParser.SUPPORTED_PKIMESSAGE_VERSIONS){
		  assert mp.pkixMessageMarshallers.get(version) != null
		  assert mp.pkixMessageUnmarshallers.get(version) != null
		}
		then:
		assert true
	}
	
	def "Verify verifyPKIMessageVersion checks the version agains supported versions"(){
		when:
		for(String version : DefaultPKIMessageParser.SUPPORTED_PKIMESSAGE_VERSIONS){
			mp.verifyPKIMessageVersion(version) 
		  }
		then:
		assert true
		when:
		mp.verifyPKIMessageVersion("999")
		then:
		thrown(IllegalArgumentException)
		
	}
	
	def "Test that unmarshaller validates against the schema"(){
		when:
		  mp.parseMessage(TestMessages.faultyRequestAgainstXSD.getBytes())
		then:
		thrown(IllegalArgumentException)
	}
	
	def "Test that marshaller validates against the schema"(){
		when:
		   mp.genIsIssuerRequest(null, null, null, null,null);		   
		then:
		  thrown(MessageException)
	}
	
	def "Test that PKI Message parsing against schema and validates signatures"(){
		setup:
		  secprov.resetCounters()
		when:
		   PKIMessage message = mp.parseMessage(TestMessages.testMessage.getBytes("UTF-8"))
		then:
		   assert message != null
		   assert secprov.getValidCallDone()
		   assert secprov.getOrganisationCalled() == "SomeOrg"
		   assert message.payload.issueTokenCredentialsRequest != null
	}
	
	def "Test that PKI Message parsing checks supported versions"(){
		when:
		   PKIMessage message = mp.parseMessage(TestMessages.testMessageWithInvalidVersion.getBytes("UTF-8"))
		then:
		   thrown(IllegalArgumentException)
	}
	
	def "Test that parsing PKI Message with invalid signature throws IllegalArgumentException"(){
		when:
		   PKIMessage message = mp.parseMessage(TestMessages.testMessageWithInvalidSignature.getBytes("UTF-8"))
		then:
		   thrown(IllegalArgumentException)

	}
	

	def "Test that unsigned basic PKI message header is populated correctly"(){
		setup:
		  mp.signMessages = false
		when:
		  PKIMessage m = mp.genPKIMessage("1.0","123","SOMEDESTINATION","SomeOrg", null, of.createIsIssuerRequest())
		then:
		  assert m.version == "1.0"
		  assert m.id == "123"
		  assert m.sourceId == "SOMESOURCEID"
		  assert m.destinationId == "SOMEDESTINATION"
		  assert m.organisation == "SomeOrg"
		  assert m.name == "IsIssuerRequest"
		  assert m.payload != null
		  assert m.originator == null
		  assert m.signature == null
		when:
		  m = mp.genPKIMessage("1.0","123","SOMEDESTINATION","SomeOrg", createOriginatorCredential(), of.createIsIssuerRequest())
		then:
		  assert m.version == "1.0"
		  assert m.id == "123"
		  assert m.sourceId == "SOMESOURCEID"
		  assert m.destinationId == "SOMEDESTINATION"
		  assert m.organisation == "SomeOrg"
		  assert m.name == "IsIssuerRequest"
		  assert m.payload != null
		  assert m.originator.credential.uniqueId == "SomeOriginatorUniqueId"
		  assert m.signature == null
		cleanup:
		  mp.signMessages = true
	}
	

	def "Test that signed PKIResponse message is populated correctly and signature is valid"(){
		when: "  with default destinationId"
          PKIMessageResponseData result = mp.genPKIResponse("SomeEntity", TestMessages.testMessageWithResponse.getBytes(), RequestStatus.ERROR, "SomeMessage",null)   
		  String message = new String(result.responseData,"UTF-8")
		  def xmlMessage = new XmlSlurper().parseText(message)
		then:		  
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SOMEREQUESTER", "SomeOrg" ,"FailureResponse")
		  verifySignature(message)
		  assert result.relatedEndEntity == "SomeEntity"
		  assert result.messageName == "FailureResponse"
		  assert result.messageId == xmlMessage.@ID.toString()
		  assert result.isForwardableResponse == false
		  assert result.destination == xmlMessage.destinationId.toString()
		  assert xmlMessage.payload.failureResponse.inResponseTo == "59fa9386-c549-4f90-9e0e-b369c15d67f6"
		  assert xmlMessage.payload.failureResponse.status == "ERROR"
		  assert xmlMessage.payload.failureResponse.failureMessage == "SomeMessage"		 
		when: "  with custom destinationId"
		  result= mp.genPKIResponse("SomeEntity",TestMessages.testMessageWithVersion1_1.getBytes(), RequestStatus.ERROR, "SomeMessage","SOMEOTHERDESTINATION",createOriginatorCredential())
		  message = new String(result.responseData,"UTF-8")
		  xmlMessage = new XmlSlurper().parseText(message)
		then:
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SOMEOTHERDESTINATION", "SomeOrg", "FailureResponse")
		  verifySignature(message)
		  assert result.relatedEndEntity == "SomeEntity"
		  assert result.messageName == "FailureResponse"
		  assert xmlMessage.payload.failureResponse.inResponseTo == "59fa9386-c549-4f90-9e0e-b369c15d67f6"
		  assert xmlMessage.payload.failureResponse.status == "ERROR"
		  assert xmlMessage.payload.failureResponse.failureMessage == "SomeMessage"
		
	}
	
	def "Test that getSigningCertificate fetches certificate properly from signed request"(){
		setup:
		byte[] request = mp.genIsIssuerRequest(TEST_ID,"SomeDestination", "SomeOrg", "SomeIssuer",null);
		when:
		X509Certificate cert = mp.getSigningCertificate(request);
		then:
		assert cert
		assert cert.getIssuerDN().toString() == "O=Demo Customer1 AT, CN=Demo Customer1 AT ServerCA"
	}
	
	def "Test that getSigningCertificate throws IllegalArgumentException if no certificate was found."(){
		when:
		X509Certificate cert = mp.getSigningCertificate(TestMessages.testMessageWithNoCert.getBytes());
		then:
		thrown(IllegalArgumentException)
	}
	
	def "Test that getSigningCertificate returns null if requireSignature is false."(){
		setup:
		mp.requireSignature = false
		when:
		X509Certificate cert = mp.getSigningCertificate(TestMessages.testMessageWithNoCert.getBytes());
		then:
		assert cert == null
		cleanup:
		mp.requireSignature = true
	}
	

	def "Test that signed IssueTokenCredentialsRequest message is populated correctly and signature is valid"(){
		setup:
		  TokenRequest tokenRequest = createDummyTokenRequest()		  
		when: 
		  byte[] responseData = mp.genIssueTokenCredentialsRequest(TEST_ID, "SomeDestinationId", "SomeOrg", tokenRequest, createOriginatorCredential())
		  String message = new String(responseData,"UTF-8")
		  def xmlMessage = new XmlSlurper().parseText(message)
		then:
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SomeDestinationId", "SomeOrg","IssueTokenCredentialsRequest")
		  verifySignature(message)
		  assert xmlMessage.@ID == TEST_ID
		  assert xmlMessage.originator.credential.uniqueId == "SomeOriginatorUniqueId"
		  assert xmlMessage.payload.issueTokenCredentialsRequest.tokenRequest.credentialRequests[0].credentialRequest.credentialRequestId == 123
		  assert xmlMessage.payload.issueTokenCredentialsRequest.tokenRequest.credentialRequests[0].credentialRequest.credentialType == "SomeCredentialType"
		  assert xmlMessage.payload.issueTokenCredentialsRequest.tokenRequest.credentialRequests[0].credentialRequest.credentialSubType == "SomeCredentialSubType"
		  assert xmlMessage.payload.issueTokenCredentialsRequest.tokenRequest.credentialRequests[0].credentialRequest.x509RequestType == "SomeX509RequestType"
		  assert xmlMessage.payload.issueTokenCredentialsRequest.tokenRequest.credentialRequests[0].credentialRequest.credentialRequestData == "MTIzNDVBQkM="		  
		  assert xmlMessage.payload.issueTokenCredentialsRequest.tokenRequest.user == "someuser"
		  assert xmlMessage.payload.issueTokenCredentialsRequest.tokenRequest.tokenContainer == "SomeTokenContainer"
		  assert xmlMessage.payload.issueTokenCredentialsRequest.tokenRequest.tokenType == "SomeTokenType"
		  assert xmlMessage.payload.issueTokenCredentialsRequest.tokenRequest.tokenClass == "SomeTokenClass"
	}
	

	def "Test that signed IssueTokenCredentialsResponse message is populated correctly and signature is valid"(){
		setup:
		  TokenRequest tokenRequest = createDummyTokenRequest()
		  List<Credential> credentials = createDummyCredentials()
		  IssueTokenCredentialsRequest payload = of.createIssueTokenCredentialsRequest();
		  payload.setTokenRequest(tokenRequest);
		  PKIMessage request = mp.genPKIMessage("1.1", null,"SOMESOURCEID", "SomeOrg", createOriginatorCredential(), payload);
		  request.setSourceId("SOMEREQUESTER")
		when:
		  PKIMessageResponseData result = mp.genIssueTokenCredentialsResponse("SomeEntity", request, credentials, null)
		  String message = new String(result.responseData,"UTF-8")		  
		  def xmlMessage = new XmlSlurper().parseText(message)
		then:
		  assert result.isForwardableResponse == true
		  assert result.relatedEndEntity == "SomeEntity"
		  assert result.messageName == "IssueTokenCredentialsResponse"
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SOMEREQUESTER", "SomeOrg", "IssueTokenCredentialsResponse")
		  verifySignature(message)
		  verifyResponseHeader(xmlMessage.payload.issueTokenCredentialsResponse, request)
		  assert xmlMessage.originator.credential.uniqueId == "SomeOriginatorUniqueId"
		  assert xmlMessage.payload.issueTokenCredentialsResponse.tokenRequest.credentialRequests[0].credentialRequest.credentialRequestId == 123
		  assert xmlMessage.payload.issueTokenCredentialsResponse.tokenRequest.credentialRequests[0].credentialRequest.credentialType == "SomeCredentialType"
		  assert xmlMessage.payload.issueTokenCredentialsResponse.tokenRequest.credentialRequests[0].credentialRequest.credentialSubType == "SomeCredentialSubType"
		  assert xmlMessage.payload.issueTokenCredentialsResponse.tokenRequest.credentialRequests[0].credentialRequest.x509RequestType == "SomeX509RequestType"
		  assert xmlMessage.payload.issueTokenCredentialsResponse.tokenRequest.credentialRequests[0].credentialRequest.credentialRequestData == "MTIzNDVBQkM="		  
		  assert xmlMessage.payload.issueTokenCredentialsResponse.tokenRequest.user == "someuser"
		  assert xmlMessage.payload.issueTokenCredentialsResponse.tokenRequest.tokenContainer == "SomeTokenContainer"
		  assert xmlMessage.payload.issueTokenCredentialsResponse.tokenRequest.tokenType == "SomeTokenType"
		  assert xmlMessage.payload.issueTokenCredentialsResponse.tokenRequest.tokenClass == "SomeTokenClass"
		  assert xmlMessage.payload.issueTokenCredentialsResponse.credentials.credential[0].credentialRequestId == 123
		  assert xmlMessage.payload.issueTokenCredentialsResponse.credentials.credential[0].uniqueId == "SomeUniqueId"
		  assert xmlMessage.payload.issueTokenCredentialsResponse.credentials.credential[0].displayName == "SomeDisplayName"
		  assert xmlMessage.payload.issueTokenCredentialsResponse.credentials.credential[0].serialNumber == "SomeSerialNumber"
		  assert xmlMessage.payload.issueTokenCredentialsResponse.credentials.credential[0].issuerId == "SomeIssuerId"
		  assert xmlMessage.payload.issueTokenCredentialsResponse.credentials.credential[0].status == 100
		  assert xmlMessage.payload.issueTokenCredentialsResponse.credentials.credential[0].credentialType == "SomeCredentialType"
		  assert xmlMessage.payload.issueTokenCredentialsResponse.credentials.credential[0].credentialSubType == "SomeCredentialSubType"
		  assert xmlMessage.payload.issueTokenCredentialsResponse.credentials.credential[0].attributes.attribute[0].key == "someattrkey"
		  assert xmlMessage.payload.issueTokenCredentialsResponse.credentials.credential[0].attributes.attribute[0].value == "someattrvalue"
		  assert xmlMessage.payload.issueTokenCredentialsResponse.credentials.credential[0].usages[0].usage == "someusage"
		  assert xmlMessage.payload.issueTokenCredentialsResponse.credentials.credential[0].credentialData == "MTIzNDVBQkNFRg=="
		  assert xmlMessage.payload.issueTokenCredentialsResponse.credentials.credential[0].issueDate == "1970-01-01T01:00:01.234+01:00"
		  assert xmlMessage.payload.issueTokenCredentialsResponse.credentials.credential[0].expireDate == "1970-01-01T01:00:02.234+01:00"
		  assert xmlMessage.payload.issueTokenCredentialsResponse.credentials.credential[0].validFromDate == "1970-01-01T01:00:03.234+01:00"
		  
	}
	

	def "Test that signed IssueTokenCredentialsResponse message is populated correctly with revoked credentials"(){
		setup:
		  TokenRequest tokenRequest = createDummyTokenRequest()
		  List<Credential> credentials = createDummyCredentials()
		  List<Credential> revokedCredentials = createDummyCredentials(160)		  		  
		  IssueTokenCredentialsRequest payload = of.createIssueTokenCredentialsRequest();
		  payload.setTokenRequest(tokenRequest);
		  PKIMessage request = mp.genPKIMessage(DefaultPKIMessageParser.PKIMESSAGE_VERSION_1_1,null,"SOMESOURCEID", "SomeOrg", createOriginatorCredential(), payload);
		  request.setSourceId("SOMEREQUESTER")
		when:
		  PKIMessageResponseData result = mp.genIssueTokenCredentialsResponse("SomeEntity", request, credentials, revokedCredentials)
		  String message = new String(result.responseData,"UTF-8")
		  def xmlMessage = new XmlSlurper().parseText(message)
		then:
		  assert result.relatedEndEntity == "SomeEntity"
		  assert result.messageName == "IssueTokenCredentialsResponse"
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SOMEREQUESTER", "SomeOrg", "IssueTokenCredentialsResponse")
		  verifySignature(message)
		  verifyResponseHeader(xmlMessage.payload.issueTokenCredentialsResponse, request)
		  assert xmlMessage.originator.credential.uniqueId == "SomeOriginatorUniqueId"
		  assert xmlMessage.payload.issueTokenCredentialsResponse.tokenRequest.credentialRequests[0].credentialRequest.credentialRequestId == 123
		  assert xmlMessage.payload.issueTokenCredentialsResponse.tokenRequest.user == "someuser"
		  assert xmlMessage.payload.issueTokenCredentialsResponse.credentials.credential[0].status == 100
		  assert xmlMessage.payload.issueTokenCredentialsResponse.revokedCredentials.credential[0].status == 160

		  
	}
	

	def "Test that signed ChangeCredentialStatusRequest message is populated correctly and signature is valid"(){
		when: 
		  byte[] responseData = mp.genChangeCredentialStatusRequest(TEST_ID, "SomeDestinationId", "SomeOrg", "SomeIssuerId", "SomeSerialNumber", 12, "SomeReasonInfo", createOriginatorCredential())		
		  String message = new String(responseData,"UTF-8")		 
		  def xmlMessage = new XmlSlurper().parseText(message)
		then:
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SomeDestinationId", "SomeOrg", "ChangeCredentialStatusRequest")
		  verifySignature(message)	
		  assert xmlMessage.@ID == TEST_ID
		  assert xmlMessage.originator.credential.uniqueId == "SomeOriginatorUniqueId"
		  assert xmlMessage.payload.changeCredentialStatusRequest.issuerId == "SomeIssuerId"
		  assert xmlMessage.payload.changeCredentialStatusRequest.serialNumber == "SomeSerialNumber"
		  assert xmlMessage.payload.changeCredentialStatusRequest.newCredentialStatus == "12"
		  assert xmlMessage.payload.changeCredentialStatusRequest.reasonInformation == "SomeReasonInfo"
		  
	}
	

	def "Test that signed ChangeCredentialStatusResponse message is populated correctly and signature is valid"(){
		setup:
		  ChangeCredentialStatusRequest payload = of.createChangeCredentialStatusRequest();		  
		  PKIMessage request = mp.genPKIMessage(DefaultPKIMessageParser.PKIMESSAGE_VERSION_1_1,null, "SOMESOURCEID", "SomeOrg", createOriginatorCredential(),payload);
		  request.setSourceId("SOMEREQUESTER")		  
		when:
		  PKIMessageResponseData result = mp.genChangeCredentialStatusResponse("SomeEntity",request, "SomeIssuerId", "SomeSerialNumber", 12, "SomeReasonInfo",new Date(1L))
		  String message = new String(result.responseData,"UTF-8")
		  def xmlMessage = new XmlSlurper().parseText(message)
		 // println message
		then:
		  assert result.isForwardableResponse == true
		  assert result.relatedEndEntity == "SomeEntity"
		  assert result.messageName == "ChangeCredentialStatusResponse"
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SOMEREQUESTER", "SomeOrg", "ChangeCredentialStatusResponse")
		  verifySignature(message)
		  verifyResponseHeader(xmlMessage.payload.changeCredentialStatusResponse, request)
		  assert xmlMessage.originator.credential.uniqueId == "SomeOriginatorUniqueId"
		  assert xmlMessage.payload.changeCredentialStatusResponse.issuerId == "SomeIssuerId"
		  assert xmlMessage.payload.changeCredentialStatusResponse.serialNumber == "SomeSerialNumber"
		  assert xmlMessage.payload.changeCredentialStatusResponse.credentialStatus == "12"
		  assert xmlMessage.payload.changeCredentialStatusResponse.reasonInformation == "SomeReasonInfo"
		  assert xmlMessage.payload.changeCredentialStatusResponse.revocationDate.toString().startsWith("1970")		  
	}
	

	def "Test that signed GetCredentialRequest message is populated correctly and signature is valid"(){
		when:
		  byte[] responseData = mp.genGetCredentialRequest(TEST_ID,"SomeDestinationId", "SomeOrg","SomeCredentialSubType","SomeIssuerId", "SomeSerialNumber", createOriginatorCredential())
		  String message = new String(responseData,"UTF-8")
		  def xmlMessage = new XmlSlurper().parseText(message)
		then:
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SomeDestinationId",  "SomeOrg", "GetCredentialRequest")
		  verifySignature(message)
		  assert xmlMessage.@ID == TEST_ID
		  assert xmlMessage.originator.credential.uniqueId == "SomeOriginatorUniqueId"
		  assert xmlMessage.payload.getCredentialRequest.credentialSubType == "SomeCredentialSubType"
		  assert xmlMessage.payload.getCredentialRequest.issuerId == "SomeIssuerId"
		  assert xmlMessage.payload.getCredentialRequest.serialNumber == "SomeSerialNumber"		  
	}
	

	def "Test that signed GetCredentialResponse message is populated correctly and signature is valid"(){
		setup:
		  GetCredentialRequest payload = of.createGetCredentialRequest();
		  PKIMessage request = mp.genPKIMessage(DefaultPKIMessageParser.PKIMESSAGE_VERSION_1_1,null, "SOMESOURCEID","SomeOrg", createOriginatorCredential(), payload);
		  request.setSourceId("SOMEREQUESTER")
		when:
		  PKIMessageResponseData result = mp.genGetCredentialResponse("SomeEntity",request, createDummyCredentials()[0])
		  String message = new String(result.responseData,"UTF-8")
		  def xmlMessage = new XmlSlurper().parseText(message)
		then:
		  assert result.isForwardableResponse == false
		  assert result.relatedEndEntity == "SomeEntity"
		  assert result.messageName == "GetCredentialResponse"
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SOMEREQUESTER", "SomeOrg","GetCredentialResponse")
		  verifySignature(message)
		  verifyResponseHeader(xmlMessage.payload.getCredentialResponse, request)
		  assert xmlMessage.originator.credential.uniqueId == "SomeOriginatorUniqueId"
		  assert xmlMessage.payload.getCredentialResponse.credential.credentialRequestId == 123
		  assert xmlMessage.payload.getCredentialResponse.credential.uniqueId == "SomeUniqueId"
		  assert xmlMessage.payload.getCredentialResponse.credential.displayName == "SomeDisplayName"
		  assert xmlMessage.payload.getCredentialResponse.credential.serialNumber == "SomeSerialNumber"
		  assert xmlMessage.payload.getCredentialResponse.credential.issuerId == "SomeIssuerId"
		  assert xmlMessage.payload.getCredentialResponse.credential.status == 100
		  assert xmlMessage.payload.getCredentialResponse.credential.credentialType == "SomeCredentialType"
		  assert xmlMessage.payload.getCredentialResponse.credential.credentialSubType == "SomeCredentialSubType"
		  assert xmlMessage.payload.getCredentialResponse.credential.attributes.attribute[0].key == "someattrkey"
		  assert xmlMessage.payload.getCredentialResponse.credential.attributes.attribute[0].value == "someattrvalue"
		  assert xmlMessage.payload.getCredentialResponse.credential.usages[0].usage == "someusage"
		  assert xmlMessage.payload.getCredentialResponse.credential.credentialData == "MTIzNDVBQkNFRg=="
		  assert xmlMessage.payload.getCredentialResponse.credential.issueDate == "1970-01-01T01:00:01.234+01:00"
		  assert xmlMessage.payload.getCredentialResponse.credential.expireDate == "1970-01-01T01:00:02.234+01:00"
		  assert xmlMessage.payload.getCredentialResponse.credential.validFromDate == "1970-01-01T01:00:03.234+01:00"
	}
	

	def "Test that signed GetCredentialStatusListRequest message is populated correctly and signature is valid"(){
		when:
		  byte[] responseData = mp.genGetCredentialStatusListRequest(TEST_ID, "SomeDestinationId","SomeOrg", "SomeIssuerId", 16L, "SomeCredentialStatusListType", createOriginatorCredential())
		  String message = new String(responseData,"UTF-8")
		  def xmlMessage = new XmlSlurper().parseText(message)
		then:
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SomeDestinationId", "SomeOrg","GetCredentialStatusListRequest")
		  verifySignature(message)
		  assert xmlMessage.@ID == TEST_ID
		  assert xmlMessage.originator.credential.uniqueId == "SomeOriginatorUniqueId"
		  assert xmlMessage.payload.getCredentialStatusListRequest.issuerId == "SomeIssuerId"
		  assert xmlMessage.payload.getCredentialStatusListRequest.serialNumber == "16"
		  assert xmlMessage.payload.getCredentialStatusListRequest.credentialStatusListType == "SomeCredentialStatusListType"
	}

	def "Test that signed GetCredentialStatusListResponse message is populated correctly and signature is valid"(){
		setup:
		  GetCredentialStatusListRequest payload = of.createGetCredentialStatusListRequest();
		  PKIMessage request = mp.genPKIMessage(DefaultPKIMessageParser.PKIMESSAGE_VERSION_1_1,null, "SOMESOURCEID", "SomeOrg", createOriginatorCredential(),payload);
		  request.setSourceId("SOMEREQUESTER")
		when:
		  PKIMessageResponseData result = mp.genGetCredentialStatusListResponse("SomeEntity", request, createDummyCredentialStatusList())
		  String message = new String(result.responseData,"UTF-8")		  
		  def xmlMessage = new XmlSlurper().parseText(message)
		then:
		  assert result.relatedEndEntity == "SomeEntity"
		  assert result.messageName == "GetCredentialStatusListResponse"
		  assert result.isForwardableResponse == false
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SOMEREQUESTER", "SomeOrg","GetCredentialStatusListResponse")
		  verifySignature(message)
		  verifyResponseHeader(xmlMessage.payload.getCredentialStatusListResponse, request)
		  assert xmlMessage.originator.credential.uniqueId == "SomeOriginatorUniqueId"
		  assert xmlMessage.payload.getCredentialStatusListResponse.credentialStatusList.issuerId == "SomeIssuerId"
		  assert xmlMessage.payload.getCredentialStatusListResponse.credentialStatusList.credentialStatusListType == "SomeCredentialStatusListType"
		  assert xmlMessage.payload.getCredentialStatusListResponse.credentialStatusList.credentialType == "SomeCredentialType"
		  assert xmlMessage.payload.getCredentialStatusListResponse.credentialStatusList.serialNumber == "16"
		  assert xmlMessage.payload.getCredentialStatusListResponse.credentialStatusList.listData == "MTIzNDVBQkNFRg=="
		  assert xmlMessage.payload.getCredentialStatusListResponse.credentialStatusList.description == "SomeDescription"
		  assert xmlMessage.payload.getCredentialStatusListResponse.credentialStatusList.issueDate == "1970-01-01T01:00:01.235+01:00"
		  assert xmlMessage.payload.getCredentialStatusListResponse.credentialStatusList.expireDate == "1970-01-01T01:00:01.234+01:00"
		  assert xmlMessage.payload.getCredentialStatusListResponse.credentialStatusList.validFromDate == "1970-01-01T01:00:01.236+01:00"		  		  
	}
	def "Test that signed GetIssuerCredentialsRequest message is populated correctly and signature is valid"(){
		when:
		  byte[] responseData = mp.genGetIssuerCredentialsRequest(TEST_ID,"SomeDestinationId", "SomeOrg","SomeIssuerId", createOriginatorCredential())
		  String message = new String(responseData,"UTF-8")
		  def xmlMessage = new XmlSlurper().parseText(message)
		then:
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SomeDestinationId", "SomeOrg","GetIssuerCredentialsRequest")
		  verifySignature(message)
		  assert xmlMessage.@ID == TEST_ID
		  assert xmlMessage.originator.credential.uniqueId == "SomeOriginatorUniqueId"
		  assert xmlMessage.payload.getIssuerCredentialsRequest.issuerId == "SomeIssuerId"
	}
	

	def "Test that signed GetIssuerCredentialsResponse message is populated correctly and signature is valid"(){
		setup:
		  GetIssuerCredentialsRequest payload = of.createGetIssuerCredentialsRequest();
		  PKIMessage request = mp.genPKIMessage(DefaultPKIMessageParser.PKIMESSAGE_VERSION_1_1,null,"SOMESOURCEID","SomeOrg", createOriginatorCredential(), payload);
		  request.setSourceId("SOMEREQUESTER")
		when:
		  PKIMessageResponseData result = mp.genGetIssuerCredentialsResponse("SomeEntity",request, createDummyCredentials()[0])
		  String message = new String(result.responseData,"UTF-8")
		  def xmlMessage = new XmlSlurper().parseText(message)
		then:
		  assert result.isForwardableResponse == false
		  assert result.relatedEndEntity == "SomeEntity"
		  assert result.messageName == "GetIssuerCredentialsResponse"
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SOMEREQUESTER","SomeOrg", "GetIssuerCredentialsResponse")
		  verifySignature(message)
		  verifyResponseHeader(xmlMessage.payload.getIssuerCredentialsResponse, request)
		  assert xmlMessage.originator.credential.uniqueId == "SomeOriginatorUniqueId"
		  assert xmlMessage.payload.getIssuerCredentialsResponse.credential.credentialRequestId == 123
		  assert xmlMessage.payload.getIssuerCredentialsResponse.credential.uniqueId == "SomeUniqueId"
		  assert xmlMessage.payload.getIssuerCredentialsResponse.credential.displayName == "SomeDisplayName"
		  assert xmlMessage.payload.getIssuerCredentialsResponse.credential.serialNumber == "SomeSerialNumber"
		  assert xmlMessage.payload.getIssuerCredentialsResponse.credential.issuerId == "SomeIssuerId"
		  assert xmlMessage.payload.getIssuerCredentialsResponse.credential.status == 100
		  assert xmlMessage.payload.getIssuerCredentialsResponse.credential.credentialType == "SomeCredentialType"
		  assert xmlMessage.payload.getIssuerCredentialsResponse.credential.credentialSubType == "SomeCredentialSubType"
		  assert xmlMessage.payload.getIssuerCredentialsResponse.credential.attributes.attribute[0].key == "someattrkey"
		  assert xmlMessage.payload.getIssuerCredentialsResponse.credential.attributes.attribute[0].value == "someattrvalue"
		  assert xmlMessage.payload.getIssuerCredentialsResponse.credential.usages[0].usage == "someusage"
		  assert xmlMessage.payload.getIssuerCredentialsResponse.credential.credentialData == "MTIzNDVBQkNFRg=="
		  assert xmlMessage.payload.getIssuerCredentialsResponse.credential.issueDate == "1970-01-01T01:00:01.234+01:00"
		  assert xmlMessage.payload.getIssuerCredentialsResponse.credential.expireDate == "1970-01-01T01:00:02.234+01:00"
		  assert xmlMessage.payload.getIssuerCredentialsResponse.credential.validFromDate == "1970-01-01T01:00:03.234+01:00"
	}

	def "Test that signed IsIssuerRequest message is populated correctly and signature is valid"(){
		when:
		  byte[] responseData = mp.genIsIssuerRequest(TEST_ID,"SomeDestinationId","SomeOrg", "SomeIssuerId", createOriginatorCredential())
		  String message = new String(responseData,"UTF-8")
		  def xmlMessage = new XmlSlurper().parseText(message)
		then:
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SomeDestinationId", "SomeOrg","IsIssuerRequest")
		  verifySignature(message)
		  assert xmlMessage.@ID == TEST_ID
		  assert xmlMessage.originator.credential.uniqueId == "SomeOriginatorUniqueId"
		  assert xmlMessage.payload.isIssuerRequest.issuerId == "SomeIssuerId"
	}

	def "Test that signed IsIssuerResponse message is populated correctly and signature is valid"(){
		setup:
		  IsIssuerRequest payload = of.createIsIssuerRequest();
		  PKIMessage request = mp.genPKIMessage(DefaultPKIMessageParser.PKIMESSAGE_VERSION_1_1,null,"SOMESOURCEID","SomeOrg", createOriginatorCredential(), payload);
		  request.setSourceId("SOMEREQUESTER")
		when:
		  PKIMessageResponseData result = mp.genIsIssuerResponse("SomeEntity",request, true)
		  String message = new String(result.responseData,"UTF-8")
		  def xmlMessage = new XmlSlurper().parseText(message)
		then:
		  assert result.isForwardableResponse == false
		  assert result.relatedEndEntity == "SomeEntity"
		  assert result.messageName == "IsIssuerResponse"
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SOMEREQUESTER","SomeOrg", "IsIssuerResponse")
		  verifySignature(message)
		  verifyResponseHeader(xmlMessage.payload.isIssuerResponse, request)
		  assert xmlMessage.originator.credential.uniqueId == "SomeOriginatorUniqueId"
		  assert xmlMessage.payload.isIssuerResponse.isIssuer == true
		  
	}

	def "Test that signed IssueCredentialStatusListRequest message is populated correctly and signature is valid"(){
		when:
		  byte[] responseData = mp.genIssueCredentialStatusListRequest(TEST_ID,"SomeDestinationId", "SomeOrg","SomeIssuerId", "SomeCredentialStatusListType", true, new Date(1), new Date(2),createOriginatorCredential())
		  String message = new String(responseData,"UTF-8")
		  def xmlMessage = new XmlSlurper().parseText(message)
		then:
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SomeDestinationId", "SomeOrg","IssueCredentialStatusListRequest")
		  verifySignature(message)
		  assert xmlMessage.@ID == TEST_ID
		  assert xmlMessage.originator.credential.uniqueId == "SomeOriginatorUniqueId"
		  assert xmlMessage.payload.issueCredentialStatusListRequest.issuerId == "SomeIssuerId"
		  assert xmlMessage.payload.issueCredentialStatusListRequest.credentialStatusListType == "SomeCredentialStatusListType"
		  assert xmlMessage.payload.issueCredentialStatusListRequest.force == "true"
		  assert xmlMessage.payload.issueCredentialStatusListRequest.requestedValidFromDate.toString().startsWith("1970")
		  assert xmlMessage.payload.issueCredentialStatusListRequest.requestedNotAfterDate.toString().startsWith("1970")
	}

	def "Test that signed IssueCredentialStatusListResponse message is populated correctly and signature is valid"(){
		setup:
		  IssueCredentialStatusListRequest payload = of.createIssueCredentialStatusListRequest();
		  PKIMessage request = mp.genPKIMessage(DefaultPKIMessageParser.PKIMESSAGE_VERSION_1_1,null,"SOMESOURCEID", "SomeOrg",createOriginatorCredential(),payload);
		  request.setSourceId("SOMEREQUESTER")
		when:
		  PKIMessageResponseData result = mp.genIssueCredentialStatusListResponse("SomeEntity",request, createDummyCredentialStatusList())
		  String message = new String(result.responseData,"UTF-8") 
		  def xmlMessage = new XmlSlurper().parseText(message)
		then:
		  assert result.isForwardableResponse == true
		  assert result.relatedEndEntity == "SomeEntity"
		  assert result.messageName == "IssueCredentialStatusListResponse"
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SOMEREQUESTER", "SomeOrg","IssueCredentialStatusListResponse")
		  verifySignature(message)
		  verifyResponseHeader(xmlMessage.payload.issueCredentialStatusListResponse, request)
		  assert xmlMessage.originator.credential.uniqueId == "SomeOriginatorUniqueId"
		  assert xmlMessage.payload.issueCredentialStatusListResponse.credentialStatusList.issuerId == "SomeIssuerId"
		  assert xmlMessage.payload.issueCredentialStatusListResponse.credentialStatusList.credentialStatusListType == "SomeCredentialStatusListType"
		  assert xmlMessage.payload.issueCredentialStatusListResponse.credentialStatusList.credentialType == "SomeCredentialType"
		  assert xmlMessage.payload.issueCredentialStatusListResponse.credentialStatusList.serialNumber == "16"
		  assert xmlMessage.payload.issueCredentialStatusListResponse.credentialStatusList.listData == "MTIzNDVBQkNFRg=="
		  assert xmlMessage.payload.issueCredentialStatusListResponse.credentialStatusList.description == "SomeDescription"
		  assert xmlMessage.payload.issueCredentialStatusListResponse.credentialStatusList.issueDate == "1970-01-01T01:00:01.235+01:00"
		  assert xmlMessage.payload.issueCredentialStatusListResponse.credentialStatusList.expireDate == "1970-01-01T01:00:01.234+01:00"
		  assert xmlMessage.payload.issueCredentialStatusListResponse.credentialStatusList.validFromDate == "1970-01-01T01:00:01.236+01:00"
	}
	
	def "Test that signed genIssueCredentialStatusListResponseWithoutRequest message is populated correctly and signature is valid"(){

		when:
		  PKIMessageResponseData result = mp.genIssueCredentialStatusListResponseWithoutRequest("SomeEntity","SOMEDESTINATION","SOMENAME", "SomeOrg", createDummyCredentialStatusList(), createOriginatorCredential())
		  String message = new String(result.responseData,"UTF-8")
		  def xmlMessage = new XmlSlurper().parseText(message)
		then:
		  assert result.isForwardableResponse == true
		  assert result.relatedEndEntity == "SomeEntity"
		  assert result.messageName == "IssueCredentialStatusListResponse"
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SOMEDESTINATION", "SomeOrg","IssueCredentialStatusListResponse")
		  verifySignature(message)
		  assert xmlMessage.originator.credential.uniqueId == "SomeOriginatorUniqueId"
		  assert xmlMessage.payload.issueCredentialStatusListResponse.inResponseTo == result.getMessageId()
		  assert xmlMessage.payload.issueCredentialStatusListResponse.status == "SUCCESS"
		  assert xmlMessage.payload.issueCredentialStatusListResponse.credentialStatusList.issuerId == "SomeIssuerId"
		  assert xmlMessage.payload.issueCredentialStatusListResponse.credentialStatusList.credentialStatusListType == "SomeCredentialStatusListType"
		  assert xmlMessage.payload.issueCredentialStatusListResponse.credentialStatusList.credentialType == "SomeCredentialType"
		  assert xmlMessage.payload.issueCredentialStatusListResponse.credentialStatusList.serialNumber == "16"
		  assert xmlMessage.payload.issueCredentialStatusListResponse.credentialStatusList.listData == "MTIzNDVBQkNFRg=="
		  assert xmlMessage.payload.issueCredentialStatusListResponse.credentialStatusList.description == "SomeDescription"
		  assert xmlMessage.payload.issueCredentialStatusListResponse.credentialStatusList.issueDate == "1970-01-01T01:00:01.235+01:00"
		  assert xmlMessage.payload.issueCredentialStatusListResponse.credentialStatusList.expireDate == "1970-01-01T01:00:01.234+01:00"
		  assert xmlMessage.payload.issueCredentialStatusListResponse.credentialStatusList.validFromDate == "1970-01-01T01:00:01.236+01:00"
	}

	def "Test that signed RemoveCredentialRequest message is populated correctly and signature is valid"(){
		when:
		  byte[] responseData = mp.genRemoveCredentialRequest(TEST_ID,"SomeDestinationId","SomeOrg", "SomeIssuerId", "SomeCredentialSerialNumber", createOriginatorCredential())
		  String message = new String(responseData,"UTF-8")
		  def xmlMessage = new XmlSlurper().parseText(message)
		then:
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SomeDestinationId","SomeOrg", "RemoveCredentialRequest")
		  verifySignature(message)
		  assert xmlMessage.@ID == TEST_ID
		  assert xmlMessage.originator.credential.uniqueId == "SomeOriginatorUniqueId"
		  assert xmlMessage.payload.removeCredentialRequest.issuerId == "SomeIssuerId"
		  assert xmlMessage.payload.removeCredentialRequest.serialNumber == "SomeCredentialSerialNumber"		  
	}

	def "Test that signed RemoveCredentialResponse message is populated correctly and signature is valid"(){
		setup:
		  RemoveCredentialRequest payload = of.createRemoveCredentialRequest();
		  PKIMessage request = mp.genPKIMessage(DefaultPKIMessageParser.PKIMESSAGE_VERSION_1_1,null,"SOMESOURCEID", "SomeOrg",createOriginatorCredential(),payload);
		  request.setSourceId("SOMEREQUESTER")
		when:
		  PKIMessageResponseData result = mp.genRemoveCredentialResponse("SomeEntity",request)
		  String message = new String(result.responseData,"UTF-8")
		  def xmlMessage = new XmlSlurper().parseText(message)
		then:
		  assert result.relatedEndEntity == "SomeEntity"
		  assert result.messageName == "RemoveCredentialResponse"
		  assert result.isForwardableResponse == false
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SOMEREQUESTER", "SomeOrg", "RemoveCredentialResponse")
		  verifySignature(message)
		  verifyResponseHeader(xmlMessage.payload.removeCredentialResponse, request)
		  assert xmlMessage.originator.credential.uniqueId == "SomeOriginatorUniqueId"
	}

	def "Test that signed FetchHardTokenDataRequest message is populated correctly and signature is valid"(){
		when:
		  byte[] responseData = mp.genFetchHardTokenDataRequest(TEST_ID,"SomeDestinationId","SomeOrg", "SomeTokenSerial", "SomeCredentialSerialNumber", "SomeIssuerId", createDummyCredentials()[0], createOriginatorCredential())
		  String message = new String(responseData,"UTF-8")
		  def xmlMessage = new XmlSlurper().parseText(message)
		then:
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SomeDestinationId", "SomeOrg","FetchHardTokenDataRequest")
		  verifySignature(message)
		  assert xmlMessage.@ID == TEST_ID
		  assert xmlMessage.originator.credential.uniqueId == "SomeOriginatorUniqueId"
		  assert xmlMessage.payload.fetchHardTokenDataRequest.tokenSerial == "SomeTokenSerial"
	      assert xmlMessage.payload.fetchHardTokenDataRequest.relatedCredentialSerialNumber == "SomeCredentialSerialNumber"
  	      assert xmlMessage.payload.fetchHardTokenDataRequest.relatedCredentialIssuerId == "SomeIssuerId"
		  assert xmlMessage.payload.fetchHardTokenDataRequest.adminCredential.credentialRequestId == 123
		  assert xmlMessage.payload.fetchHardTokenDataRequest.adminCredential.uniqueId == "SomeUniqueId"
		  assert xmlMessage.payload.fetchHardTokenDataRequest.adminCredential.displayName == "SomeDisplayName"
		  assert xmlMessage.payload.fetchHardTokenDataRequest.adminCredential.serialNumber == "SomeSerialNumber"
		  assert xmlMessage.payload.fetchHardTokenDataRequest.adminCredential.issuerId == "SomeIssuerId"
		  assert xmlMessage.payload.fetchHardTokenDataRequest.adminCredential.status == 100
		  assert xmlMessage.payload.fetchHardTokenDataRequest.adminCredential.credentialType == "SomeCredentialType"
		  assert xmlMessage.payload.fetchHardTokenDataRequest.adminCredential.credentialSubType == "SomeCredentialSubType"
		  assert xmlMessage.payload.fetchHardTokenDataRequest.adminCredential.attributes.attribute[0].key == "someattrkey"
		  assert xmlMessage.payload.fetchHardTokenDataRequest.adminCredential.attributes.attribute[0].value == "someattrvalue"
		  assert xmlMessage.payload.fetchHardTokenDataRequest.adminCredential.usages[0].usage == "someusage"
		  assert xmlMessage.payload.fetchHardTokenDataRequest.adminCredential.credentialData == "MTIzNDVBQkNFRg=="
		  assert xmlMessage.payload.fetchHardTokenDataRequest.adminCredential.issueDate == "1970-01-01T01:00:01.234+01:00"
		  assert xmlMessage.payload.fetchHardTokenDataRequest.adminCredential.expireDate == "1970-01-01T01:00:02.234+01:00"
		  assert xmlMessage.payload.fetchHardTokenDataRequest.adminCredential.validFromDate == "1970-01-01T01:00:03.234+01:00"
	}

	def "Test that signed FetchHardTokenDataResponse message is populated correctly and signature is valid"(){
		setup:
		  FetchHardTokenDataRequest payload = of.createFetchHardTokenDataRequest();
		  PKIMessage request = mp.genPKIMessage(DefaultPKIMessageParser.PKIMESSAGE_VERSION_1_1,null,"SOMESOURCEID", "SomeOrg",createOriginatorCredential(),payload);
		  request.setSourceId("SOMEREQUESTER")
		when:
		  PKIMessageResponseData result = mp.genFetchHardTokenDataResponse("SomeEntity",request, "123456", "SomeData".getBytes())
		  String message = new String(result.responseData,"UTF-8")
		  def xmlMessage = new XmlSlurper().parseText(message)
		then:
		  assert result.isForwardableResponse == false
		  assert result.relatedEndEntity == "SomeEntity"
		  assert result.messageName == "FetchHardTokenDataResponse"
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SOMEREQUESTER", "SomeOrg","FetchHardTokenDataResponse")
		  verifySignature(message)
		  verifyResponseHeader(xmlMessage.payload.fetchHardTokenDataResponse, request)
		  assert xmlMessage.originator.credential.uniqueId == "SomeOriginatorUniqueId"
		  assert xmlMessage.payload.fetchHardTokenDataResponse.tokenSerial == "123456"
		  assert xmlMessage.payload.fetchHardTokenDataResponse.encryptedData == "U29tZURhdGE="		  
	}

	def "Test that signed StoreHardTokenDataRequest message is populated correctly and signature is valid"(){
		when:
		  byte[] responseData = mp.genStoreHardTokenDataRequest(TEST_ID,"SomeDestinationId", "SomeOrg","SomeTokenSerial", "SomeCredentialSerialNumber", "SomeIssuerId", "SomeData".getBytes(),createOriginatorCredential())
		  String message = new String(responseData,"UTF-8")
		  def xmlMessage = new XmlSlurper().parseText(message)
		then:
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SomeDestinationId", "SomeOrg","StoreHardTokenDataRequest")
		  verifySignature(message)
		  assert xmlMessage.@ID == TEST_ID
		  assert xmlMessage.originator.credential.uniqueId == "SomeOriginatorUniqueId"
		  assert xmlMessage.payload.storeHardTokenDataRequest.tokenSerial == "SomeTokenSerial"
		  assert xmlMessage.payload.storeHardTokenDataRequest.relatedCredentialSerialNumber == "SomeCredentialSerialNumber"
		  assert xmlMessage.payload.storeHardTokenDataRequest.relatedCredentialIssuerId == "SomeIssuerId"
		  assert xmlMessage.payload.storeHardTokenDataRequest.encryptedData == "U29tZURhdGE="		  
	}

	def "Test that signed StoreHardTokenDataResponse message is populated correctly and signature is valid"(){
		setup:
		  StoreHardTokenDataRequest payload = of.createStoreHardTokenDataRequest();
		  PKIMessage request = mp.genPKIMessage(DefaultPKIMessageParser.PKIMESSAGE_VERSION_1_1,null,"SOMESOURCEID", "SomeOrg", createOriginatorCredential(),payload);
		  request.setSourceId("SOMEREQUESTER")
		when:
		  PKIMessageResponseData result = mp.genStoreHardTokenDataResponse("SomeEntity",request)
		  String message = new String(result.responseData,"UTF-8")
		  def xmlMessage = new XmlSlurper().parseText(message)
		then:
		  assert result.isForwardableResponse == false
		  assert result.relatedEndEntity == "SomeEntity"
		  assert result.messageName == "StoreHardTokenDataResponse"
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SOMEREQUESTER", "SomeOrg","StoreHardTokenDataResponse")
		  verifySignature(message)
		  verifyResponseHeader(xmlMessage.payload.storeHardTokenDataResponse, request)
		  assert xmlMessage.originator.credential.uniqueId == "SomeOriginatorUniqueId"
	}
	
	
	def "Test that getVersionFromMessage parses the version attribute correctly."(){
		
		expect:
		mp.getVersionFromMessage(TestMessages.testMessageWithResponse.getBytes("UTF-8")) == "1.0"
		mp.getVersionFromMessage(TestMessages.testMessageWithVersion1_1.getBytes("UTF-8")) == "1.1"
		when:
		mp.getVersionFromMessage(TestMessages.testMessageWithNoVersion.getBytes("UTF-8"))
		then:
		thrown IllegalArgumentException
		when:
		mp.getVersionFromMessage(TestMessages.testMessageWithEmptyVersion.getBytes("UTF-8"))
		then:
		thrown IllegalArgumentException
		
		
		
		
	}
	
	def "Test that a version 1.1 message with originator element validates"(){
		expect:
		mp.genIsIssuerRequest(TEST_ID,"SomeDestinationId","SomeOrg", "SomeIssuerId", createOriginatorCredential()) != null
	}
	
	def "Test that a version 1.0 message with originator element is invalid"(){
		setup:
		mp.setDefaultVersion(DefaultPKIMessageParser.PKIMESSAGE_VERSION_1_0)
		when:
		mp.genIsIssuerRequest(TEST_ID,"SomeDestinationId","SomeOrg", "SomeIssuerId", createOriginatorCredential())
		then:
		thrown(MessageException)
		cleanup:
		mp.setDefaultVersion(DefaultPKIMessageParser.PKIMESSAGE_VERSION_1_1)
	}
	
	def "Test that getOriginatorFromRequest works as expected"(){
		setup:
		StoreHardTokenDataRequest payload = of.createStoreHardTokenDataRequest();		
		PKIMessage withOriginator = mp.genPKIMessage(DefaultPKIMessageParser.PKIMESSAGE_VERSION_1_1,null,"SOMESOURCEID", "SomeOrg", createOriginatorCredential(),payload);
		PKIMessage withoutOriginator = mp.genPKIMessage(DefaultPKIMessageParser.PKIMESSAGE_VERSION_1_1,null,"SOMESOURCEID", "SomeOrg", null,payload);
		expect:
		DefaultPKIMessageParser.getOriginatorFromRequest(withOriginator) != null
		DefaultPKIMessageParser.getOriginatorFromRequest(withoutOriginator) == null
		DefaultPKIMessageParser.getOriginatorFromRequest(null) == null
	}
	
	def "Test that marshallAndSignPKIMessage signs and marshalls a request properly"(){
		setup:
		  IsIssuerResponse payload = of.createIsIssuerResponse()
		  payload.isIssuer = true
		  
		  payload.status = RequestStatus.SUCCESS
		  PKIMessage request = mp.genPKIMessage(DefaultPKIMessageParser.PKIMESSAGE_VERSION_1_1,null,"SOMEREQUESTER", "SomeOrg",createOriginatorCredential(),payload);
		  request.setSourceId("SOMESOURCEID")
		  payload.inResponseTo = request.id
		  
		when:
		  byte[] result = mp.marshallAndSignPKIMessage(request)
		  String message = new String(result,"UTF-8")
		  def xmlMessage = new XmlSlurper().parseText(message)
		then:
		  verifyPKIHeaderMessage(message, xmlMessage, "SOMESOURCEID", "SOMEREQUESTER", "SomeOrg","IsIssuerResponse")
		  verifySignature(message)
		  verifyResponseHeader(xmlMessage.payload.isIssuerResponse, request)
		  assert xmlMessage.originator.credential.uniqueId == "SomeOriginatorUniqueId"
	}

	
	private void verifyPKIHeaderMessage(String message, GPathResult xmlMessage, String expectedSourceId, String expectedDestinationId, String expectedOrganisation, String expectedName){
		assert message.contains("xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"")
		assert message.contains("xmlns=\"http://certificateservices.org/xsd/pkimessages1_0\"")
		assert message.contains("xsi:schemaLocation=\"http://certificateservices.org/xsd/pkimessages1_0 pkimessages_schema1_0.xsd\"")
		assert xmlMessage.@version == "1.1" || xmlMessage.@version == "1.0"
		assert xmlMessage.@ID != null
		assert xmlMessage.name == expectedName
		assert xmlMessage.sourceId == expectedSourceId
		assert xmlMessage.destinationId == expectedDestinationId
		assert xmlMessage.organisation == expectedOrganisation
		assert xmlMessage.payload != null
		assert xmlMessage.@timeStamp != null
	}
	
	private void verifySignature(String message){
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true)
		DocumentBuilder builder = factory.newDocumentBuilder();
		Document doc = builder.parse(new InputSource(new StringReader(message)));
	
		Element signature = doc.getElementsByTagName("ds:Signature").item(0)

		assert signature != null
		
		DOMValidateContext validationContext = new DOMValidateContext(new X509KeySelector(createTestKeyStore()), signature)
		validationContext.setIdAttributeNS(doc.getDocumentElement(), null, "ID")
		XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM",new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI())
		XMLSignature sig =  signatureFactory.unmarshalXMLSignature(validationContext)
		assert sig.validate(validationContext)
	}
	
	private void verifyResponseHeader(GPathResult payload, PKIMessage request){
		assert payload.inResponseTo == request.getID()
		assert payload.status == "SUCCESS"
	}
	
	private KeyStore createTestKeyStore(){
		KeyStore ks = KeyStore.getInstance("JKS")
		ks.load(null)
		ks.setCertificateEntry("trustedCert", secprov.getSigningCertificate());
		return ks
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
	
	private List<Credential> createDummyCredentials(int status = 100){
		List<Credential> retval = [];
		Credential c = of.createCredential();
		

		
		c.credentialRequestId = 123
		c.credentialType = "SomeCredentialType"
		c.credentialSubType = "SomeCredentialSubType"
		c.uniqueId = "SomeUniqueId"
		c.displayName = "SomeDisplayName"
		c.serialNumber = "SomeSerialNumber"
		c.issuerId = "SomeIssuerId"
		c.status = status
		c.credentialData = "12345ABCEF"
		
		GregorianCalendar gc = new GregorianCalendar();
		gc.setTime(new Date(1234L));
		
		c.issueDate = DatatypeFactory.newInstance().newXMLGregorianCalendar(gc);
		c.issueDate.setTimezone(60)
		
		gc = new GregorianCalendar();
		gc.setTime(new Date(2234L));
		c.expireDate = DatatypeFactory.newInstance().newXMLGregorianCalendar(gc);
		c.expireDate.setTimezone(60)
		gc = new GregorianCalendar();
		gc.setTime(new Date(3234L));
		c.validFromDate = DatatypeFactory.newInstance().newXMLGregorianCalendar(gc);
		c.validFromDate.setTimezone(60)
		Attribute attr = of.createAttribute();
		attr.setKey("someattrkey")
		attr.setValue("someattrvalue")
		
		c.setAttributes(new Credential.Attributes())
		c.getAttributes().getAttribute().add(attr)

		c.setUsages(new Credential.Usages())
		c.getUsages().getUsage().add("someusage")
		
		retval.add(c)

		return retval
	}
	
	private Credential createOriginatorCredential(){		
		Credential c = of.createCredential();
		

		
		c.credentialRequestId = 123
		c.credentialType = "SomeCredentialType"
		c.credentialSubType = "SomeCredentialSubType"
		c.uniqueId = "SomeOriginatorUniqueId"
		c.displayName = "SomeOrignatorDisplayName"
		c.serialNumber = "SomeSerialNumber"
		c.issuerId = "SomeIssuerId"
		c.status = 100
		c.credentialData = "12345ABCEF"
		
		GregorianCalendar gc = new GregorianCalendar();
		gc.setTime(new Date(1234L));
		
		c.issueDate = DatatypeFactory.newInstance().newXMLGregorianCalendar(gc);
		c.issueDate.setTimezone(60)
		
		gc = new GregorianCalendar();
		gc.setTime(new Date(2234L));
		c.expireDate = DatatypeFactory.newInstance().newXMLGregorianCalendar(gc);
		c.expireDate.setTimezone(60)
		gc = new GregorianCalendar();
		gc.setTime(new Date(3234L));
		c.validFromDate = DatatypeFactory.newInstance().newXMLGregorianCalendar(gc);
		c.validFromDate.setTimezone(60)
		Attribute attr = of.createAttribute();
		attr.setKey("someattrkey")
		attr.setValue("someattrvalue")
		
		c.setAttributes(new Credential.Attributes())
		c.getAttributes().getAttribute().add(attr)

		c.setUsages(new Credential.Usages())
		c.getUsages().getUsage().add("someusage")
		

		return c
	}
	
	private CredentialStatusList createDummyCredentialStatusList(){
		CredentialStatusList retval = of.createCredentialStatusList();
		retval.credentialStatusListType = "SomeCredentialStatusListType"
		retval.credentialType = "SomeCredentialType"
		retval.description = "SomeDescription"
		GregorianCalendar gc = new GregorianCalendar();
		gc.setTime(new Date(1234L));
		retval.expireDate = DatatypeFactory.newInstance().newXMLGregorianCalendar(gc);
		retval.expireDate.setTimezone(60)
		gc.setTime(new Date(1235L));
		retval.issueDate = DatatypeFactory.newInstance().newXMLGregorianCalendar(gc);
		retval.issueDate.setTimezone(60)
		retval.issuerId = "SomeIssuerId"
		retval.listData = "12345ABCEF"
		retval.serialNumber = 16L
		gc.setTime(new Date(1236L));
		retval.validFromDate = DatatypeFactory.newInstance().newXMLGregorianCalendar(gc);
		retval.validFromDate.setTimezone(60)
		return retval
	}

}
