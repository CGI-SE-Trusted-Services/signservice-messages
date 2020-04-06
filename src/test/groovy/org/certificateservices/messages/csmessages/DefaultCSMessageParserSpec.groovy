/************************************************************************
 *                                                                       *
 *  Certificate Service - Messages                                       *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.certificateservices.messages.csmessages;

import groovy.util.slurpersupport.GPathResult
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.certificateservices.messages.MessageSecurityProvider

import java.security.Security
import java.security.cert.X509Certificate
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Marshaller;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.parsers.DocumentBuilder;

import org.apache.xml.security.Init
import org.certificateservices.messages.DummyMessageSecurityProvider;
import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.assertion.AssertionPayloadParser
import org.certificateservices.messages.saml2.assertion.jaxb.AssertionType;
import org.certificateservices.messages.credmanagement.CredManagementPayloadParser;
import org.certificateservices.messages.credmanagement.jaxb.FieldValue
import org.certificateservices.messages.csmessages.jaxb.ApprovalStatus;
import org.certificateservices.messages.csmessages.jaxb.Attribute;
import org.certificateservices.messages.csmessages.jaxb.CSMessage
import org.certificateservices.messages.csmessages.jaxb.CSResponse;
import org.certificateservices.messages.csmessages.jaxb.Credential;
import org.certificateservices.messages.csmessages.jaxb.ObjectFactory;
import org.certificateservices.messages.csmessages.jaxb.RequestStatus;
import org.certificateservices.messages.dummy.DummyPayloadParser;
import org.certificateservices.messages.dummy.jaxb.SomePayload;
import org.certificateservices.messages.saml2.protocol.jaxb.ResponseType;
import org.certificateservices.messages.sysconfig.SysConfigPayloadParser;
import org.certificateservices.messages.sysconfig.jaxb.GetActiveConfigurationRequest
import org.certificateservices.messages.utils.SystemTime
import org.w3c.dom.Document
import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.messages.csmessages.DefaultCSMessageParser.*
import static org.certificateservices.messages.csmessages.TestMessages.*
import static org.certificateservices.messages.TestUtils.*

public class DefaultCSMessageParserSpec extends Specification{
	
	
	org.certificateservices.messages.sysconfig.jaxb.ObjectFactory sysConfigOf = new org.certificateservices.messages.sysconfig.jaxb.ObjectFactory()
	static ObjectFactory of = new ObjectFactory();
	DefaultCSMessageParser mp = new DefaultCSMessageParser()
	DefaultCSMessageParser requestMessageParser = new DefaultCSMessageParser()
	DummyMessageSecurityProvider secprov = new DummyMessageSecurityProvider();
	
	AssertionPayloadParser assertionPayloadParser
	CredManagementPayloadParser credManagementPayloadParser
	
	public static final String TEST_ID = "12345678-1234-4444-8000-123456789012"
	
	List<X509Certificate> recipients
	def fv1
	def fv2
	
	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Init.init()

		// Use english - make test locale independent.
		Locale.setDefault(new Locale("en", "US"));
	}
	
	def setup(){
		Properties requestConfig = new Properties();
		requestConfig.setProperty(DefaultCSMessageParser.SETTING_SOURCEID, "SOMEREQUESTER");
		requestMessageParser =  CSMessageParserManager.initCSMessageParser(secprov,requestConfig)


		
		Properties config = new Properties();
		config.setProperty(DefaultCSMessageParser.SETTING_SOURCEID, "SOMESOURCEID");
		mp.init(secprov, config)
		
		assertionPayloadParser = PayloadParserRegistry.getParser(AssertionPayloadParser.NAMESPACE)
		assertionPayloadParser.systemTime = Mock(SystemTime)
		assertionPayloadParser.systemTime.getSystemTime() >> new Date(1436279213000)
		assertionPayloadParser.samlAssertionMessageParser.systemTime = assertionPayloadParser.systemTime


		credManagementPayloadParser = PayloadParserRegistry.getParser(CredManagementPayloadParser.NAMESPACE)
		
		
		X509Certificate validCert = secprov.getDecryptionCertificate(secprov.decryptionKeyIds.iterator().next())
		recipients = [validCert]
		
		fv1 = new FieldValue();
		fv1.key = "someKey1"
		fv1.value = "someValue1"
		fv2 = new FieldValue();
		fv2.key = "someKey2"
		fv2.value = "someValue2"
	
	}
	
	def "Verify init()"(){
		expect:
		PayloadParserRegistry.configurationCallback != null
		mp.properties != null
		mp.securityProvider instanceof DummyMessageSecurityProvider
		mp.messageNameCatalogue != null
		mp.jaxbData.jaxbContext != null
		mp.jaxbData.csMessageMarshallers.size() == SUPPORTED_CSMESSAGE_VERSIONS.length
		mp.jaxbData.csMessageUnmarshallers.size() == SUPPORTED_CSMESSAGE_VERSIONS.length
		mp.sourceId == "SOMESOURCEID"
	}
	


	def "Verify that generateIsApprovalRequest() generates a valid xml message and generateIsApprovalResponse() generates a valid CSMessageResponseData"(){
		when:
		byte[] requestMessage = requestMessageParser.generateIsApprovedRequest(TEST_ID, "SOMESOURCEID", "someorg", "123-212", createOriginatorCredential(), null);
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.IsApprovedRequest
		then:
		messageContainsPayload requestMessage, "cs:IsApprovedRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","IsApprovedRequest", createOriginatorCredential())
		payloadObject.approvalId == "123-212"
		
		when:
		CSMessage request = mp.parseMessage(requestMessage)
		CSMessageResponseData rd = mp.generateIsApprovedResponse("SomeRelatedEndEntity", request, ApprovalStatus.APPROVED, createAssertions())
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.IsApprovedResponse
		
		then:
		messageContainsPayload rd.responseData, "cs:IsApprovedResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "IsApprovedResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","IsApprovedResponse", createOriginatorCredential())
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.approvalId == "123-212"
		payloadObject.approvalStatus == ApprovalStatus.APPROVED.toString()
		payloadObject.assertions.Assertion.size() == 2
		payloadObject.assertions.Assertion[0].AttributeStatement.Attribute[0].AttributeValue == "APPROVAL_TICKET"
	}
	
	
	def "Verify that generateGetApprovalRequest() generates a valid xml message  generateGetApprovalResponse() generates a valid CSMessageResponseData"(){
		setup:
		SysConfigPayloadParser scpp = PayloadParserRegistry.getParser(SysConfigPayloadParser.NAMESPACE);
		when:
		byte[] reqData = scpp.generateGetActiveConfigurationRequest(TEST_ID, "someDest", "someorg", "SomeApp", null, null)

		byte[] requestMessage = requestMessageParser.generateGetApprovalRequest(TEST_ID, "SOMESOURCEID", "someorg", reqData, createOriginatorCredential(), null);
		
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.GetApprovalRequest

		then:
		
		messageContainsPayload requestMessage, "cs:GetApprovalRequest"
		messageContainsPayload requestMessage, "sysconfig:GetActiveConfigurationRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","GetApprovalRequest", createOriginatorCredential())
		payloadObject.requestPayload.GetActiveConfigurationRequest.application == "SomeApp"
		payloadObject.requestPayload.GetActiveConfigurationRequest.organisationShortName == "someorg"
		
		when:
		CSMessage request = mp.parseMessage(requestMessage)
		CSMessageResponseData rd = mp.generateGetApprovalResponse("SomeRelatedEndEntity", request, "123-212",ApprovalStatus.APPROVED, createAssertions())
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.GetApprovalResponse
		
		then:
		messageContainsPayload rd.responseData, "cs:GetApprovalResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "GetApprovalResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","GetApprovalResponse", createOriginatorCredential())
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.approvalId == "123-212"
		payloadObject.approvalStatus == ApprovalStatus.APPROVED.toString()
		payloadObject.assertions.Assertion.size() == 2
		payloadObject.assertions.Assertion[0].AttributeStatement.Attribute[0].AttributeValue == "APPROVAL_TICKET"
		
		when:
		mp.parseMessage(getApprovalRequestWithInvalidRequestPayload)

		then:
		thrown MessageContentException		

	}

	
	def "Verify that genCSFailureResponse() generates correct failure response message"(){
		setup:
		byte[] requestMessage = mp.generateIsApprovedRequest(TEST_ID, "somedest", "someorg", "someid", null, null);
		when:
		CSMessageResponseData rd = mp.genCSFailureResponse("SomeRelatedEndEntity", requestMessage, RequestStatus.ILLEGALARGUMENT, "SomeFailureMessage", "somedest", createOriginatorCredential())
		def xml = slurpXml(rd.responseData)
		then:
		messageContainsPayload rd.responseData, "cs:FailureResponse"
		
		verifyCSMessageResponseData  rd, "somedest", TEST_ID, false, "FailureResponse", "SomeRelatedEndEntity"		
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "somedest", "someorg","FailureResponse", createOriginatorCredential())
		
		xml.payload.FailureResponse.inResponseTo == TEST_ID
		xml.payload.FailureResponse.status == "ILLEGALARGUMENT"
		xml.payload.FailureResponse.failureMessage == "SomeFailureMessage"
		
		when:
		rd = mp.genCSFailureResponse("SomeRelatedEndEntity", requestMessage, RequestStatus.ILLEGALARGUMENT, null, "somedest", createOriginatorCredential())
		xml = slurpXml(rd.responseData)
	
		then:
		xml.payload.FailureResponse.inResponseTo == TEST_ID
		xml.payload.FailureResponse.status == "ILLEGALARGUMENT"
		xml.payload.FailureResponse.failureMessage.size() == 0
	}
	
	def "Verify that getSigningCertificate parses signer certificate"(){
		expect:
		mp.requireSignature()
		mp.getSigningCertificate(simpleCSMessage) instanceof X509Certificate
		when:
		mp.requireSignature = false
		then:
		mp.getSigningCertificate(simpleCSMessage) == null

		when:
		mp.requireSignature = true
		mp.getSigningCertificate(simpleCSMessageWithBadCertificate)
		then:
		thrown MessageContentException
		
	}
	
	def "Verify that genCSMessage() generates a valid header structure"(){
		when: "Create minimal cs message"
		CSMessage m = mp.genCSMessage("2.0", "2.1", null, null, "somedest", "someorg", null, createPayLoad(), null)
		then:
		m.id != null && m.id != TEST_ID;
		m.timeStamp != null
		m.organisation == "someorg"
		m.name == "GetActiveConfigurationRequest"
		m.sourceId == "SOMESOURCEID"
		m.destinationId == "somedest"
		m.originator == null
		m.assertions == null
		m.payload.any instanceof GetActiveConfigurationRequest
		m.version == "2.0"
		m.payLoadVersion == "2.1"
		m.signature == null
		
		when: "Create full cs message"
		m = mp.genCSMessage("2.0", "2.1", "NameRequest", TEST_ID, "somedest", "someorg", createOriginatorCredential(), createPayLoad(), null)
		then:
		m.id == TEST_ID;
		m.timeStamp != null
		m.organisation == "someorg"
		m.name == "GetActiveConfigurationRequest"
		m.sourceId == "SOMESOURCEID"
		m.destinationId == "somedest"
		m.originator.credential.displayName == "SomeOrignatorDisplayName"
		m.payload.any instanceof GetActiveConfigurationRequest
		m.version == "2.0"
		m.payLoadVersion == "2.1"
		m.signature == null
	}
	
	
	def "Verify populateSuccessfulResponse handles both CSResponse and JAXBElement input"(){
		setup:
		CSMessage request = mp.parseMessage(mp.generateIsApprovedRequest(TEST_ID, "somedest", "someorg", "someid", null, null));
		
		when:
		CSResponse csResponse = sysConfigOf.createGetActiveConfigurationResponse()
		mp.populateSuccessfulResponse(csResponse, request)
		then:
		csResponse.status == RequestStatus.SUCCESS
		csResponse.inResponseTo == TEST_ID
		csResponse.failureMessage == null
		
		when:
		Object jaxbResponse = of.createIsApprovedResponse(of.createIsApprovedResponseType())
		mp.populateSuccessfulResponse(jaxbResponse, request)
		then:
		jaxbResponse.value.status == RequestStatus.SUCCESS
		jaxbResponse.value.inResponseTo == TEST_ID
		jaxbResponse.value.failureMessage == null
		
		when:
		mp.populateSuccessfulResponse(new Integer(1), request)
		then:
		thrown MessageProcessingException
	}
	
	def "Verify that marshallAndSignCSMessage generates correct signatures"(){
		setup:
		def csMessage = mp.genCSMessage("2.0", "2.0", null, TEST_ID, "somedest", "someorg", null, createPayLoad(), createAssertions())
		expect:
		mp.requireSignature()
		
		when:
		String msg = new String(mp.marshallAndSignCSMessage(csMessage), "UTF-8")
		then:
		msg =~ "ds:Signature"
		mp.parseMessage(msg.getBytes("UTF-8"))
		
		when:
		mp.requireSignature = false
		msg = new String(mp.marshallAndSignCSMessage(csMessage), "UTF-8")
		
		then:
		msg !=~ "ds:Signature"
		
		
	}

	def "Verify that marshallCSMessage generates message without signatures"(){
		setup:
		def csMessage = mp.genCSMessage("2.0", "2.0", null, TEST_ID, "somedest", "someorg", null, createPayLoad(), createAssertions())

		when:
		String msg = new String(mp.marshallCSMessage(csMessage), "UTF-8")
		then:
		msg !=~ "ds:Signature"
		mp.parseMessage(msg.getBytes("UTF-8"),false,false)
	}

	def "Verify that parseMessage performsValidation if flag is set to true"(){
		setup:
		def orgSecProv = mp.xmlSigner.messageSecurityProvider
		def csMessage = mp.genCSMessage("2.0", "2.0", null, TEST_ID, "somedest", "someorg", null, createPayLoad(), createAssertions())
		byte[] msg = mp.marshallAndSignCSMessage(csMessage)
		mp.xmlSigner.messageSecurityProvider = Mock(MessageSecurityProvider)
		when:
		mp.parseMessage(msg, true)
		then:
		1 * mp.xmlSigner.messageSecurityProvider.isValidAndAuthorized(_,_) >> true

		cleanup:
		true
		mp.xmlSigner.messageSecurityProvider  = orgSecProv
	}

	def "Verify that parseMessage doesn't performsValidation if flag is set to false"(){
		setup:
		def orgSecProv = mp.xmlSigner.messageSecurityProvider
		def csMessage = mp.genCSMessage("2.0", "2.0", null, TEST_ID, "somedest", "someorg", null, createPayLoad(), createAssertions())
		byte[] msg = mp.marshallAndSignCSMessage(csMessage)
		mp.xmlSigner.messageSecurityProvider = Mock(MessageSecurityProvider)
		when:
		mp.parseMessage(msg, false)
		then:
		1 * mp.xmlSigner.messageSecurityProvider.isValidAndAuthorized(_,null) >> {true}

		cleanup:
		true
		mp.xmlSigner.messageSecurityProvider  = orgSecProv
	}

	
	
	def "Verify validateCSMessage() method"(){
		when: "Verify that valid message passes validation"
		mp.validateCSMessage(mp.getVersionFromMessage(simpleCSMessage), mp.parseMessage(simpleCSMessage), getDoc(simpleCSMessage),true, true)
		then:
		true
		
		when: "Verify that non CSMessage object throws MessageContentException"
		mp.validateCSMessage(null, new Object(), null, true, true)
		then:
		thrown MessageContentException
		
		when: "Verify invalid signature throws MessageContentException"
		mp.validateCSMessage(mp.getVersionFromMessage(cSMessageWithInvalidSignature), mp.parseMessage(cSMessageWithInvalidSignature), getDoc(cSMessageWithInvalidSignature), true, true)
		then:
		final MessageContentException e1 = thrown()
		e1.message =~ "signed message"
		
		when: "Verify invalid payload throws MessageContentException"
		mp.validateCSMessage(mp.getVersionFromMessage(simpleCSMessageWithInvalidPayload), mp.parseMessage(simpleCSMessageWithInvalidPayload), getDoc(simpleCSMessageWithInvalidPayload), true, true)
		then:
		final MessageContentException e2 = thrown()
		e2.message =~ "parsing payload"
		
	}
	
	def "Verify that verifyCSMessageVersion returns true for supported versions and throws MessageContentException for unsupported versions"(){
		expect:
		mp.verifyCSMessageVersion(SUPPORTED_CSMESSAGE_VERSIONS[0]) 
		
		when:
		mp.verifyCSMessageVersion("unsupported")
		
		then:
		thrown MessageContentException
	}
	
	def "Verify that validateSignature correctly parses the ds:Signature object and verifies the signature"(){
		expect:
		mp.requireSignature() == true
		
		when:
		mp.validateSignature(getDoc(simpleCSMessage), true, true)
		then:
		true
		when:
		mp.validateSignature(getDoc(cSMessageWithInvalidSignature), true, true)
		then:
		thrown MessageContentException
		
		when:
		mp.validateSignature(getDoc(simpleCSMessageWithoutSignature), true, true)
		then:
		thrown MessageContentException
		
		when:
		mp.requireSignature = false
		mp.validateSignature(getDoc(cSMessageWithInvalidSignature), true, true)
		mp.validateSignature(getDoc(simpleCSMessageWithoutSignature), true, true)
		
		then:
		true // No exception was thrown for invalid signature
		
	}
	
	def "Verify that getVersionFromMessage parses version and payload version from message"(){
		when:
		CSMessageVersion v = mp.getVersionFromMessage(simpleCSMessagePayloadVersion2_1)
		then:
		v.messageVersion == "2.0"
		v.payLoadVersion == "2.1"
	}
	
	@Unroll
	def "Verify that getVersionFromMessage throws MessageContentException for invalid message data"(){
		when:
	    mp.getVersionFromMessage(message)
		then:
		thrown MessageContentException
		where:
		message << [ simpleCSMessageWithEmptyVersion, simpleCSMessageWithEmptyPayloadVersion, simpleCSMessageWithoutVersion, simpleCSMessageWithoutPayloadVersion, invalidXML]
	}
	
	@Unroll
	def "Verify that signMessages() returns #expected for property: #property"(){
		setup:
		Properties p = new Properties()
		p.load(new StringReader(property))
		mp.properties = p
		mp.signMessages = null
		expect:
		mp.signMessages() == expected
		mp.signMessages == expected
		
		where:
		property                     | expected
		"notset="                    | true
		"csmessage.sign= tRue "      | true
		"csmessage.sign= False "     | false
		"pkimessage.sign= tRue "     | true
		"pkimessage.sign= False "    | false
	}
	
	def "Verify that signMessages() throws MessageProcessingException if missconfigured"(){
		setup:
		Properties p = new Properties()
		p.load(new StringReader("csmessage.sign= InvalidBoolean "))
		mp.properties = p
		mp.signMessages = null
		
		when:
		mp.signMessages() 

		then:
		thrown (MessageProcessingException)

	}
	
	def "Verify that getMessageNameCatalogue() generates MessageNameCatalogue correctly"(){
		setup:
		def p = new Properties();
		expect: "Verify that default Message Name Catalogue is returned by default"
		mp.getMessageNameCatalogue(p) instanceof DefaultMessageNameCatalogue
		
		when: "Generate a cusom MessageNameCatalogue and verify that initilize is called"
		p.setProperty(SETTING_MESSAGE_NAME_CATALOGUE_IMPL, TestMessageNameCatalogue.class.getName())
		TestMessageNameCatalogue tmnc = mp.getMessageNameCatalogue(p)
		then:
		tmnc.initCalled
		
		when: "Verify that MessageProcessingException is thrown if invalid classpath is configured"
		p.setProperty(SETTING_MESSAGE_NAME_CATALOGUE_IMPL, "somepkg.InvalidClass")
		mp.getMessageNameCatalogue(p)
		then:
		thrown MessageProcessingException
		
	}
	
	@Unroll
	def "Verify that requireSignature() returns #expected for property: #property"(){
		setup:
		Properties p = new Properties()
		p.load(new StringReader(property))
		mp.properties = p
		mp.requireSignature == null
		expect:
		mp.requireSignature() == expected
		mp.requireSignature == expected
		
		where:
		property                                 | expected
		"notset="                  			     | true
		"csmessage.requiresignature= tRue "      | true
		"csmessage.requiresignature= False "     | false
		"pkimessage.requiresignature= tRue "     | true
		"pkimessage.requiresignature= False "    | false
	}
	
	def "Verify that requireSignature() throws MessageProcessingException if missconfigured"(){
		setup:
		Properties p = new Properties()
		p.load(new StringReader("csmessage.requiresignature= InvalidBoolean "))
		mp.properties = p
		
		when:
		mp.requireSignature()

		then:
		thrown (MessageProcessingException)

	}
	
	def "Verify that getMessageSecurityProvider()  isnt null"(){
		expect:
		mp.getMessageSecurityProvider() != null
	}
	
	def "Verify that JAXB Related Data helper method works"(){
		setup:		
	
		mp.jaxbData.getJAXBIntrospector()
		expect: // Verify that JAXB data isn't cleaned
		mp.jaxbData.jaxbClassPath =~ "org.certificateservices.messages.csmessages.jaxb"
		mp.jaxbData.jaxbClassPath =~ ":org.certificateservices.messages.sysconfig.jaxb"
		mp.jaxbData.jaxbContext != null
		mp.jaxbData.jaxbIntrospector != null
		mp.jaxbData.csMessageMarshallers.size() != 0
		mp.jaxbData.csMessageUnmarshallers.size() != 0
		
		
		when:
		mp.jaxbData.clearAllJAXBData()
		
		then:
		mp.jaxbData.jaxbClassPath == ""
		mp.jaxbData.jaxbContext == null
		mp.jaxbData.payLoadValidatorCache.size() == 0
		mp.jaxbData.jaxbIntrospector == null
		mp.jaxbData.csMessageMarshallers.size() == 0
		mp.jaxbData.csMessageUnmarshallers.size() == 0
		
		mp.jaxbData.getJAXBContext() != null
		mp.jaxbData.getJAXBIntrospector() != null
		mp.jaxbData.getCSMessageMarshaller("2.0") != null 
		mp.jaxbData.getCSMessageUnmarshaller("2.0") != null
		mp.jaxbData.getPayLoadValidatorFromCache(SysConfigPayloadParser.NAMESPACE, "2.0", "2.0") != null
		
		mp.jaxbData.jaxbClassPath =~ "org.certificateservices.messages.csmessages.jaxb"
		mp.jaxbData.jaxbContext !=null
		mp.jaxbData.jaxbIntrospector != null
		mp.jaxbData.csMessageMarshallers.size() == 1
		mp.jaxbData.csMessageUnmarshallers.size() == 1

		when: "Try to add a dummy payload parser"
		
		PayloadParserRegistry.register(DummyPayloadParser.NAMESPACE, DummyPayloadParser.class)
		
		then: "Verify that jaxbContext is cleared after new registration"
		mp.jaxbData.jaxbContext == null
		
		when:
		mp.jaxbData.getJAXBContext() != null
		mp.jaxbData.getJAXBIntrospector() != null
		mp.jaxbData.getCSMessageMarshaller("2.0") != null
		mp.jaxbData.getCSMessageUnmarshaller("2.0") != null
		mp.jaxbData.getPayLoadValidatorFromCache(SysConfigPayloadParser.NAMESPACE, "2.0", "2.0") != null
		mp.jaxbData.getPayLoadValidatorFromCache(DummyPayloadParser.NAMESPACE, "2.0", "2.0") != null
		then:
		mp.jaxbData.jaxbClassPath =~ "org.certificateservices.messages.dummy.jaxb"
		mp.jaxbData.jaxbContext != null
		mp.jaxbData.jaxbIntrospector != null
		mp.jaxbData.csMessageMarshallers.size() == 1
		mp.jaxbData.csMessageUnmarshallers.size() == 1
		when: "Try to generate new payload with registered dummy parser"
		// Test to generate and parse new payload parser
		DummyPayloadParser dp = PayloadParserRegistry.getParser(DummyPayloadParser.NAMESPACE)
		byte[] data = mp.generateCSRequestMessage(TEST_ID, "someDest", "SomeOrg", "2.0", dp.genSomePayload("SomeValue"), null)
		CSMessage cSMessage = mp.parseMessage(data)
		SomePayload somePayload = cSMessage.getPayload().getAny()
		
		then:
		somePayload.someValue == "SomeValue"
	
		when: "Try to remove dummy parser again and check that it's not possible to parse dummy messages any more."
		PayloadParserRegistry.deregister(DummyPayloadParser.NAMESPACE)
		then: "Verify that jaxbContext is cleared after de-registration"
		mp.jaxbData.jaxbContext == null
		
		when:
		mp.jaxbData.getJAXBContext() != null
		mp.jaxbData.getJAXBIntrospector() != null
		mp.jaxbData.getCSMessageMarshaller("2.0") != null
		mp.jaxbData.getCSMessageUnmarshaller("2.0") != null
		mp.jaxbData.getPayLoadValidatorFromCache(SysConfigPayloadParser.NAMESPACE, "2.0", "2.0") != null
		then:
		mp.jaxbData.jaxbClassPath !=~ "org.certificateservices.messages.dummy.jaxb"
		mp.jaxbData.jaxbContext != null
		mp.jaxbData.jaxbIntrospector != null
		mp.jaxbData.csMessageMarshallers.size() == 1
		mp.jaxbData.csMessageUnmarshallers.size() == 1
		
		when: "Verify that parsing a message with dummy data throws MessageContentException"
		mp.parseMessage(data)
		then:
		thrown MessageContentException
	}
	
	def "Verify that setCSMessageVersion changes the version of generated requests"(){
		when:
		requestMessageParser.setCSMessageVersion("2.0")
		CSMessage request = requestMessageParser.parseMessage(requestMessageParser.generateIsApprovedRequest(TEST_ID, "somedest", "someorg", "someid", null, null));
		then:
		request.version == "2.0"
		when:
		credManagementPayloadParser.setPayloadVersion("2.0")
		request = requestMessageParser.parseMessage(credManagementPayloadParser.genGetCredentialRequest(TEST_ID,"somedest","someorg","somesubtype","someissuerid","someserialnumber",null,null))
		then:
		request.version == "2.0"

		cleanup:
		requestMessageParser.setCSMessageVersion(DefaultCSMessageParser.DEFAULT_CSMESSAGE_PROTOCOL)
	}


	@Unroll
	def "Verify that getMarshaller returns a marshaller for CS Message Version: #version"(){
		setup:
		CSMessage m = new CSMessage();
		m.version = version
		expect:
		mp.getMarshaller(m) instanceof Marshaller
		where:
		version << DefaultCSMessageParser.SUPPORTED_CSMESSAGE_VERSIONS
	}
	
	def "Test to generate a ChangeCredentialStatusRequest with two assertions, verify that validation of assertions is ok"(){
		setup:
		ResponseType ticketResp =  assertionPayloadParser.parseAttributeQueryResponse(assertionPayloadParser.genDistributedAuthorizationTicket("_123456789", "someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject",["role1", "role2"], recipients))
		JAXBElement<AssertionType> ticketAssertion = assertionPayloadParser.getAssertionFromResponseType(ticketResp)
		JAXBElement<AssertionType> approvalResp = assertionPayloadParser.parseApprovalTicket(assertionPayloadParser.genApprovalTicket("someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject","1234",["abcdef", "defcva"], null, null,null))
		def assertions = [approvalResp, ticketAssertion]
		when:
		byte[] requestData = credManagementPayloadParser.genChangeCredentialStatusRequest(TEST_ID, "somedst", "someorg", "someissuer", "123", 100, "", null, assertions)
		//printXML(requestData)
		def xml = slurpXml(requestData)
		then:
		xml.assertions.size() == 1
		xml.assertions.Assertion.size() == 2
		xml.assertions.Assertion[0].AttributeStatement.Attribute[0].AttributeValue == "APPROVAL_TICKET"
		xml.assertions.Assertion[1].AttributeStatement.Attribute[0].AttributeValue == "AUTHORIZATION_TICKET"
		
		when: "Test to parse ticket with assertion "
		CSMessage csMessage = credManagementPayloadParser.parseMessage(requestData)
		
		then:
		csMessage != null
	}

	def "Verify that parse message with require signature as false doesn't verify signature"(){
		when:
		mp.parseMessage(verifyPopulateWithFullCSMessage,true,true)
		then:
		thrown MessageContentException
		when:
		CSMessage result = mp.parseMessage(verifyPopulateWithFullCSMessage,true,false)
		then:
		result != null
		when:
		Document doc = mp.getDocumentBuilder().parse(new ByteArrayInputStream(verifyPopulateWithFullCSMessage));
		mp.parseMessage(doc,true,true)
		then:
		thrown MessageContentException
		when:
		result = mp.parseMessage(doc,true,false)
		then:
		result != null
	}

	def "Verify that invalid CS Message generates a descriptive error message"(){
		when:
		mp.parseMessage(invalidCSMessage, false,false)
		then:
		def e = thrown(MessageContentException)
		e.message == "Error parsing CS Message: cvc-complex-type.2.4.a: Invalid content was found starting with element 'cs:neme'. One of '{\"http://certificateservices.org/xsd/csmessages2_0\":name}' is expected."
	}

	def "Verify that populateOriginatorAssertionsAndSignCSMessage populates requests properly."(){
		setup:
		ResponseType ticketResp =  assertionPayloadParser.parseAttributeQueryResponse(assertionPayloadParser.genDistributedAuthorizationTicket("_123456789", "someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject",["role1", "role2"], recipients))
		JAXBElement<AssertionType> ticketAssertion = assertionPayloadParser.getAssertionFromResponseType(ticketResp)
		JAXBElement<AssertionType> approvalResp = assertionPayloadParser.parseApprovalTicket(assertionPayloadParser.genApprovalTicket("someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject","1234",["abcdef", "defcva"], null, null,null))
		def assertions = [approvalResp, ticketAssertion]
		def newOriginator = createOriginatorCredential()
		newOriginator.uniqueId = "NewOriginator"


		when: "Populate a minimal cs request and make sure all fields are set"
		CSMessage msg = mp.parseMessage(verifyPopulateWithFullCSMessage,true,false)
		byte[] populatedReq = mp.populateOriginatorAssertionsAndSignCSMessage(msg, "SomeNewDestination", newOriginator,assertions)
		CSMessage populatedMsg = mp.parseMessage(populatedReq)
		then:
		populatedMsg.destinationId == "SomeNewDestination"
		populatedMsg.originator.credential.uniqueId == "NewOriginator"
		populatedMsg.assertions.any.size() == 2
		populatedMsg.assertions.any[0].value.getID() == approvalResp.value.getID()
		populatedMsg.assertions.any[1].value.getID() == ticketAssertion.value.getID()
		// Signature is replaced becase the message parsed with required signature, original message had broken signature.
		when: "Test not populating any fields"
		populatedReq = mp.populateOriginatorAssertionsAndSignCSMessage(mp.parseMessage(verifyPopulateWithFullCSMessage,true,false), null, null,null)
		populatedMsg = mp.parseMessage(populatedReq)
		then:
		populatedMsg.destinationId != "SomeNewDestination"
		populatedMsg.originator.credential.uniqueId != "NewOriginator"
		populatedMsg.assertions.any.size() == 2
		populatedMsg.assertions.any[0].value.getID() != approvalResp.value.getID()
		populatedMsg.assertions.any[1].value.getID() != ticketAssertion.value.getID()

		when: "Test to populate minimal message"
		msg = mp.parseMessage(verifyPopulateWithMinCSMessage,true,false)
		populatedReq = mp.populateOriginatorAssertionsAndSignCSMessage(msg, "SomeNewDestination", newOriginator,assertions)
		populatedMsg = mp.parseMessage(populatedReq)
		then:
		populatedMsg.destinationId == "SomeNewDestination"
		populatedMsg.originator.credential.uniqueId == "NewOriginator"
		populatedMsg.assertions.any.size() == 2
		populatedMsg.assertions.any[0].value.getID() == approvalResp.value.getID()
		populatedMsg.assertions.any[1].value.getID() == ticketAssertion.value.getID()


	}


	private void verifyCSHeaderMessage(byte[] messageData, GPathResult xmlMessage, String expectedSourceId, String expectedDestinationId, String expectedOrganisation, String expectedName, Credential expectedOriginator){
		verifyCSHeaderMessage(messageData, xmlMessage, expectedSourceId, expectedDestinationId, expectedOrganisation, expectedName, expectedOriginator, mp)
	}
	
	private static void verifyCSHeaderMessage(byte[] messageData, GPathResult xmlMessage, String expectedSourceId, String expectedDestinationId, String expectedOrganisation, String expectedName, Credential expectedOriginator, DefaultCSMessageParser mp, boolean requireSignature=true){
		String message = new String(messageData,"UTF-8")
		assert message.contains("xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"")
		assert message.contains("xmlns:cs=\"http://certificateservices.org/xsd/csmessages2_0\"")
		assert message.contains("xsi:schemaLocation=\"http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd\"")
		
		assert DefaultCSMessageParser.SUPPORTED_CSMESSAGE_VERSIONS.find { 
			it == xmlMessage.@version.toString() 
			}
		assert xmlMessage.@ID != null
		assert xmlMessage.name == expectedName
		assert xmlMessage.sourceId == expectedSourceId
		assert xmlMessage.destinationId == expectedDestinationId
		assert xmlMessage.organisation == expectedOrganisation
		assert xmlMessage.payload != null
		assert xmlMessage.@payloadVersion != null
		assert xmlMessage.@timeStamp != null
		
		if(expectedOriginator != null){
			assert xmlMessage.originator.credential.displayName == expectedOriginator.displayName
		}
		if(requireSignature) {
			assert xmlMessage.Signature != null
			mp.validateSignature(mp.getDocumentBuilder().parse(new ByteArrayInputStream(message.getBytes())), true, true)
		}
	}
	
	static void verifySuccessfulBasePayload(GPathResult payLoadObject, String expectedResponseTo){
	  assert payLoadObject.inResponseTo == expectedResponseTo
	  assert payLoadObject.status == "SUCCESS"
	  assert payLoadObject.failureMessage.size() == 0
	}
	
	private Object createPayLoad(){
		GetActiveConfigurationRequest payLoad = sysConfigOf.createGetActiveConfigurationRequest()
		payLoad.application = "asdf"
		payLoad.organisationShortName = "SomeOrg"
		
		return payLoad
	}
	

	static Credential createOriginatorCredential(){
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
	
	private List<Object> createAssertions(){
		def as1 = assertionPayloadParser.parseApprovalTicket(assertionPayloadParser.genApprovalTicket("someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject","1234",["abcdef", "defcva"], null, null,null))
		def as2 = assertionPayloadParser.parseApprovalTicket(assertionPayloadParser.genApprovalTicket("someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject","2345",["fdasdf", "asdf"], null,null,null))
		return [as1,as2];
	}
	
	private Document getDoc(byte[] message){
		return mp.getDocumentBuilder().parse(new ByteArrayInputStream(message))
	}

	byte[] verifyPopulateWithFullCSMessage = """<?xml version="1.0" encoding="UTF-8"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:auth="http://certificateservices.org/xsd/authorization2_0" xmlns:credmanagement="http://certificateservices.org/xsd/credmanagement2_0" xmlns:csexd="http://certificateservices.org/xsd/csexport_data_1_0" xmlns:csexp="http://certificateservices.org/xsd/cs_export_protocol2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:keystoremgmt="http://certificateservices.org/xsd/keystoremgmt2_0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="2.0" timeStamp="2017-01-06T08:15:06.041+03:00" version="2.0" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd">
  <cs:name>IsApprovedRequest</cs:name>
  <cs:sourceId>SOMEREQUESTER</cs:sourceId>
  <cs:destinationId>SOMESOURCEID</cs:destinationId>
  <cs:organisation>someorg</cs:organisation>
  <cs:originator>
    <cs:credential>
      <cs:credentialRequestId>123</cs:credentialRequestId>
      <cs:uniqueId>SomeOriginatorUniqueId</cs:uniqueId>
      <cs:displayName>SomeOrignatorDisplayName</cs:displayName>
      <cs:serialNumber>SomeSerialNumber</cs:serialNumber>
      <cs:issuerId>SomeIssuerId</cs:issuerId>
      <cs:status>100</cs:status>
      <cs:credentialType>SomeCredentialType</cs:credentialType>
      <cs:credentialSubType>SomeCredentialSubType</cs:credentialSubType>
      <cs:attributes>
        <cs:attribute>
          <cs:key>someattrkey</cs:key>
          <cs:value>someattrvalue</cs:value>
        </cs:attribute>
      </cs:attributes>
      <cs:usages>
        <cs:usage>someusage</cs:usage>
      </cs:usages>
      <cs:credentialData>MTIzNDVBQkNFRg==</cs:credentialData>
      <cs:issueDate>1970-01-01T03:00:01.234+01:00</cs:issueDate>
      <cs:expireDate>1970-01-01T03:00:02.234+01:00</cs:expireDate>
      <cs:validFromDate>1970-01-01T03:00:03.234+01:00</cs:validFromDate>
    </cs:credential>
  </cs:originator>
  <cs:assertions>
    <saml:Assertion ID="_2696EAC6-DBBA-4A3B-b6ED-1B5597523690" IssueInstant="2015-07-07T17:26:53.000+03:00" Version="2.0">
      <saml:Issuer>someIssuer</saml:Issuer>
      <ds:Signature>
        <ds:SignedInfo>
          <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
          <ds:Reference URI="#_2696EAC6-DBBA-4A3B-b6ED-1B5597523690">
            <ds:Transforms>
              <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            </ds:Transforms>
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            <ds:DigestValue>H1/EMr7aVpFVwqFAVeO9C2nSiyyyrvsDPSblzvr6zHs=</ds:DigestValue>
          </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>EG0f+C95ue7FrgeRurP+CpLAYQVUWiUKF0gQODAw8FTbhvOGZ/lVHCBoADZYrPqdrxqYjK2HjctLQD59FhxK+4b/59C+C7Q1TLvwb1Hh9U+plGkNzZtNHldvpfuF2quP8OgeRXe8EPB9WSZFRrMyL0G8h4H39IS6/MUb2iuS0AJFaZv0//gfM8nNWmyMTzRCTdYcfXLzkNn/j8XK7QtgwzpdRzHjWwfjiw6PGhIXs9Tw+odx0eqb0Sdbz4nrRcbI0QoGYr9V2XZl4DYEIDyOwHM9EvMcWH8Prt/hZEZuRvk+d4z890GuI1/qfjUz5l+A8gcQw+N/p430YC8yGTFrvg==</ds:SignatureValue>
        <ds:KeyInfo>
          <ds:X509Data>
            <ds:X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBDdXN0b21lcjEgQVQgU2VydmVyQ0ExGjAYBgNVBAoMEURlbW8gQ3VzdG9tZXIxIEFUMB4XDTEyMTAxMDE0NDQwNFoXDTE0MTAxMDE0NDQwNFowKzENMAsGA1UEAwwEdGVzdDEaMBgGA1UECgwRRGVtbyBDdXN0b21lcjEgQVQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCbDqmR4e8sgxw2Afi/y3i/mT7WwtpW18/QfyUGpYPPxQ4bvPPn61y3jJg/dAbGHvnyQSHfIvrIJUN83q6evvk0bNZNVSENUEP29isE4D+KjD3PFtAzQq18P8m/8mSXMva5VTooEUSDX+VJ/6el6tnyZdc85AlIJkkkvyiDKcjhf10yllaiVCHLunGMDXAec4DapPi5GdmSMMXyPOhRx5e+oy6b5q9XmT3C29VNVFf+tkAt3ew3BoQbd+VrlBI4oRYq+mfbgkXU6dSKr9DRqhsbu5rU4Jdst2KClXsxaxvC0rVeKQ8iXCDKFH5glzhSYoeWl7CI15CdQM6/so7EisSvAgMBAAGjgeMwgeAwHQYDVR0OBBYEFLpidyp0Pc46cUpJf1neFnq/rLJBMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUgEn+Hp9+Yxe4lOhaIPmf++Wu7SYwGAYDVR0gBBEwDzANBgsrBgEEAYH1fgMDCTBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vYXQtY3JsLndtLm5ldC9kZW1vY3VzdG9tZXIxX3NlcnZlcmNhLmNybDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0RBAgwBoIEdGVzdDANBgkqhkiG9w0BAQUFAAOCAQEAZxGls/mNT4GyAf9u9lg78sSA27sc3xFvHNogrT4yUCbYAOhLXO4HJ9XuKaFyz4bKz6JGdLaQDknDI1GUvpJLpiPTXk4cq1ppHVt5/2QVeDCGtite4CH/YrAe4gufBqWo9q7XQeQbjil0mOUsSp1ErrcSadyT+KZoD4GXJBIVFcOIWKL7aCHzSLpw/+DY1sEiAbStmhz0K+UrFK+FVdZn1RIWGeVClhJklLb2vNjQgPYGdd5nKyLrlA4zekPDDWdmmxwv4A3MG8KSnl8VBU5CmAZLR1YRaioK6xL1QaH0a16FTkn3y6GVeYUGsTeyLvLlfhgAZLCP64EJEfE1mGxCJg==</ds:X509Certificate>
          </ds:X509Data>
        </ds:KeyInfo>
      </ds:Signature>
      <saml:Subject>
        <saml:NameID>SomeSubject</saml:NameID>
      </saml:Subject>
      <saml:Conditions NotBefore="2015-07-07T17:26:52.427+03:00" NotOnOrAfter="2015-07-07T17:28:32.427+03:00"/>
      <saml:AttributeStatement>
        <saml:Attribute Name="Type">
          <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">APPROVAL_TICKET</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="DestinationId">
          <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">ANY</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="ApprovalId">
          <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">1234</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="ApprovedRequests">
          <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">abcdef</saml:AttributeValue>
          <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">defcva</saml:AttributeValue>
        </saml:Attribute>
      </saml:AttributeStatement>
    </saml:Assertion>
    <saml:Assertion ID="_92F1A23B-ED97-47CC-aFDC-786BD4E9F20D" IssueInstant="2015-07-07T17:26:53.000+03:00" Version="2.0">
      <saml:Issuer>someIssuer</saml:Issuer>
      <ds:Signature>
        <ds:SignedInfo>
          <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
          <ds:Reference URI="#_92F1A23B-ED97-47CC-aFDC-786BD4E9F20D">
            <ds:Transforms>
              <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            </ds:Transforms>
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            <ds:DigestValue>rxHjM5YRZzmvWzHpvChcOPUN52+F4euZiH1w6a7DWNQ=</ds:DigestValue>
          </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>LKRUYsfgPDQLWoWGeBgLQ5ablKSUY4/JevtRSLuKdMrc3CmVL3y1f+j9/FKkxen3iYY/dsyHhBj+zVFTVEldWNg0Sz/2RPRSERTGoPcRoB5nVMWc2B2Ec7JH16NAphR2qR5ZTZZj2AknDeNEEQhwCcJtvVdmndtrWKgsOW9HLiJjsKBG0pj3TRiNEGX9Vfy4qe9AX5PwZOlA/3M1iImYu0/W74o7g2B1vGPxEtRCBp1k26uzMChQXQ01ZYgDMiOpiygCbrWCDHogZbN0A5HdhhxYnCPxsv5Fvjxz3wXL+Y4e5v0zmit0HvE+9/bQibqAwwACQjRsnpXDz6pNDsWJAQ==</ds:SignatureValue>
        <ds:KeyInfo>
          <ds:X509Data>
            <ds:X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBDdXN0b21lcjEgQVQgU2VydmVyQ0ExGjAYBgNVBAoMEURlbW8gQ3VzdG9tZXIxIEFUMB4XDTEyMTAxMDE0NDQwNFoXDTE0MTAxMDE0NDQwNFowKzENMAsGA1UEAwwEdGVzdDEaMBgGA1UECgwRRGVtbyBDdXN0b21lcjEgQVQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCbDqmR4e8sgxw2Afi/y3i/mT7WwtpW18/QfyUGpYPPxQ4bvPPn61y3jJg/dAbGHvnyQSHfIvrIJUN83q6evvk0bNZNVSENUEP29isE4D+KjD3PFtAzQq18P8m/8mSXMva5VTooEUSDX+VJ/6el6tnyZdc85AlIJkkkvyiDKcjhf10yllaiVCHLunGMDXAec4DapPi5GdmSMMXyPOhRx5e+oy6b5q9XmT3C29VNVFf+tkAt3ew3BoQbd+VrlBI4oRYq+mfbgkXU6dSKr9DRqhsbu5rU4Jdst2KClXsxaxvC0rVeKQ8iXCDKFH5glzhSYoeWl7CI15CdQM6/so7EisSvAgMBAAGjgeMwgeAwHQYDVR0OBBYEFLpidyp0Pc46cUpJf1neFnq/rLJBMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUgEn+Hp9+Yxe4lOhaIPmf++Wu7SYwGAYDVR0gBBEwDzANBgsrBgEEAYH1fgMDCTBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vYXQtY3JsLndtLm5ldC9kZW1vY3VzdG9tZXIxX3NlcnZlcmNhLmNybDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0RBAgwBoIEdGVzdDANBgkqhkiG9w0BAQUFAAOCAQEAZxGls/mNT4GyAf9u9lg78sSA27sc3xFvHNogrT4yUCbYAOhLXO4HJ9XuKaFyz4bKz6JGdLaQDknDI1GUvpJLpiPTXk4cq1ppHVt5/2QVeDCGtite4CH/YrAe4gufBqWo9q7XQeQbjil0mOUsSp1ErrcSadyT+KZoD4GXJBIVFcOIWKL7aCHzSLpw/+DY1sEiAbStmhz0K+UrFK+FVdZn1RIWGeVClhJklLb2vNjQgPYGdd5nKyLrlA4zekPDDWdmmxwv4A3MG8KSnl8VBU5CmAZLR1YRaioK6xL1QaH0a16FTkn3y6GVeYUGsTeyLvLlfhgAZLCP64EJEfE1mGxCJg==</ds:X509Certificate>
          </ds:X509Data>
        </ds:KeyInfo>
      </ds:Signature>
      <saml:Subject>
        <saml:NameID>SomeSubject</saml:NameID>
      </saml:Subject>
      <saml:Conditions NotBefore="2015-07-07T17:26:52.427+03:00" NotOnOrAfter="2015-07-07T17:28:32.427+03:00"/>
      <saml:AttributeStatement>
        <saml:Attribute Name="Type">
          <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">APPROVAL_TICKET</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="DestinationId">
          <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">ANY</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="ApprovalId">
          <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">2345</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="ApprovedRequests">
          <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">fdasdf</saml:AttributeValue>
          <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">asdf</saml:AttributeValue>
        </saml:Attribute>
      </saml:AttributeStatement>
    </saml:Assertion>
  </cs:assertions>
  <cs:payload>
    <cs:IsApprovedRequest>
      <cs:approvalId>123-212</cs:approvalId>
    </cs:IsApprovedRequest>
  </cs:payload>
  <ds:Signature>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#12345678-1234-4444-8000-123456789012">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>ygEdC6SeAFzVcQBWF7hUnWeRjvLxIj6zanXHCPANeFk=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>AFKA35h77/i7nAcAYfnxXaGcGAZ7+pQ76DJL4mfE2DT4d0/Eo0qPC23vUiD0sFoHHI0nWrHbe1DO
6ZOsiD+Pbf//pmBP/7KCsnarMuEYK6WwV2kXLnIAwPvJVsisqM6Hl2MIX75iw07csA1pMidqFySr
CDxpWs/BBGVxsf24d66fI+wp30jlEyJG3dAuas1N4RvWbzq7qiuh6XI60Vx3RIZyfVEfX/M1yNZY
Z0lgYU0xg91Y5gUP76KxSW+fhafRRtonQsblbWFbbrytPe5RFYa3Gwlz1XYmQ+ZLU1sqEkcIdubY
eNDUMScoSqeSfISfmmk7O9j0SNt3WFbYTA+Z8Q==</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
dXN0b21lcjEgQVQgU2VydmVyQ0ExGjAYBgNVBAoMEURlbW8gQ3VzdG9tZXIxIEFUMB4XDTEyMTAx
MDE0NDQwNFoXDTE0MTAxMDE0NDQwNFowKzENMAsGA1UEAwwEdGVzdDEaMBgGA1UECgwRRGVtbyBD
dXN0b21lcjEgQVQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCbDqmR4e8sgxw2Afi/
y3i/mT7WwtpW18/QfyUGpYPPxQ4bvPPn61y3jJg/dAbGHvnyQSHfIvrIJUN83q6evvk0bNZNVSEN
UEP29isE4D+KjD3PFtAzQq18P8m/8mSXMva5VTooEUSDX+VJ/6el6tnyZdc85AlIJkkkvyiDKcjh
f10yllaiVCHLunGMDXAec4DapPi5GdmSMMXyPOhRx5e+oy6b5q9XmT3C29VNVFf+tkAt3ew3BoQb
d+VrlBI4oRYq+mfbgkXU6dSKr9DRqhsbu5rU4Jdst2KClXsxaxvC0rVeKQ8iXCDKFH5glzhSYoeW
l7CI15CdQM6/so7EisSvAgMBAAGjgeMwgeAwHQYDVR0OBBYEFLpidyp0Pc46cUpJf1neFnq/rLJB
MAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUgEn+Hp9+Yxe4lOhaIPmf++Wu7SYwGAYDVR0gBBEw
DzANBgsrBgEEAYH1fgMDCTBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vYXQtY3JsLndtLm5ldC9k
ZW1vY3VzdG9tZXIxX3NlcnZlcmNhLmNybDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwDwYDVR0RBAgwBoIEdGVzdDANBgkqhkiG9w0BAQUFAAOCAQEAZxGls/mNT4GyAf9u9lg7
8sSA27sc3xFvHNogrT4yUCbYAOhLXO4HJ9XuKaFyz4bKz6JGdLaQDknDI1GUvpJLpiPTXk4cq1pp
HVt5/2QVeDCGtite4CH/YrAe4gufBqWo9q7XQeQbjil0mOUsSp1ErrcSadyT+KZoD4GXJBIVFcOI
WKL7aCHzSLpw/+DY1sEiAbStmhz0K+UrFK+FVdZn1RIWGeVClhJklLb2vNjQgPYGdd5nKyLrlA4z
ekPDDWdmmxwv4A3MG8KSnl8VBU5CmAZLR1YRaioK6xL1QaH0a16FTkn3y6GVeYUGsTeyLvLlfhgA
ZLCP64EJEfE1mGxCJg==</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>
</cs:CSMessage>""".getBytes("UTF-8")

	def verifyPopulateWithMinCSMessage = """<?xml version="1.0" encoding="UTF-8"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:auth="http://certificateservices.org/xsd/authorization2_0" xmlns:credmanagement="http://certificateservices.org/xsd/credmanagement2_0" xmlns:csexd="http://certificateservices.org/xsd/csexport_data_1_0" xmlns:csexp="http://certificateservices.org/xsd/cs_export_protocol2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:keystoremgmt="http://certificateservices.org/xsd/keystoremgmt2_0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="2.0" timeStamp="2017-01-06T08:03:25.638+03:00" version="2.0" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd">
  <cs:name>IsApprovedRequest</cs:name>
  <cs:sourceId>SOMEREQUESTER</cs:sourceId>
  <cs:destinationId>SOMESOURCEID</cs:destinationId>
  <cs:organisation>someorg</cs:organisation>
  <cs:payload>
    <cs:IsApprovedRequest>
      <cs:approvalId>123-212</cs:approvalId>
    </cs:IsApprovedRequest>
  </cs:payload>
</cs:CSMessage>
""".getBytes("UTF-8")

	def invalidCSMessage = """<?xml version="1.0" encoding="UTF-8"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:auth="http://certificateservices.org/xsd/authorization2_0" xmlns:credmanagement="http://certificateservices.org/xsd/credmanagement2_0" xmlns:csexd="http://certificateservices.org/xsd/csexport_data_1_0" xmlns:csexp="http://certificateservices.org/xsd/cs_export_protocol2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:keystoremgmt="http://certificateservices.org/xsd/keystoremgmt2_0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="2.0" timeStamp="2017-01-06T08:03:25.638+03:00" version="2.0" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd">
  <cs:neme>IsApprovedRequest</cs:neme>
  <cs:sourceId>SOMEREQUESTER</cs:sourceId>
  <cs:destinationId>SOMESOURCEID</cs:destinationId>
  <cs:organisation>someorg</cs:organisation>
  <cs:payload>
    <cs:IsApprovedRequest>
      <cs:approvalId>123-212</cs:approvalId>
    </cs:IsApprovedRequest>
  </cs:payload>
</cs:CSMessage>
""".getBytes("UTF-8")
}
