package org.certificateservices.messages.credmanagement

import org.apache.xml.security.Init
import org.apache.xml.security.utils.Base64
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Hex
import org.certificateservices.messages.MessageContentException
import org.certificateservices.messages.credmanagement.jaxb.AutomaticRenewCredentialResponse
import org.certificateservices.messages.credmanagement.jaxb.CredentialAvailableActionType
import org.certificateservices.messages.credmanagement.jaxb.CredentialAvailableActionsOperation
import org.certificateservices.messages.credmanagement.jaxb.CredentialFilter
import org.certificateservices.messages.credmanagement.jaxb.FieldValue
import org.certificateservices.messages.credmanagement.jaxb.GetTokensResponse
import org.certificateservices.messages.credmanagement.jaxb.GetUsersRequest
import org.certificateservices.messages.credmanagement.jaxb.GetUsersResponse
import org.certificateservices.messages.credmanagement.jaxb.HardTokenData
import org.certificateservices.messages.credmanagement.jaxb.Key
import org.certificateservices.messages.credmanagement.jaxb.ObjectFactory
import org.certificateservices.messages.credmanagement.jaxb.RecoverableKey
import org.certificateservices.messages.credmanagement.jaxb.TokenFilter
import org.certificateservices.messages.csmessages.CSMessageParser
import org.certificateservices.messages.csmessages.CSMessageParserManager
import org.certificateservices.messages.csmessages.CSMessageResponseData
import org.certificateservices.messages.csmessages.DefaultCSMessageParser
import org.certificateservices.messages.csmessages.PayloadParserRegistry
import org.certificateservices.messages.csmessages.constants.AvailableCredentialTypes
import org.certificateservices.messages.csmessages.jaxb.*
import org.certificateservices.messages.utils.CSMessageUtils
import org.certificateservices.messages.utils.MessageGenerateUtils
import spock.lang.Specification

import javax.xml.datatype.DatatypeFactory
import java.security.Security

import static org.certificateservices.messages.TestUtils.*
import static org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.*

class CredManagementPayloadParserSpec extends Specification {
	
	CredManagementPayloadParser pp;
	ObjectFactory of = new ObjectFactory()
	static org.certificateservices.messages.csmessages.jaxb.ObjectFactory csMessageOf = new org.certificateservices.messages.csmessages.jaxb.ObjectFactory()
	Calendar cal = Calendar.getInstance();

	DefaultCSMessageParser csMessageParser
	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Init.init()

		// Use english - make test locale independent.
		Locale.setDefault(new Locale("en", "US"))
	}


	def setup(){
		setupRegisteredPayloadParser();
		csMessageParser = CSMessageParserManager.getCSMessageParser()
		pp = PayloadParserRegistry.getParser(CredManagementPayloadParser.NAMESPACE);
	}
	
	def "Verify that JAXBPackage(), getNameSpace(), getSchemaAsInputStream(), getSupportedVersions(), getDefaultPayloadVersion() returns the correct values"(){
		expect:
		pp.getJAXBPackage() == "org.certificateservices.messages.credmanagement.jaxb"
		pp.getNameSpace() == "http://certificateservices.org/xsd/credmanagement2_0"
		pp.getSchemaAsInputStream("2.0") != null
		pp.getSchemaAsInputStream("2.1") != null
		pp.getSchemaAsInputStream("2.2") != null
		pp.getSchemaAsInputStream("2.3") != null
		pp.getDefaultPayloadVersion() == "2.3"
		pp.getSupportedVersions() == ["2.0","2.1","2.2","2.3"] as String[]
	}

	def "Verify that init using customCSMessageParser returns custom message parser with getCSMessageParser"(){
		setup:
		CredManagementPayloadParser customPP = new CredManagementPayloadParser()
		CSMessageParser customParser = Mock(CSMessageParser)
		when:
		customPP.init(null,null,customParser)
		then:
		customPP.getCSMessageParser() == customParser
	}
	
	def "Verify that genIssueTokenCredentialsRequest() generates a valid xml message and genIssueTokenCredentialsResponse() generates a valid CSMessageResponseData"(){
		
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genIssueTokenCredentialsRequest(TEST_ID, "SOMESOURCEID", "someorg", createTokenRequest(true, "1234", AutomationLevel.AUTOMATIC), null,  null, createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.IssueTokenCredentialsRequest
		
		pp.parseMessage(requestMessage) // verify that the message parses
		
		then:
		messageContainsPayload requestMessage, "credmanagement:IssueTokenCredentialsRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","IssueTokenCredentialsRequest", createOriginatorCredential(), csMessageParser)

		payloadObject.tokenRequest.user == "someuser"
		payloadObject.tokenRequest.departmentName == "SomeDepartment"
		payloadObject.tokenRequest.previousSerialNumber == "1234"
		payloadObject.tokenRequest.renewAction == "RENEW"
		payloadObject.tokenRequest.automationLevel == "AUTOMATIC"
		payloadObject.fieldValues.size() == 0
		payloadObject.hardTokenData.size() == 0
		
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		requestMessage = pp.genIssueTokenCredentialsRequest(TEST_ID, "SOMESOURCEID", "someorg", createTokenRequest(), createFieldValues(), createHardTokenData(), createOriginatorCredential(), null)
		//printXML(requestMessage)
		xml = slurpXml(requestMessage)
		payloadObject = xml.payload.IssueTokenCredentialsRequest

		then:
		messageContainsPayload requestMessage, "credmanagement:IssueTokenCredentialsRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","IssueTokenCredentialsRequest", createOriginatorCredential(), csMessageParser)

		payloadObject.tokenRequest.user == "someuser"
		payloadObject.fieldValues.fieldValue[0].key == "someKey1"
		payloadObject.fieldValues.fieldValue[1].key == "someKey2"
		payloadObject.hardTokenData.relatedCredentialIssuerId == "CN=SomeIssuerId"
		
		
		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genIssueTokenCredentialsResponse("SomeRelatedEndEntity", request,  createCredentials(100), createCredentials(160), null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.IssueTokenCredentialsResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:IssueTokenCredentialsResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, true, "IssueTokenCredentialsResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","IssueTokenCredentialsResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.tokenRequest.user == "someuser"
		payloadObject.credentials.credential[0].status == "100"
		payloadObject.revokedCredentials.credential[0].status == "160"

		expect:
		pp.parseMessage(rd.responseData)
		
		when:
		rd = pp.genIssueTokenCredentialsResponse("SomeRelatedEndEntity", request,  createCredentials(100), null, null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.IssueTokenCredentialsResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:IssueTokenCredentialsResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, true, "IssueTokenCredentialsResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","IssueTokenCredentialsResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.tokenRequest.user == "someuser"
		payloadObject.credentials.credential[0].status == "100"
		payloadObject.revokedCredentials.size() == 0

		expect:
		pp.parseMessage(rd.responseData)
		
		when:
		rd = pp.genIssueTokenCredentialsResponse("SomeRelatedEndEntity", request,  createCredentials(100), [], null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.IssueTokenCredentialsResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:IssueTokenCredentialsResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, true, "IssueTokenCredentialsResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","IssueTokenCredentialsResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.tokenRequest.user == "someuser"
		payloadObject.credentials.credential[0].status == "100"
		payloadObject.revokedCredentials.size() == 0

		expect:
		pp.parseMessage(rd.responseData)
				
		when: // Verify that a bad requests throws MessageContentException
		request = pp.parseMessage(pp.genGetCredentialRequest(TEST_ID, "SOMESOURCEID", "someorg", "someCredentialSubType","someIssuerId", "someSerialNumber",  createOriginatorCredential(), null))
		pp.genIssueTokenCredentialsResponse("SomeRelatedEndEntity", request,  createCredentials(100), [], null)
		then:
		thrown MessageContentException
	}

	def "Verify that genIssueTokenCredentialsRequest() generates a valid ver 2.1 message"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genIssueTokenCredentialsRequest(TEST_ID, "SOMESOURCEID", "someorg", createTokenRequest(), createFieldValues(), createHardTokenData(), createRecoverableKey(), createOriginatorCredential(), null)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.IssueTokenCredentialsRequest
		then:
		payloadObject.recoverableKeys.key.size() == 2
	}

	def "Verify backward compability of 2.0 messages"(){
		when:
		CSMessage msg = pp.parseMessage(ver2_0IssueTokenCredentialMessage)
		then:
		msg != null

		when: // Verify that parsing a 2.1 message with payload 2.0 version
		pp.parseMessage(invalidVersionIssueTokenCredentials_2_0)
		then:
		thrown MessageContentException
	}

	def "Verify that 2.0 CS message and 2.0 payload throws MessageContentException if TokenRequest contains department."(){
		when:
		pp.parseMessage(ver2_0IssueTokenCredentialMessageWithDepartment)
		then:
		thrown MessageContentException
	}

	def "Verify that genChangeCredentialStatusRequest() generates a valid xml message and genChangeCredentialStatusResponse() generates a valid CSMessageResponseData"(){
		setup:
		cal.set(2014, 11, 01)
		Date revokeDate = cal.getTime()
		
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genChangeCredentialStatusRequest(TEST_ID, "SOMESOURCEID", "someorg", "someIssuerId", "someSerialNumber", 100, "someReasonInformation",  createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.ChangeCredentialStatusRequest

		then:
		messageContainsPayload requestMessage, "credmanagement:ChangeCredentialStatusRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","ChangeCredentialStatusRequest", createOriginatorCredential(), csMessageParser)

		payloadObject.issuerId == "someIssuerId"
		payloadObject.newCredentialStatus == "100"
		payloadObject.serialNumber == "someSerialNumber"
		payloadObject.reasonInformation == "someReasonInformation"
		
		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genChangeCredentialStatusResponse("SomeRelatedEndEntity", request,  "someIssuerId", "someSerialNumber", 100, "someReasonInformation",revokeDate, null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.ChangeCredentialStatusResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:ChangeCredentialStatusResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, true, "ChangeCredentialStatusResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","ChangeCredentialStatusResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.issuerId == "someIssuerId"
		payloadObject.serialNumber == "someSerialNumber"
		payloadObject.credentialStatus == "100"
		payloadObject.revocationDate  =~ "2014-12-01"
		payloadObject.reasonInformation == "someReasonInformation"
		
		expect:
		pp.parseMessage(rd.responseData)

	}

	def "Verify that genChangeTokenStatusRequest() generates a valid xml message and genChangeTokenStatusResponse() generates a valid CSMessageResponseData"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genChangeTokenStatusRequest(TEST_ID, "SOMESOURCEID", "someorg", "someTokenSerial", genCredentialFilter(), 100, "someReasonInformation",  createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.ChangeTokenStatusRequest

		then:
		messageContainsPayload requestMessage, "credmanagement:ChangeTokenStatusRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","ChangeTokenStatusRequest", createOriginatorCredential(), csMessageParser)

		payloadObject.tokenSerialNumber == "someTokenSerial"
		payloadObject.credentialFilter.credentialTypeFilters.credentialTypeFilter[0].credentialType == AvailableCredentialTypes.CREDENTIAL_TYPE_X509CERTIFICATE
		payloadObject.credentialFilter.credentialTypeFilters.credentialTypeFilter[0].credentialSubType == "SomeCredSubType1"
		payloadObject.credentialFilter.credentialTypeFilters.credentialTypeFilter[1].credentialType == AvailableCredentialTypes.CREDENTIAL_TYPE_X509CERTIFICATE
		payloadObject.credentialFilter.credentialTypeFilters.credentialTypeFilter[1].credentialSubType == "SomeCredSubType2"
		payloadObject.newCredentialStatus == "100"
		payloadObject.reasonInformation == "someReasonInformation"

		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)

		CSMessageResponseData rd = pp.genChangeTokenStatusResponse("SomeRelatedEndEntity", request,createToken("someTokenSerial"), null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.ChangeTokenStatusResponse

		then:
		messageContainsPayload rd.responseData, "credmanagement:ChangeTokenStatusResponse"

		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, true, "ChangeTokenStatusResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","ChangeTokenStatusResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)

		payloadObject.token.serialNumber == "someTokenSerial"

		expect:
		pp.parseMessage(rd.responseData)

	}

	def "Verify that genChangeUserStatusRequest() generates a valid xml message and genChangeUserStatusResponse() generates a valid CSMessageResponseData"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genChangeUserStatusRequest(TEST_ID, "SOMESOURCEID", "someorg", "someUserId", genTokenFilter(), genCredentialFilter(), 100, "someReasonInformation",  createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.ChangeUserStatusRequest

		then:
		messageContainsPayload requestMessage, "credmanagement:ChangeUserStatusRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","ChangeUserStatusRequest", createOriginatorCredential(), csMessageParser)

		payloadObject.userUniqueId == "someUserId"
		payloadObject.tokenFilter.tokenTypes.tokenType[0] == "TokenType1"
		payloadObject.tokenFilter.tokenTypes.tokenType[1] == "TokenType2"
		payloadObject.credentialFilter.credentialTypeFilters.credentialTypeFilter[0].credentialType == AvailableCredentialTypes.CREDENTIAL_TYPE_X509CERTIFICATE
		payloadObject.credentialFilter.credentialTypeFilters.credentialTypeFilter[0].credentialSubType == "SomeCredSubType1"
		payloadObject.credentialFilter.credentialTypeFilters.credentialTypeFilter[1].credentialType == AvailableCredentialTypes.CREDENTIAL_TYPE_X509CERTIFICATE
		payloadObject.credentialFilter.credentialTypeFilters.credentialTypeFilter[1].credentialSubType == "SomeCredSubType2"
		payloadObject.newCredentialStatus == "100"
		payloadObject.reasonInformation == "someReasonInformation"

		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)

		CSMessageResponseData rd = pp.genChangeUserStatusResponse("SomeRelatedEndEntity", request,createUser("someUserId"), null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.ChangeUserStatusResponse

		then:
		messageContainsPayload rd.responseData, "credmanagement:ChangeUserStatusResponse"

		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, true, "ChangeUserStatusResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","ChangeUserStatusResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)

		payloadObject.user.uniqueId == "someUserId"

		expect:
		pp.parseMessage(rd.responseData)

	}

	def "Verify that genGetCredentialRequest() generates a valid xml message and genGetCredentialResponse() generates a valid CSMessageResponseData"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genGetCredentialRequest(TEST_ID, "SOMESOURCEID", "someorg", "someCredentialSubType","someIssuerId", "someSerialNumber",  createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.GetCredentialRequest

		then:
		messageContainsPayload requestMessage, "credmanagement:GetCredentialRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","GetCredentialRequest", createOriginatorCredential(), csMessageParser)

		payloadObject.issuerId == "someIssuerId"
		payloadObject.credentialSubType == "someCredentialSubType"
		payloadObject.serialNumber == "someSerialNumber"
		
		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genGetCredentialResponse("SomeRelatedEndEntity", request, createCredential(), null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.GetCredentialResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:GetCredentialResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "GetCredentialResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","GetCredentialResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.credential.displayName == "SomeDisplayName"

		expect:
		pp.parseMessage(rd.responseData)

	}
	
	def "Verify that genGetCredentialStatusListRequest() generates a valid xml message and genGetCredentialStatusListResponse() generates a valid CSMessageResponseData"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genGetCredentialStatusListRequest(TEST_ID, "SOMESOURCEID", "someorg", "someIssuerId", 123L, "someListType", createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.GetCredentialStatusListRequest

		then:
		messageContainsPayload requestMessage, "credmanagement:GetCredentialStatusListRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","GetCredentialStatusListRequest", createOriginatorCredential(), csMessageParser)

		payloadObject.issuerId == "someIssuerId"
		payloadObject.credentialStatusListType == "someListType"
		payloadObject.serialNumber == "123"
		
		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genGetCredentialStatusListResponse("SomeRelatedEndEntity", request, createCredentialStatusList(), null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.GetCredentialStatusListResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:GetCredentialStatusListResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "GetCredentialStatusListResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","GetCredentialStatusListResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.credentialStatusList.credentialStatusListType == "SomeCredentialStatusListType"

		expect:
		pp.parseMessage(rd.responseData)

	}
	
	def "Verify that genGetIssuerCredentialsRequest() generates a valid xml message and genGetIssuerCredentialsResponse() generates a valid CSMessageResponseData"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genGetIssuerCredentialsRequest(TEST_ID, "SOMESOURCEID", "someorg", "someIssuerId", createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.GetIssuerCredentialsRequest
		then:
		messageContainsPayload requestMessage, "credmanagement:GetIssuerCredentialsRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","GetIssuerCredentialsRequest", createOriginatorCredential(), csMessageParser)

		payloadObject.issuerId == "someIssuerId"
		
		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genGetIssuerCredentialsResponse("SomeRelatedEndEntity", request, createCredential(), null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.GetIssuerCredentialsResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:GetIssuerCredentialsResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "GetIssuerCredentialsResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","GetIssuerCredentialsResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.credential.displayName == "SomeDisplayName"

		expect:
		pp.parseMessage(rd.responseData)

	}
	
	def "Verify that genIsIssuerRequest() generates a valid xml message and genIsIssuerResponse() generates a valid CSMessageResponseData"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genIsIssuerRequest(TEST_ID, "SOMESOURCEID", "someorg", "someIssuerId", createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.IsIssuerRequest
		then:
		messageContainsPayload requestMessage, "credmanagement:IsIssuerRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","IsIssuerRequest", createOriginatorCredential(), csMessageParser)

		payloadObject.issuerId == "someIssuerId"
		
		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genIsIssuerResponse("SomeRelatedEndEntity", request, true, null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.IsIssuerResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:IsIssuerResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "IsIssuerResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","IsIssuerResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.isIssuer == "true"

		expect:
		pp.parseMessage(rd.responseData)

	}
	
	def "Verify that genIssueCredentialStatusListRequest() generates a valid xml message and genIssueCredentialStatusListResponse() generates a valid CSMessageResponseData"(){
		setup:
		cal.set(2014, 11, 01)
		Date notBefore = cal.getTime()
		cal.set(2015, 00, 01)
		Date notAfter = cal.getTime()
		
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genIssueCredentialStatusListRequest(TEST_ID, "SOMESOURCEID", "someorg", "someIssuerId", "someListType",true, notBefore, notAfter, createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.IssueCredentialStatusListRequest
		then:
		messageContainsPayload requestMessage, "credmanagement:IssueCredentialStatusListRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","IssueCredentialStatusListRequest", createOriginatorCredential(), csMessageParser)

		payloadObject.issuerId == "someIssuerId"
		payloadObject.credentialStatusListType == "someListType"
		payloadObject.force == "true"
		payloadObject.requestedValidFromDate =~ "2014-12-01"
		payloadObject.requestedNotAfterDate =~ "2015-01-01"
		
		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genIssueCredentialStatusListResponse("SomeRelatedEndEntity", request, createCredentialStatusList(), null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.IssueCredentialStatusListResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:IssueCredentialStatusListResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, true, "IssueCredentialStatusListResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","IssueCredentialStatusListResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.credentialStatusList.credentialStatusListType == "SomeCredentialStatusListType"
		 
		expect:
		pp.parseMessage(rd.responseData)

	}
	
	def "Verify that genIssueCredentialStatusListResponseWithoutRequest() generates a valid xml message and a valid CSMessageResponseData"(){
		when:
		CSMessageResponseData rd = pp.genIssueCredentialStatusListResponseWithoutRequest("2.0", "2.0", "SomeRelatedEndEntity", "SOMEREQUESTER", "IssueCredentialStatusListRequest", "someorg", createCredentialStatusList(), createOriginatorCredential(), null)

		//printXML(rd.responseData)
		def xml = slurpXml(rd.responseData)
		def payloadObject = xml.payload.IssueCredentialStatusListResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:IssueCredentialStatusListResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, true, "IssueCredentialStatusListResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","IssueCredentialStatusListResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, xml.@ID.toString())
		
		payloadObject.credentialStatusList.credentialStatusListType == "SomeCredentialStatusListType"
		 
		expect:
		pp.parseMessage(rd.responseData)

	}
	
	
	def "Verify that genRemoveCredentialRequest() generates a valid xml message and genRemoveCredentialResponse() generates a valid CSMessageResponseData"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genRemoveCredentialRequest(TEST_ID, "SOMESOURCEID", "someorg", "someIssuerId", "someSerialNumber",  createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.RemoveCredentialRequest
		then:
		messageContainsPayload requestMessage, "credmanagement:RemoveCredentialRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","RemoveCredentialRequest", createOriginatorCredential(), csMessageParser)

		payloadObject.issuerId == "someIssuerId"
		payloadObject.serialNumber == "someSerialNumber"
		
		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genRemoveCredentialResponse("SomeRelatedEndEntity", request, null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.RemoveCredentialResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:RemoveCredentialResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, true, "RemoveCredentialResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","RemoveCredentialResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		

		expect:
		pp.parseMessage(rd.responseData)

	}
	
	def "Verify that genFetchHardTokenDataRequest() generates a valid xml message and genFetchHardTokenDataResponse() generates a valid CSMessageResponseData"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genFetchHardTokenDataRequest(TEST_ID, "SOMESOURCEID", "someorg", "someTokenSerial", "someRelatedCredentialIssuerId", createCredential(), createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.FetchHardTokenDataRequest
		then:
		messageContainsPayload requestMessage, "credmanagement:FetchHardTokenDataRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","FetchHardTokenDataRequest", createOriginatorCredential(), csMessageParser)

		payloadObject.tokenSerial == "someTokenSerial"
		payloadObject.relatedCredentialIssuerId == "someRelatedCredentialIssuerId"
		payloadObject.adminCredential.displayName == "SomeDisplayName"
		
		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genFetchHardTokenDataResponse("SomeRelatedEndEntity", request, "someTokenSerial", "someencrypteddata".getBytes(), null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.FetchHardTokenDataResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:FetchHardTokenDataResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "FetchHardTokenDataResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","FetchHardTokenDataResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.tokenSerial == "someTokenSerial"
		new String(Base64.decode(((String)payloadObject.encryptedData))) == "someencrypteddata"
		
		expect:
		pp.parseMessage(rd.responseData)

	}

	def "Verify that genRecoverHardTokenRequest() generates a valid xml message and genRecoverHardTokenDataResponse() generates a valid CSMessageResponseData"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genRecoverHardTokenRequest(TEST_ID, "SOMESOURCEID", "someorg", "someTokenSerial", "someRelatedCredentialIssuerId", createCredential(), createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.RecoverHardTokenRequest
		then:
		messageContainsPayload requestMessage, "credmanagement:RecoverHardTokenRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","RecoverHardTokenRequest", createOriginatorCredential(), csMessageParser)

		payloadObject.tokenSerial == "someTokenSerial"
		payloadObject.relatedCredentialIssuerId == "someRelatedCredentialIssuerId"
		payloadObject.adminCredential.displayName == "SomeDisplayName"

		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)

		List keys = createKeys()
		CSMessageResponseData rd = pp.genRecoverHardTokenResponse("SomeRelatedEndEntity", request, "someTokenSerial", "someencrypteddata".getBytes(),keys,null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.RecoverHardTokenResponse

		then:
		messageContainsPayload rd.responseData, "credmanagement:RecoverHardTokenResponse"

		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "RecoverHardTokenResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","RecoverHardTokenResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)

		payloadObject.tokenSerial == "someTokenSerial"
		new String(Base64.decode(((String)payloadObject.encryptedData))) == "someencrypteddata"
		payloadObject.recoveredKeys.key[0].relatedCredential.size() == 1
		payloadObject.recoveredKeys.key[0].encryptedData.size() == 1
		payloadObject.recoveredKeys.key[1].relatedCredential.size() == 1
		payloadObject.recoveredKeys.key[1].encryptedData.size() == 1
		expect:
		pp.parseMessage(rd.responseData)

	}
	
	def "Verify that genStoreHardTokenDataRequest() generates a valid xml message and genStoreHardTokenDataResponse() generates a valid CSMessageResponseData"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genStoreHardTokenDataRequest(TEST_ID, "SOMESOURCEID", "someorg", "someTokenSerial",  "someRelatedCredentialIssuerId", "someencrypteddata".getBytes(), createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.StoreHardTokenDataRequest
		then:
		messageContainsPayload requestMessage, "credmanagement:StoreHardTokenDataRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","StoreHardTokenDataRequest", createOriginatorCredential(), csMessageParser)

		payloadObject.tokenSerial == "someTokenSerial"
		payloadObject.relatedCredentialIssuerId == "someRelatedCredentialIssuerId"
		new String(Base64.decode(((String)payloadObject.encryptedData))) == "someencrypteddata"
		
		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genStoreHardTokenDataResponse("SomeRelatedEndEntity", request, null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.StoreHardTokenDataResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:StoreHardTokenDataResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "StoreHardTokenDataResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","StoreHardTokenDataResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		expect:
		pp.parseMessage(rd.responseData)

	}
	
	
	def "Verify that genGetTokensRequest() generates a valid xml message and genGetTokensResponse() generates a valid CSMessageResponseData"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genGetTokensRequest(TEST_ID, "SOMESOURCEID", "someorg", "someserial", true, createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.GetTokensRequest
		then:
		messageContainsPayload requestMessage, "credmanagement:GetTokensRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","GetTokensRequest", createOriginatorCredential(), csMessageParser)

		payloadObject.serialNumber == "someserial"
		payloadObject.exactMatch == "true"	
		
		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.genGetTokensResponse("SomeRelatedEndEntity", request, createTokens(true), null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.GetTokensResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:GetTokensResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "GetTokensResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","GetTokensResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.tokens.token.size() == 2
		
		expect:
		pp.parseMessage(rd.responseData)

		when: // Verify to generate 2.1 messages
		csMessageParser.sourceId = "SOMEREQUESTER"
		requestMessage = pp.genGetTokensRequest(TEST_ID, "SOMESOURCEID", "someorg", "someuniqueid", true, 5,10, createOriginatorCredential(), null)
       // printXML(requestMessage)
		xml = slurpXml(requestMessage)
		payloadObject = xml.payload.GetTokensRequest

		then:
		payloadObject.serialNumber == "someuniqueid"
		payloadObject.exactMatch == "true"
		payloadObject.startIndex == 5
		payloadObject.resultSize == 10

		when:
		rd =  pp.genGetTokensResponse("SomeRelatedEndEntity", request, createTokens(), 5,19,null)
//		printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.GetTokensResponse

		then:
		payloadObject.tokens.token.size() == 2
		payloadObject.startIndex == 5
		payloadObject.totalMatching == 19


	}
		
	def "Verify that genGetUsersRequest() generates a valid xml message and genGetUsersResponse() generates a valid CSMessageResponseData"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genGetUsersRequest(TEST_ID, "SOMESOURCEID", "someorg", "someuniqueid", true, createOriginatorCredential(), null)
//        printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.GetUsersRequest
		then:
		messageContainsPayload requestMessage, "credmanagement:GetUsersRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","GetUsersRequest", createOriginatorCredential(), csMessageParser)


		payloadObject.uniqueId == "someuniqueid"
		payloadObject.exactMatch == "true"
		
		
		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		GetUsersRequest pl = CSMessageUtils.getPayload(request)
		then:
		pl.startIndex == null
		pl.resultSize == null

		when:
		CSMessageResponseData rd = pp.genGetUsersResponse("SomeRelatedEndEntity", request, createUsers(true), null)

		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.GetUsersResponse
		
		then:
		messageContainsPayload rd.responseData, "credmanagement:GetUsersResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "GetUsersResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","GetUsersResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.users.user.size() == 2
		
		expect:
		pp.parseMessage(rd.responseData)

		when: // Verify to generate 2.1 messages
		csMessageParser.sourceId = "SOMEREQUESTER"
		requestMessage = pp.genGetUsersRequest(TEST_ID, "SOMESOURCEID", "someorg", "someuniqueid", true, 5,10, createOriginatorCredential(), null)
//        printXML(requestMessage)
		xml = slurpXml(requestMessage)
		payloadObject = xml.payload.GetUsersRequest

		then:
		payloadObject.uniqueId == "someuniqueid"
		payloadObject.exactMatch == "true"
		payloadObject.startIndex == 5
		payloadObject.resultSize == 10

		when:
		rd = pp.genGetUsersResponse("SomeRelatedEndEntity", request, createUsers(), 5,19, null)
//		printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.GetUsersResponse

		then:
		payloadObject.users.user.size() == 2
		payloadObject.startIndex == 5
		payloadObject.totalMatching == 19

	}

	def "Verify that genGetCredentialAvailableActionsRequest() generates a valid xml message and genGetCredentialAvailableActionsResponse() generates a valid CSMessageResponseData"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genGetCredentialAvailableActionsRequest(TEST_ID, "SOMESOURCEID", "someorg",  "SomeIssuerId","123abc", "en", createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.GetCredentialAvailableActionsRequest
		then:
		messageContainsPayload requestMessage, "credmanagement:GetCredentialAvailableActionsRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","GetCredentialAvailableActionsRequest", createOriginatorCredential(), csMessageParser)

		payloadObject.issuerId == "SomeIssuerId"
		payloadObject.serialNumber == "123abc"
		payloadObject.locale == "en"

		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)

		CSMessageResponseData rd = pp.genGetCredentialAvailableActionsResponse("SomeRelatedEndEntity", request, genOperations(), null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.GetCredentialAvailableActionsResponse

		then:
		messageContainsPayload rd.responseData, "credmanagement:GetCredentialAvailableActionsResponse"

		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "GetCredentialAvailableActionsResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","GetCredentialAvailableActionsResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)

		payloadObject.operations.operation.size() == 2
		payloadObject.operations.operation[0].type == "ISSUE"
		payloadObject.operations.operation[0].available == "true"
		payloadObject.operations.operation[0].message == "message1"
		payloadObject.operations.operation[1].type == "RENEW"
		payloadObject.operations.operation[1].available == "false"
		payloadObject.operations.operation[1].message == "message2"

		expect:
		pp.parseMessage(rd.responseData)

	}

	def "Verify that genAutomaticRenewCredentialRequest() generates a valid xml message and genAutomaticRenewCredentialResponse() generates a valid CSMessageResponseData"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genAutomaticRenewCredentialRequest(TEST_ID, "SOMESOURCEID", "someorg",  AutomationLevel.AUTOMATIC, ["somedata1".getBytes(),"somedata2".getBytes()], createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.AutomaticRenewCredentialRequest
		then:
		messageContainsPayload requestMessage, "credmanagement:AutomaticRenewCredentialRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","AutomaticRenewCredentialRequest", createOriginatorCredential(), csMessageParser)

		payloadObject.automationLevel == "AUTOMATIC"
		payloadObject.renewalRequestData.size() == 2


		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)

		CSMessageResponseData rd = pp.genAutomaticRenewCredentialResponse("SomeRelatedEndEntity", request, getRenewedCredentials(), null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.AutomaticRenewCredentialResponse

		then:
		messageContainsPayload rd.responseData, "credmanagement:AutomaticRenewCredentialResponse"

		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "AutomaticRenewCredentialResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","AutomaticRenewCredentialResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)

		payloadObject.renewedCredential.size() == 2
		payloadObject.renewedCredential[0].originalCredentialId == "originalCredentialId1"
		payloadObject.renewedCredential[0].credential != null
		payloadObject.renewedCredential[1].originalCredentialId == "originalCredentialId2"
		payloadObject.renewedCredential[1].credential != null

		expect:
		pp.parseMessage(rd.responseData)

	}

	def "Verify that 2.0 version GetUsersRequest doesn't populate startIndex and totalMatching and that users doesn't have departmentname in response"(){
		when:
		CSMessage request = pp.parseMessage(validGetUsersRequestV2_0)
		CSMessageResponseData rd = pp.genGetUsersResponse("SomeRelatedEndEntity", request, createUsers(true), 5,17, null)
		CSMessage response = pp.parseMessage(rd.responseData)
		GetUsersResponse payload = CSMessageUtils.getPayload(response)

		then:
		response.payLoadVersion == "2.0"
		payload.startIndex == null
		payload.totalMatching == null
		payload.users.user.size() == 2
		payload.users.user.each { u ->
			u.tokens.token.each{ t ->
			   assert t.departmentName == null
			}
		}
	}

	def "Verify that 2.0 GetUsersRequest with 2.1 data throws MessageContentException"(){
		when:
		pp.parseMessage(getUsersRequestV2_0With2_1Data)
		then:
		thrown MessageContentException
	}

	def "Verify that 2.1 IssueTokenCredentials with 2.2 data throws MessageContentException"(){
		when:
		pp.parseMessage(issueTokenCredentialWithRenewandInvalidVersion,false, false)
		then:
		def e = thrown(MessageContentException)
		e.message == "Error parsing payload of CS Message: Problems occurred generating pay load schema for http://certificateservices.org/xsd/credmanagement2_0, version 2.2, error: src-resolve: Cannot resolve the name 'cs:AutomationLevel' to a(n) 'type definition' component."
	}



	def "Verify that 2.0 version GetTokensRequest doesn't populate startIndex and totalMatching that users doesn't have departmentname in response"(){
		when:
		CSMessage request = pp.parseMessage(validGetTokensRequestV2_0)
		CSMessageResponseData rd =pp.genGetTokensResponse("SomeRelatedEndEntity", request, createTokens(true), 5,18, null)
		CSMessage response = pp.parseMessage(rd.responseData)
		GetTokensResponse payload = CSMessageUtils.getPayload(response)

		then:
		response.payLoadVersion == "2.0"
		payload.startIndex == null
		payload.totalMatching == null
		payload.tokens.token.size() == 2
		payload.tokens.token.each{ t->
			assert t.departmentName == null
		}
	}

	def "Verify that 2.0 GetTokensRequest with 2.1 data throws MessageContentException"(){
		when:
		pp.parseMessage(getTokensRequestV2_0With2_1Data)
		then:
		thrown MessageContentException
	}

	def "Verify that 2.2 ChangeTokenStatusRequest with 2.3 data throws MessageContentException"(){
		when:
		pp.parseMessage(changeTokenStatusRequestV2_2_With2_3Data)
		then:
		def e = thrown MessageContentException
		e.message == "Error parsing payload of CS Message: cvc-elt.1: Cannot find the declaration of element 'credmanagement:ChangeTokenStatusRequest'."
	}


	def "Verify that genRecoverKeyRequest() generates a valid xml message and genRecoverKeyResponse() generates a valid CSMessageResponseData"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genRecoverKeyRequest(TEST_ID, "SOMESOURCEID", "someorg",  createCredential(), [createCredential(),createCredential()],createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.RecoverKeyRequest
		then:
		messageContainsPayload requestMessage, "credmanagement:RecoverKeyRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","RecoverKeyRequest", createOriginatorCredential(), csMessageParser)

		payloadObject.adminCredential.displayName == "SomeDisplayName"
		payloadObject.relatedCredentials.credential.size() == 2

		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)

		List keys = createKeys()
		CSMessageResponseData rd = pp.genRecoverKeyResponse("SomeRelatedEndEntity", request, keys,null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.RecoverKeyResponse

		then:
		messageContainsPayload rd.responseData, "credmanagement:RecoverKeyResponse"

		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "RecoverKeyResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","RecoverKeyResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)

		payloadObject.recoveredKeys.key[0].relatedCredential.size() == 1
		payloadObject.recoveredKeys.key[0].encryptedData.size() == 1
		payloadObject.recoveredKeys.key[1].relatedCredential.size() == 1
		payloadObject.recoveredKeys.key[1].encryptedData.size() == 1
		expect:
		pp.parseMessage(rd.responseData)

	}

	def "Verify that genStoreKeyRequest() generates a valid xml message and genStoreKeyResponse() generates a valid CSMessageResponseData"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genStoreKeyRequest(TEST_ID, "SOMESOURCEID", "someorg", createKeys(), createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.StoreKeyRequest
		then:
		messageContainsPayload requestMessage, "credmanagement:StoreKeyRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","StoreKeyRequest", createOriginatorCredential(), csMessageParser)

		payloadObject.recoverableKeys.key[0].relatedCredential.size() == 1
		payloadObject.recoverableKeys.key[0].encryptedData.size() == 1
		payloadObject.recoverableKeys.key[1].relatedCredential.size() == 1
		payloadObject.recoverableKeys.key[1].encryptedData.size() == 1
		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)

		CSMessageResponseData rd = pp.genStoreKeyResponse("SomeRelatedEndEntity", request,null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.StoreKeyResponse

		then:
		messageContainsPayload rd.responseData, "credmanagement:StoreKeyResponse"

		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "StoreKeyResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","StoreKeyResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)

		expect:
		pp.parseMessage(rd.responseData)

	}

	private List<User> createUsers(boolean includeDepartment = false){
		return [createUser("user1"),createUser("user2",[createToken("321", includeDepartment)])]
	}
	
	private User createUser(String id, List<Token> tokens = createTokens()){
		User user = csMessageOf.createUser()
		user.attributes = new User.Attributes()
		user.attributes.attribute.add(createAttribute("somekey", "somevalue"))
		
		user.dateCreated = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1233123L))
		user.lastUpdated  = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1243123L))
		user.uniqueId = id
		user.displayName = "User " + id
		user.status = "100"
		user.description = "some desc"
		
		user.tokens = new User.Tokens() 
		for(Token t : tokens){
			user.tokens.token.add(t)
		}
		
		return user;
	}

	
	private Token createToken(String serial, boolean includeDepartment = false){
		Token t = csMessageOf.createToken()
		
		t.attributes = new Token.Attributes()
		t.attributes.attribute.add(createAttribute("sometokenkey", "sometokenvalue"))
		
		t.credentials = new Token.Credentials()
		t.credentials.credential.addAll(createCredentials())
		
		t.dateCreated = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1253123L))
		t.lastUpdated  = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1273123L))
		
		t.expireDate = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1283123L))
		t.issueDate  = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1213123L))
		t.requestDate = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1203123L))
		t.validFromDate = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1243123L))
		
		t.serialNumber = serial
		t.status = 200
		t.tokenClass = "SomeTokenClass"
		t.tokenContainer = "SomeTokenContainer"
		t.tokenType = "SomeTokenType"

		t.departmentName = "SomeDepartmentName"
		
		return t;
	}
	
	private List<Token> createTokens(boolean includeDepartment = false){
		return [createToken("serial123"),createToken("serial124",includeDepartment)]
	}
	
	private static Attribute createAttribute(String key, String value){
		Attribute retval = csMessageOf.createAttribute();
		retval.setKey(key)
		retval.setValue(value)
		return retval
	}
	
	
	private TokenRequest createTokenRequest(boolean includeDepartment=false, String renewTokenSerial= null, AutomationLevel automationLevel = null){
		TokenRequest retval = csMessageOf.createTokenRequest()
		retval.user = "someuser";
		retval.tokenContainer = "SomeTokenContainer"
		retval.tokenType = "SomeTokenType"
		retval.tokenClass = "SomeTokenClass"
		if(includeDepartment) {
			retval.departmentName = "SomeDepartment"
		}
		if(renewTokenSerial != null) {
			retval.previousSerialNumber = renewTokenSerial
			retval.renewAction = RegenerateActionType.RENEW
		}
		if(automationLevel != null){
			retval.automationLevel = automationLevel
		}

		retval.setCredentialRequests(new TokenRequest.CredentialRequests())
		retval.getCredentialRequests().getCredentialRequest().add(createCredentialRequest())

		return retval
	}

	private static CredentialRequest createCredentialRequest(){
		CredentialRequest cr = csMessageOf.createCredentialRequest()
		cr.credentialRequestId = 123
		cr.credentialType = "SomeCredentialType"
		cr.credentialSubType = "SomeCredentialSubType"
		cr.x509RequestType = "SomeX509RequestType"
		cr.credentialRequestData = "12345ABC"
		return cr
	}

	public static Credential createCredential(int status = 100){
		Credential c = csMessageOf.createCredential();

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
		Attribute attr = createAttribute("someattrkey", "someattrvalue")
		
		c.setAttributes(new Credential.Attributes())
		c.getAttributes().getAttribute().add(attr)

		c.setUsages(new Credential.Usages())
		c.getUsages().getUsage().add("someusage")
		
		return c
	}
	
	private List<Credential> createCredentials(int status = 100){
		List<Credential> retval = [];
		retval.add(createCredential(status))

		return retval
	}
	

	
	private CredentialStatusList createCredentialStatusList(){
		CredentialStatusList retval = csMessageOf.createCredentialStatusList();
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
	
	private List<FieldValue> createFieldValues(){
		def retval = []
		FieldValue fv1 = of.createFieldValue()
		fv1.setKey("someKey1")
		fv1.setValue("someValue1")
		retval.add(fv1)
		FieldValue fv2 = of.createFieldValue()
		fv2.setKey("someKey2")
		fv2.setValue("someValue2")
		retval.add(fv2)
		
		return retval
	}

	private HardTokenData createHardTokenData(){
		def retval = new HardTokenData()
		retval.encryptedData="123".bytes
		retval.relatedCredentialIssuerId="CN=SomeIssuerId"
		return retval
	}

	private List<Key> createKeys(){
		return [pp.genKey(createCredential(),key1Data),pp.genKey(createCredential(),key2Data)]
	}

	private List<RecoverableKey> createRecoverableKey(){
		return [pp.genRecoverableKey(1,key1Data),pp.genRecoverableKey(2,key2Data)]
	}

	private List<CredentialAvailableActionsOperation> genOperations(){
		List retval = []

		CredentialAvailableActionsOperation op1 = of.createCredentialAvailableActionsOperation()
		op1.setType(CredentialAvailableActionType.ISSUE)
		op1.setMessage("message1")
		op1.available = true

		CredentialAvailableActionsOperation op2 = of.createCredentialAvailableActionsOperation()
		op2.setType(CredentialAvailableActionType.RENEW)
		op2.setMessage("message2")
		op2.available = false

		retval << op1
		retval << op2

		return retval
	}

	private List<AutomaticRenewCredentialResponse.RenewedCredential> getRenewedCredentials(){
		AutomaticRenewCredentialResponse.RenewedCredential rc1 = new AutomaticRenewCredentialResponse.RenewedCredential()
		rc1.originalCredentialId = "originalCredentialId1"
		rc1.credential = createCredential()
		AutomaticRenewCredentialResponse.RenewedCredential rc2 = new AutomaticRenewCredentialResponse.RenewedCredential()
		rc2.originalCredentialId = "originalCredentialId2"
		rc2.credential = createCredential()
		[rc1,rc2]
	}

	private TokenFilter genTokenFilter(){
		TokenFilter tokenFilter = new TokenFilter()
		tokenFilter.tokenTypes = new TokenFilter.TokenTypes()
		tokenFilter.tokenTypes.tokenType.add("TokenType1")
		tokenFilter.tokenTypes.tokenType.add("TokenType2")
		return tokenFilter
	}

	private CredentialFilter genCredentialFilter(){
		CredentialFilter credFilter = new CredentialFilter()
		credFilter.credentialTypeFilters = new CredentialFilter.CredentialTypeFilters()
		CredentialFilter.CredentialTypeFilters.CredentialTypeFilter f1 = new CredentialFilter.CredentialTypeFilters.CredentialTypeFilter()
		f1.credentialType = AvailableCredentialTypes.CREDENTIAL_TYPE_X509CERTIFICATE
		f1.credentialSubType = "SomeCredSubType1"
		CredentialFilter.CredentialTypeFilters.CredentialTypeFilter f2 = new CredentialFilter.CredentialTypeFilters.CredentialTypeFilter()
		f2.credentialType = AvailableCredentialTypes.CREDENTIAL_TYPE_X509CERTIFICATE
		f2.credentialSubType = "SomeCredSubType2"
		credFilter.credentialTypeFilters.credentialTypeFilter.add(f1)
		credFilter.credentialTypeFilters.credentialTypeFilter.add(f2)

		return credFilter
	}

	static byte[] ver2_0IssueTokenCredentialMessage = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:ae="http://certificateservices.org/xsd/autoenroll2_x" xmlns:auth="http://certificateservices.org/xsd/authorization2_0" xmlns:credmanagement="http://certificateservices.org/xsd/credmanagement2_0" xmlns:csexd="http://certificateservices.org/xsd/csexport_data_1_0" xmlns:csexp="http://certificateservices.org/xsd/cs_export_protocol2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:key="http://certificateservices.org/xsd/sensitivekeys" xmlns:keystoremgmt="http://certificateservices.org/xsd/keystoremgmt2_0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="2.0" timeStamp="2017-03-02T15:51:57.225+01:00" version="2.0" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd"><cs:name>IssueTokenCredentialsRequest</cs:name><cs:sourceId>SOMEREQUESTER</cs:sourceId><cs:destinationId>SOMESOURCEID</cs:destinationId><cs:organisation>someorg</cs:organisation><cs:originator><cs:credential><cs:credentialRequestId>123</cs:credentialRequestId><cs:uniqueId>SomeOriginatorUniqueId</cs:uniqueId><cs:displayName>SomeOrignatorDisplayName</cs:displayName><cs:serialNumber>SomeSerialNumber</cs:serialNumber><cs:issuerId>SomeIssuerId</cs:issuerId><cs:status>100</cs:status><cs:credentialType>SomeCredentialType</cs:credentialType><cs:credentialSubType>SomeCredentialSubType</cs:credentialSubType><cs:attributes><cs:attribute><cs:key>someattrkey</cs:key><cs:value>someattrvalue</cs:value></cs:attribute></cs:attributes><cs:usages><cs:usage>someusage</cs:usage></cs:usages><cs:credentialData>MTIzNDVBQkNFRg==</cs:credentialData><cs:issueDate>1970-01-01T01:00:01.234+01:00</cs:issueDate><cs:expireDate>1970-01-01T01:00:02.234+01:00</cs:expireDate><cs:validFromDate>1970-01-01T01:00:03.234+01:00</cs:validFromDate></cs:credential></cs:originator><cs:payload><credmanagement:IssueTokenCredentialsRequest><credmanagement:tokenRequest><cs:credentialRequests><cs:credentialRequest><cs:credentialRequestId>123</cs:credentialRequestId><cs:credentialType>SomeCredentialType</cs:credentialType><cs:credentialSubType>SomeCredentialSubType</cs:credentialSubType><cs:x509RequestType>SomeX509RequestType</cs:x509RequestType><cs:credentialRequestData>MTIzNDVBQkM=</cs:credentialRequestData></cs:credentialRequest></cs:credentialRequests><cs:user>someuser</cs:user><cs:tokenContainer>SomeTokenContainer</cs:tokenContainer><cs:tokenType>SomeTokenType</cs:tokenType><cs:tokenClass>SomeTokenClass</cs:tokenClass></credmanagement:tokenRequest><credmanagement:fieldValues><credmanagement:fieldValue><credmanagement:key>someKey1</credmanagement:key><credmanagement:value>someValue1</credmanagement:value></credmanagement:fieldValue><credmanagement:fieldValue><credmanagement:key>someKey2</credmanagement:key><credmanagement:value>someValue2</credmanagement:value></credmanagement:fieldValue></credmanagement:fieldValues><credmanagement:hardTokenData><credmanagement:relatedCredentialIssuerId>CN=SomeIssuerId</credmanagement:relatedCredentialIssuerId><credmanagement:encryptedData>MTIz</credmanagement:encryptedData></credmanagement:hardTokenData></credmanagement:IssueTokenCredentialsRequest></cs:payload><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#12345678-1234-4444-8000-123456789012"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>4N+Z5XCfsbvalSY8j3zug/TnHLFBEDqcOOTlmMGxAJ4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>IG6UqeRGFX0TbozQ5wAOstfQp3bqlP+t5qqOtvuSLANIX9D5kA3Y3F5g9H3WkHR4wB0pdczO9DUJ
kkOVk2CiQ/y1wsshtiAgPM3qBAGnSxvNaEWyLRM4GkgBU7eGnzBV0Hpcnug2HbO0MH3dk5cCsvXV
vKSc7XIKyAo/p+KhMdtliVG+sRfDELGiqdmhsJVbrTugdQJ+iecntSDPGJ2FzpDdvrhkCxz4eDw6
e+hjicC+4QjCQqbiyq+pd3KOEqGSv5uR4ovxoGN2BGbExFCvqYnW4B+2w8oosn3xBfyaX0uSjVcI
zPNpTGu3z5mg5AjAcXt30ZLc+q9RsHZ4tE0y5g==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
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
ZLCP64EJEfE1mGxCJg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></cs:CSMessage>""".getBytes("UTF-8")

	byte[] invalidVersionIssueTokenCredentials_2_0 = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:ae="http://certificateservices.org/xsd/autoenroll2_x" xmlns:auth="http://certificateservices.org/xsd/authorization2_0" xmlns:credmanagement="http://certificateservices.org/xsd/credmanagement2_0" xmlns:csexd="http://certificateservices.org/xsd/csexport_data_1_0" xmlns:csexp="http://certificateservices.org/xsd/cs_export_protocol2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:key="http://certificateservices.org/xsd/sensitivekeys" xmlns:keystoremgmt="http://certificateservices.org/xsd/keystoremgmt2_0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="2.0" timeStamp="2017-03-02T15:56:49.524+01:00" version="2.0" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd"><cs:name>IssueTokenCredentialsRequest</cs:name><cs:sourceId>SOMEREQUESTER</cs:sourceId><cs:destinationId>SOMESOURCEID</cs:destinationId><cs:organisation>someorg</cs:organisation><cs:originator><cs:credential><cs:credentialRequestId>123</cs:credentialRequestId><cs:uniqueId>SomeOriginatorUniqueId</cs:uniqueId><cs:displayName>SomeOrignatorDisplayName</cs:displayName><cs:serialNumber>SomeSerialNumber</cs:serialNumber><cs:issuerId>SomeIssuerId</cs:issuerId><cs:status>100</cs:status><cs:credentialType>SomeCredentialType</cs:credentialType><cs:credentialSubType>SomeCredentialSubType</cs:credentialSubType><cs:attributes><cs:attribute><cs:key>someattrkey</cs:key><cs:value>someattrvalue</cs:value></cs:attribute></cs:attributes><cs:usages><cs:usage>someusage</cs:usage></cs:usages><cs:credentialData>MTIzNDVBQkNFRg==</cs:credentialData><cs:issueDate>1970-01-01T01:00:01.234+01:00</cs:issueDate><cs:expireDate>1970-01-01T01:00:02.234+01:00</cs:expireDate><cs:validFromDate>1970-01-01T01:00:03.234+01:00</cs:validFromDate></cs:credential></cs:originator><cs:payload><credmanagement:IssueTokenCredentialsRequest><credmanagement:tokenRequest><cs:credentialRequests><cs:credentialRequest><cs:credentialRequestId>123</cs:credentialRequestId><cs:credentialType>SomeCredentialType</cs:credentialType><cs:credentialSubType>SomeCredentialSubType</cs:credentialSubType><cs:x509RequestType>SomeX509RequestType</cs:x509RequestType><cs:credentialRequestData>MTIzNDVBQkM=</cs:credentialRequestData></cs:credentialRequest></cs:credentialRequests><cs:user>someuser</cs:user><cs:tokenContainer>SomeTokenContainer</cs:tokenContainer><cs:tokenType>SomeTokenType</cs:tokenType><cs:tokenClass>SomeTokenClass</cs:tokenClass></credmanagement:tokenRequest><credmanagement:fieldValues><credmanagement:fieldValue><credmanagement:key>someKey1</credmanagement:key><credmanagement:value>someValue1</credmanagement:value></credmanagement:fieldValue><credmanagement:fieldValue><credmanagement:key>someKey2</credmanagement:key><credmanagement:value>someValue2</credmanagement:value></credmanagement:fieldValue></credmanagement:fieldValues><credmanagement:hardTokenData><credmanagement:relatedCredentialIssuerId>CN=SomeIssuerId</credmanagement:relatedCredentialIssuerId><credmanagement:encryptedData>MTIz</credmanagement:encryptedData></credmanagement:hardTokenData><credmanagement:recoverableKeys><credmanagement:key><credmanagement:relatedCredential><cs:credentialRequestId>123</cs:credentialRequestId><cs:uniqueId>SomeUniqueId</cs:uniqueId><cs:displayName>SomeDisplayName</cs:displayName><cs:serialNumber>SomeSerialNumber</cs:serialNumber><cs:issuerId>SomeIssuerId</cs:issuerId><cs:status>100</cs:status><cs:credentialType>SomeCredentialType</cs:credentialType><cs:credentialSubType>SomeCredentialSubType</cs:credentialSubType><cs:attributes><cs:attribute><cs:key>someattrkey</cs:key><cs:value>someattrvalue</cs:value></cs:attribute></cs:attributes><cs:usages><cs:usage>someusage</cs:usage></cs:usages><cs:credentialData>MTIzNDVBQkNFRg==</cs:credentialData><cs:issueDate>1970-01-01T01:00:01.234+01:00</cs:issueDate><cs:expireDate>1970-01-01T01:00:02.234+01:00</cs:expireDate><cs:validFromDate>1970-01-01T01:00:03.234+01:00</cs:validFromDate></credmanagement:relatedCredential><credmanagement:encryptedData>PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+PHhlbmM6RW5jcnlwdGVkRGF0YSB4bWxuczp4ZW5jPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyMiIFR5cGU9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI0VsZW1lbnQiPjx4ZW5jOkVuY3J5cHRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNhZXMyNTYtY2JjIi8+PGRzOktleUluZm8geG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPgo8eGVuYzpFbmNyeXB0ZWRLZXk+PHhlbmM6RW5jcnlwdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3JzYS1vYWVwLW1nZjFwIi8+PGRzOktleUluZm8+CjxkczpYNTA5RGF0YT4KPGRzOlg1MDlDZXJ0aWZpY2F0ZT4KTUlJRGNUQ0NBbG1nQXdJQkFnSUVaZjA4ZHpBTkJna3Foa2lHOXcwQkFRc0ZBREJwTVJBd0RnWURWUVFHRXdkVmJtdHViM2R1TVJBdwpEZ1lEVlFRSUV3ZFZibXR1YjNkdU1SQXdEZ1lEVlFRSEV3ZFZibXR1YjNkdU1SQXdEZ1lEVlFRS0V3ZDBaWE4wYjNKbk1SQXdEZ1lEClZRUUxFd2RWYm10dWIzZHVNUTB3Q3dZRFZRUURFd1JyWlhreE1CNFhEVEUxTURjd05qRXdORFl3TWxvWERUTTFNRE15TXpFd05EWXcKTWxvd2FURVFNQTRHQTFVRUJoTUhWVzVyYm05M2JqRVFNQTRHQTFVRUNCTUhWVzVyYm05M2JqRVFNQTRHQTFVRUJ4TUhWVzVyYm05MwpiakVRTUE0R0ExVUVDaE1IZEdWemRHOXlaekVRTUE0R0ExVUVDeE1IVlc1cmJtOTNiakVOTUFzR0ExVUVBeE1FYTJWNU1UQ0NBU0l3CkRRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFLRUZaZkVVa3FWdzNmZTlZZlB1SytYL0dkQUpndzJ6dlo4UU5ZM0oKWC9kSmpNamVmakRsWklrQU0xemFWemp4aXU5NFVoclMvQ0VMK291TFdnUmkzZHZ0T1lDc2lsa1RqbDZOUEt3UEZrVTFFZlJWT1ZuUAphSm9hcWVMTHZEY2sraU4vZisweHRPZDFZWTZ2WlppdlBlWEFPSW9uTVdwcnh6YUZVaS8vLzF0TDVRU1EwOUZVUjZFSE5QdEZrOEFqCkNHRjdqN1kxREN3YXlmWVllNWF1eVB2Uk5iSjJJa21FZW1yV2luYTh1VjZ2MmdxSWhqajNIUGU4aWRVa1Fmc2JkN0NuNTAzNkVUTGIKTklIQ0Y5TWhBUU80VnZTY211Y2FaWmNiSkFzYzZ1Si9kakNYNU9tZnFtMkU3RFdwRFFESEtMRzFmbG42NXR4SnBQYTIzV1RhNWZFQwpBd0VBQWFNaE1COHdIUVlEVlIwT0JCWUVGTTFjbjBJQlR6bnBVZTFBWEpLck9ydnNvb2ZSTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCCkFRQ1B1U0hLLzFOWCtuV2J5NjdTUkMveFlwWWVuTHF5amg2dmRyeEE4QWZxT3VacTBITm9HUG1BUWM2SFFuM2FYMUZKKzZzVmlvaGwKMVNxSTM4RjlyYUI4T3BxZzhlMHpPTkVaVjFGTnRTMlY3U3gvSUEwV2N4bnNvTXVXUmVZS3FWUit5ZmZxc2duODlxM01VV3d1RDlZeApzU1JqUHhDZUJkN2FyQWdadjcyUHJpaXF4dnZGQ0dvWHJYNVBybmc4ZXVTL2dJZURRWkJORVdDM016Ykx0eThRd01xS0ZkMCtWMmZ6CkxhUk1BcllMcDBuUzNUd0YyNEtkZ2FLdVN5QTBucTFqL1pOeWkvVG93ck5QQTRGTEUyZi8xYWtqbjNtdmdwbjYyWFFvUE8xQmZaQ3EKdXRrVUpyT3g1UDdaSXI5MWVyWFVmc1FiUERzUWtjakFpM0lQSkZBcgo8L2RzOlg1MDlDZXJ0aWZpY2F0ZT4KPC9kczpYNTA5RGF0YT4KPC9kczpLZXlJbmZvPjx4ZW5jOkNpcGhlckRhdGE+PHhlbmM6Q2lwaGVyVmFsdWU+WHFpM2J4ME5QVzN5RCtCTGxMQVA4Rm5WaXlsZkJSbS9FOEhXaURPMnl6cjVwRXpLbVZHb04rN1d5NEFnUUVYQ2FLbW03TG1uZnRFUgp6ODJwZU40L3JrZTBmU0F0NFpEbHhPZFY0TTh1L2wwNm5YQS9ROVBiSXhKNldwVGI5SS9raHhkOWZNeGVKc1VFQXhLQVAzVmF1VlllCmJKU3dJM1FNM1VSQm1BSDlCd0VZV3hsRFZxZzRIVUFGUDA4TWl2dU02SDhoR05COWxscXo0QkY2b2FKU1VFSzYrYVd0MUxib1BmY3AKTmFpaU50NmtDN2RqcUpUN0k5YVFPcllEc2QyTitEcVRGUEFpYWVEZHlzbjd0bVEvNE1RaXBFaGh6bkhQMXdveFZHbTRPQzZxSmJMNgpLekNsTVJUQmhBQnkyWDZUaFk3MlFYTTZzR09BZmxFak5DNnRldz09PC94ZW5jOkNpcGhlclZhbHVlPjwveGVuYzpDaXBoZXJEYXRhPjwveGVuYzpFbmNyeXB0ZWRLZXk+PC9kczpLZXlJbmZvPjx4ZW5jOkNpcGhlckRhdGE+PHhlbmM6Q2lwaGVyVmFsdWU+V2hNZ05xWHk5UjgwcXRzTU42TGxIdzNaZW4xbEVzYmp0MzMvdytHeHR4TCtUajEvbVBBVzlXaWh1U1NVQWN3aEJzb2htVHZsN3pJWApOc2F0S2FyYWxqN3kyZDZMRkVlWlBEVThJUHllVjZMaWI4WDhkd3NtK3NyNWVqVmR6eU8wc3JLRytmZjhraGFRMDhMNFkwdzBuRnVNCllENjBoSnBnR1FXb09XU0d2eUFiSmE4SE10bGpwT0s0dVgwUUIyb0dmNERnN1NnVVo4d0MxL09lM0JmNG8wUWpQdlFpb3FuNVBHOUwKNzN3RzE3ZnBlVGJTdm91NjVkeUhlVWExMDZ0T3p0bnJCNklLcHZaT1RleE42SmxQSmUrSVRKeVNQRTZaVzB1WldNMnBxV1VFWnpaNgpyU1o4M2ZPMmFURnR5TkhjR0pma3ZrN1RTdG9SYlZGL0lzZ1ROUU1RQTB2d0JMT2hyeHR4QUZaV1pvRnB0QitPOHNmT1JwaUNJWVNuCmU4ZlhyM1M3WU51amZuendxZEE3dE9RaVFtL2IybFpGSDNrSkpRVGxkQ0xWaDkweWhoZTlnS0pYK05hYUpZckRYc2hseDdVNXpIalMKMyt1Zk15Nk9GcVZremJHNUtaR2h2eUhONlQwK3BkMHJMTVJpNlM5ZHlJMG1wYXNDcjFpczI0ZnM4bmcwN2l6bjdNMVkyVEZWOHo5LwpNK0tQWnJ1SitkbW0zNDFCQjNLNTJSL1BZbWcwRllGRm8rMjM3dldnbjB2RTRwUTF2akZqQXozK3lTRms5YUs2TjhhcVUwQlhUOXlQCllWVGNBZGpKR1B0UlNIckI5TStRR0Q4NTlqNzJ5UURyVnYrSXRVdUsybzJYV2IrVis3enVsREJMZklwdzgrcW55U2FFOUI3ZnZ5ZVkKdDVtR0I0akVON3h2Zmdabkw5UTVrVjZJbWRkOFV6Q1lYN2NQL2d3MXZOeVNsTE5RODdVMFAxWUl1MjkzY1NycklGVXcramRISnJiQworV0g0SEhyWExYOUxKSFp6YnBoYUNXOE5VWFRPMVpWeG83TGVXajdDVWRHWS9JdDNZSDlLd2prN2RsSFhoRm5UcnU1SzZDWkEzS1JwCm01N1NwVnpUcmZBZFB3cFdydmVHd3doN0poa3loTFpvcm1lbi9mcTFXcmNoT0lVL25JSnZvLzlxWnhKb2ZQTVFQUmVJQmdrRGV0cmUKT3hoc2JvK2pHNll0U0ZtV1h0dTVacmo5Y3F1VnhjYUpkSjVvZXVuNFQwNkJ6NERCRjFIcDZmSGJnaVgyQnJHeEpXYi9ERUFBbDFveQpmY1NqVlNoK2ZrenNQbERVOXhtQ1A0NS9wZkRUaDdpaEUvRG9XbllRbGk0a25OVWtpR3V6SmFYVld5YnZqUGo5M3RjdGJDbzJtZ1gyClUrT3pVSE5jOVJsNnowM3hPbkphc1RWclBLbzU5S0hOODhqUUlXYjlGQlo3UlhoaU5UclhuNVN4WHBXb2x0bUYrbFRwN0N3Umw0UXgKNWI2NVEzelEwcCtrNFdBektMZXZGOVBab2NDT0I5NFBEMXl2L0ZKWWxpZ01ZTVhqM21KWEhJeU5UOXdVVFhVTEl6TW1oNVJwc3pLTQo5Mm5WeEk3cUNKWkNrNk9CUGVNOWNhSW1WY3BWNEpxcm00OCttTVpIWld0Ny9wYUFKNVpkRDZIa0xwV3FpeVVHSCtDYzQzb2Y2N3IxCmJveVJpTktuNWYxQXF3SEpFRDk5SWwrRVl4cStUUkwxWko1UDVpWi9qUnU5NlJOaVY3aXRITFlCL2t2STFQWU5wTFFkRFgxeFE2c0QKa043ZUV3Lzgxa0NIcjFodWY4UURLZ3FiZGcrdUZ1ZEh4TW5pSjlRL25VL0dmaElCTThuMERxbGNZWm5neG1Ld095bU11elQzSzRrRgpaR082VmJNbHVnYS9Qakp1MytXVFpOVDk0K1ZtdzNpd2FOK2R5N2RqTmhzOFVLZFRVazRJbWFyQmVVSFlCT082RTNvRU1MSlpURDl5CmhsYXNTaVVtNGZXWjViNjRjajdRZTU4Nyt4WEdjZXJjb2hLS1JaMFBRQWtyYXlHMXhBb2VKa1RiNHZDbjltMEZPL2UyWkY0Q1FvNjMKcFF4K0tXMHRuWVU5Ni8xYW5QdGFyQ0RZZll4QXZTSkQ1Q3M5WjZERHl1Q3dxTWI5YWR6ZnVFV1JrelhLVFFFck45WnIzOG1BcEREaQpzWldKeXk3Qm1xbkJUanZ4ZjVJN0kzRFUrVEhHOUloV2hZcitkaE1QR2Z5eHhXQ0prOUtUNE1nYjVDcG51M3VTR2JWQlUwcWo0R0tpCjNSb1o5Zm1wcXc1a2FVR2FUY0pWQjZ1aEZPK0R6SFpNaGJ4ZnZmTkNwNmVOTVhQOUVIekpJeXNUdDF4OGFhY1ZIeENGRDFxTGZHUEoKZjlNY2FJVElwS3lKVExjQ2wwQXM1QnlsSTJ6bldia25BNGFINXU4L3dWVG1Ib3N2SXZxZXBNVTRQTU1ORGdHS2lyUVFWY2ovdU1NbwpbMTA5LCA0MywgMTAxLCA2NSwgMTIwLCA5OCwgNDksIDEyMiwgOTksIDEwMiwgNzYsIDUwLCA4MCwgMTA3LCA2NiwgMTAzLCAxMTAsIDEyMiwgMTAzLCAxMTIsIDgzLCAxMDMsIDEwOSwgMTEwLCA3MiwgNzQsIDEwNSwgMTIwLCA1NiwgODEsIDExMCwgNTAsIDEwNywgMTEyLCA4NCwgNDcsIDg0LCA3NSwgNTcsIDEyMCwgODcsIDU0LCA2OCwgNDcsIDg5LCAxMTYsIDEyMSwgMTE4LCA2OSwgMTA4LCA1MSwgOTcsIDEyMiwgMTE4LCA0MywgODksIDgxLCAxMTQsIDEwOSwgMTE4LCA1NiwgMTA0LCA3NywgNjEsIDYwLCA0NywgMTIwLCAxMDEsIDExMCwgOTksIDU4LCA2NywgMTA1LCAxMTIsIDEwNCwgMTAxLCAxMTQsIDg2LCA5NywgMTA4LCAxMTcsIDEwMSwgNjIsIDYwLCA0NywgMTIwLCAxMDEsIDExMCwgOTksIDU4LCA2NywgMTA1LCAxMTIsIDEwNCwgMTAxLCAxMTQsIDY4LCA5NywgMTE2LCA5NywgNjIsIDYwLCA0NywgMTIwLCAxMDEsIDExMCwgOTksIDU4LCA2OSwgMTEwLCA5OSwgMTE0LCAxMjEsIDExMiwgMTE2LCAxMDEsIDEwMCwgNjgsIDk3LCAxMTYsIDk3LCA2Ml0=</credmanagement:encryptedData></credmanagement:key><credmanagement:key><credmanagement:relatedCredential><cs:credentialRequestId>123</cs:credentialRequestId><cs:uniqueId>SomeUniqueId</cs:uniqueId><cs:displayName>SomeDisplayName</cs:displayName><cs:serialNumber>SomeSerialNumber</cs:serialNumber><cs:issuerId>SomeIssuerId</cs:issuerId><cs:status>100</cs:status><cs:credentialType>SomeCredentialType</cs:credentialType><cs:credentialSubType>SomeCredentialSubType</cs:credentialSubType><cs:attributes><cs:attribute><cs:key>someattrkey</cs:key><cs:value>someattrvalue</cs:value></cs:attribute></cs:attributes><cs:usages><cs:usage>someusage</cs:usage></cs:usages><cs:credentialData>MTIzNDVBQkNFRg==</cs:credentialData><cs:issueDate>1970-01-01T01:00:01.234+01:00</cs:issueDate><cs:expireDate>1970-01-01T01:00:02.234+01:00</cs:expireDate><cs:validFromDate>1970-01-01T01:00:03.234+01:00</cs:validFromDate></credmanagement:relatedCredential><credmanagement:encryptedData>PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+PHhlbmM6RW5jcnlwdGVkRGF0YSB4bWxuczp4ZW5jPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyMiIFR5cGU9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI0VsZW1lbnQiPjx4ZW5jOkVuY3J5cHRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNhZXMyNTYtY2JjIi8+PGRzOktleUluZm8geG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPgo8eGVuYzpFbmNyeXB0ZWRLZXk+PHhlbmM6RW5jcnlwdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3JzYS1vYWVwLW1nZjFwIi8+PGRzOktleUluZm8+CjxkczpYNTA5RGF0YT4KPGRzOlg1MDlDZXJ0aWZpY2F0ZT4KTUlJRGNUQ0NBbG1nQXdJQkFnSUVaZjA4ZHpBTkJna3Foa2lHOXcwQkFRc0ZBREJwTVJBd0RnWURWUVFHRXdkVmJtdHViM2R1TVJBdwpEZ1lEVlFRSUV3ZFZibXR1YjNkdU1SQXdEZ1lEVlFRSEV3ZFZibXR1YjNkdU1SQXdEZ1lEVlFRS0V3ZDBaWE4wYjNKbk1SQXdEZ1lEClZRUUxFd2RWYm10dWIzZHVNUTB3Q3dZRFZRUURFd1JyWlhreE1CNFhEVEUxTURjd05qRXdORFl3TWxvWERUTTFNRE15TXpFd05EWXcKTWxvd2FURVFNQTRHQTFVRUJoTUhWVzVyYm05M2JqRVFNQTRHQTFVRUNCTUhWVzVyYm05M2JqRVFNQTRHQTFVRUJ4TUhWVzVyYm05MwpiakVRTUE0R0ExVUVDaE1IZEdWemRHOXlaekVRTUE0R0ExVUVDeE1IVlc1cmJtOTNiakVOTUFzR0ExVUVBeE1FYTJWNU1UQ0NBU0l3CkRRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFLRUZaZkVVa3FWdzNmZTlZZlB1SytYL0dkQUpndzJ6dlo4UU5ZM0oKWC9kSmpNamVmakRsWklrQU0xemFWemp4aXU5NFVoclMvQ0VMK291TFdnUmkzZHZ0T1lDc2lsa1RqbDZOUEt3UEZrVTFFZlJWT1ZuUAphSm9hcWVMTHZEY2sraU4vZisweHRPZDFZWTZ2WlppdlBlWEFPSW9uTVdwcnh6YUZVaS8vLzF0TDVRU1EwOUZVUjZFSE5QdEZrOEFqCkNHRjdqN1kxREN3YXlmWVllNWF1eVB2Uk5iSjJJa21FZW1yV2luYTh1VjZ2MmdxSWhqajNIUGU4aWRVa1Fmc2JkN0NuNTAzNkVUTGIKTklIQ0Y5TWhBUU80VnZTY211Y2FaWmNiSkFzYzZ1Si9kakNYNU9tZnFtMkU3RFdwRFFESEtMRzFmbG42NXR4SnBQYTIzV1RhNWZFQwpBd0VBQWFNaE1COHdIUVlEVlIwT0JCWUVGTTFjbjBJQlR6bnBVZTFBWEpLck9ydnNvb2ZSTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCCkFRQ1B1U0hLLzFOWCtuV2J5NjdTUkMveFlwWWVuTHF5amg2dmRyeEE4QWZxT3VacTBITm9HUG1BUWM2SFFuM2FYMUZKKzZzVmlvaGwKMVNxSTM4RjlyYUI4T3BxZzhlMHpPTkVaVjFGTnRTMlY3U3gvSUEwV2N4bnNvTXVXUmVZS3FWUit5ZmZxc2duODlxM01VV3d1RDlZeApzU1JqUHhDZUJkN2FyQWdadjcyUHJpaXF4dnZGQ0dvWHJYNVBybmc4ZXVTL2dJZURRWkJORVdDM016Ykx0eThRd01xS0ZkMCtWMmZ6CkxhUk1BcllMcDBuUzNUd0YyNEtkZ2FLdVN5QTBucTFqL1pOeWkvVG93ck5QQTRGTEUyZi8xYWtqbjNtdmdwbjYyWFFvUE8xQmZaQ3EKdXRrVUpyT3g1UDdaSXI5MWVyWFVmc1FiUERzUWtjakFpM0lQSkZBcgo8L2RzOlg1MDlDZXJ0aWZpY2F0ZT4KPC9kczpYNTA5RGF0YT4KPC9kczpLZXlJbmZvPjx4ZW5jOkNpcGhlckRhdGE+PHhlbmM6Q2lwaGVyVmFsdWU+SlVVaWpFZWhpaG9mQmNUMTFaVWZtdGx5a3puTERzbzhhR3VCbWVoanFxb1hlTExDQ2dMOFl2SUtwMWNCQVBmcDV0Y2NWWUFnVTgwdAo1Qk5lUFZucDYyc2JCVUNzcjNQWkx0Y1BubzJaaUhMWHdhRlBoVWNPbkRaeDdBRC9CWE9PTk1JNXlhRXFiL2ROYnJQNFlRVVVrVVhTCndxemRKdmZ4bDdhdXc2T0pua2ZwUU9McnhEUStPWXVlS0JzVDVnc3J6U2NJb0VJR01nMjVVc0hpVS8xaUU0cGJMR0Q1ckJEek05c3YKSloydmV5Y00wLzlvNDFXbVhWTXhoeUVLU0RXWG5nOUF4Z0NZSFhRUEtFT0J0U0xlb2ZneFQyRGh4V2lQUXU0dHhrNWU4SkVJM1JYTApBN1RmZ25HbWc4MHpMc29IYkdCclBscnRZeVJEWUtZaEhoTXJwUT09PC94ZW5jOkNpcGhlclZhbHVlPjwveGVuYzpDaXBoZXJEYXRhPjwveGVuYzpFbmNyeXB0ZWRLZXk+PC9kczpLZXlJbmZvPjx4ZW5jOkNpcGhlckRhdGE+PHhlbmM6Q2lwaGVyVmFsdWU+TmJyaVBXK3JDNnJqVHc0cW4wZWpuQTd6ckdRYnVQSWF1SUhQWGMxT3JoVUZNZ0x2aHpESzNpOGhZVkdYWWticTdBL1JGNVNwM2grbApyMDY4L2pyM2pLamRIdEVsa1lWZ29HdWdLTStqTjFKcUJ5eDlBcFNSem1DR1M2Z1ZQWTdqL3VDYzgwWEZCL3FCWndpcVcvdGZ1YWVVCm52ZnRnbXdYbUhHNW9vQ0xKcDAvbEFIMVdSN2lLTVZmRURzQW5aUjZJNnVWMExyK2hlSFdqMWh3aWl5NHI1SHlaQnE0UW96c0tubEsKemdkVHZYdC80RFVHN20rc0hEZEo3dGxDU0YvSEN2MFNvenNWZVI5bGduWmtMVE85bTJ4WGE3UUxEZnpCNjVlUWlkbTEyYjhpdUIvQgpUNU52Q1kzUDRpZUVJalRDSlBDUUgwY0RtUTVXOHZwUXBlNy84aUwvd2ROQ3JWTVdXeG1nZlJJd1UzM1hqLzBuY1NUSDdvY21sc0lBCnI3eVJ0QWNUNGhJM2xSeVdZbnB6eHk4WVcrbXBLcU54ZEpkVm9vRGUrYi9ZWXM1SFQrbTkxNFNTc00zN1Vlb1ZtZk5uRndPeThnd04KVnFNMGV0TE5zbkx2anJTOU9NV3JabG5jMy9UWEhvcEhrL2ZIUG9pQVc1c1QvMnpJMGdyYWVTaWh1Unhyb2VVclRXbE1rV215ano5dgptci93amxiUmdRWEhEQXdxRXlaZUpGQUZMc1NGTnN2eGE2VEtTanIrVUVBRUM1SWdYaVl1ZmxGTWd2aGZ0d2l1bXhManZnSWN1ZW9mCmxhYTVUNmxLU1YweW1zaTQyR25BK1FYNzZTcUZWcEE2Q1Q3YlVOY29MTHVkMDlabG80MUJzTmJLUWhBSkRmMkx6ZlFUeTQ5NkVndUIKbGRQV3QwcEdmTE5peW01MDA1bVA3akZyVm5zNGtrVG5MTFVlZ2d5Y1I0VlhaUktDV2ZQM0dIMENZOU9DbU9DTVc4eXNad29WN3NNVAptNEVEbktPWGFIY0UwcjVDM0QydFU1enRJcEx1UlIyVENXN25jdDN6a044bTN6ajBhQW1YRDhHbmNKRElPK0lGUS8wMDZDbjdGc2tqClBpdldMWkNjem04UmFxWFgwb1ZXSFFLNGpxL1BOcG9RZStreG1hZkg5K051WkxTR0FwTThLYlNxeVhZT3EyYURITTZQL2tBSDBTNGMKbER0amEzK2ZsMkY2bThlWWlJQ2NrbDVjNlVDbU45SHVwbTNiZkpDWFh1aVRhS1RuaHpvb29tb1NqUU83WkVWd2hmY0RRbjZETFNYdApJWWZ5Q21qNUVOREJ3M0I2Yyt0VmVkQTR4MVVIdFp2a0d4SEgzQUphZDNVOHNueHR0eDFTY0dEYngrZVRpaVErZjBJcTYvelpCaytNCjMrK3FSbXJJc3ZUU0FNRGllUTlyWjdnbWNHSHVmVjBZUFZQRkVhVHdzcnVhV0RYWVNRWXp5eUNqUWtDZGtUNnJ5SlN3TVVtN1B5YU0KMk9Oc3dPalBEbzQyb1l3WURFSW1XajhwN3IxUm8zU2Zta3hnS0ZkNk9PRE1oNi9WZzdsbVBpR3gyK09pQ3Z1UHhvZEVPYjgvY0tvMApvbXNMUmJZV3Q0RzBXSXJ3UUEvVFowblRqNUZFTmZOb1ZnWUR2a0NWM1l2OHphSEh3NEM3NUhPMnJZaTdQOWtqNUIyVyt0Z1NPL3ovClk4OERobTlrRU5jSmVhOEY3T0JzVTBNWGhicnk5ZmRaUlVrNGVMNjdxSHA4WTBHQXhtdFEzNkQ3cVJ0ck9DcTFYOHZsM3BudVVjeDAKdmczcGFBMHIzd01DYnY5bU44bm9TU0E5SmFEaXhNQ0JhNllHaXBXS0dtTXliR2NYN2UzaUo3cWs1QnNtcFg1VGJkLy8rU3V6NnBMMQppb3JpcmZzNEpvMWdXYW82QlBzeFdvYnNqRWdhUnUvbGVSZ3RaL1lEYVNCNGk5TjkwU0I2L3Y3b0V2U0F1QkJrQlVNZlNPbVQ1WWRKCk01R1prWDAxUnpKbDhlZE90TkprVUd0ZnY0MldUV1ZTRXplcjRTZVkvQXFGTmRZakd2bFkreXFsQVdXSVJYT3RYY0Rlc0tWVDUvMzcKMnVTRlpqbURMWVNITXVRR3lVN2NrODJITVdkdVZyQ3B0WWdyWXp6bGpQRjU0RXJ6aFdkbHN3ZFQvUzJpYmE5ZHlMcFdRa2ZBY0pYdgpxVW82bGZEb0VkUVVYMmQraERJRk40MWR0WUcvTjIyWm5lbWNXQjlEakYyMkFTVnY0aVUzY0JDTm5NQndOdGtkVTlPcW5xbkVXWkJvCmkwMHQzOXZEVStrOWEyTGpyb1VVWXlSTlhiYi8vWnYwZXNKKzdUZFNTOWhtUHlOVk5ZMFFHMXZmeHUyUWR3TUkvMVB2Q3JLNStQT08KQXYxb0lQa3hEZGdhN3A2bnhzcld5VkwxcllqNjcwRkhpTitXckp0OUVEZ1E3bFZuSHVJbTUzbDAyeTVxR2IrNnpiRDliMmwyYzkrUQpbNzMsIDgzLCA0OCwgODcsIDc0LCAxMTYsIDExNCwgNjcsIDU0LCA4OCwgODMsIDEwOSwgNjgsIDQ5LCAxMjAsIDEyMSwgMTA5LCA4MSwgMTA4LCA4MSwgNTQsIDUzLCAxMTQsIDgyLCA4OSwgOTksIDExNCwgMTIwLCA3MiwgODUsIDgyLCA1NSwgODYsIDg1LCAxMTAsIDc4LCA0OCwgMTE1LCA5NywgMTIwLCA3NiwgNTYsIDEwNCwgNjksIDEwOCwgODMsIDEwOCwgODEsIDEwNCwgNTAsIDkwLCAxMTAsIDExNywgMTExLCA4MSwgMTEyLCA2OCwgNjksIDEwNiwgNTMsIDY4LCAxMDksIDc3LCA2MSwgNjAsIDQ3LCAxMjAsIDEwMSwgMTEwLCA5OSwgNTgsIDY3LCAxMDUsIDExMiwgMTA0LCAxMDEsIDExNCwgODYsIDk3LCAxMDgsIDExNywgMTAxLCA2MiwgNjAsIDQ3LCAxMjAsIDEwMSwgMTEwLCA5OSwgNTgsIDY3LCAxMDUsIDExMiwgMTA0LCAxMDEsIDExNCwgNjgsIDk3LCAxMTYsIDk3LCA2MiwgNjAsIDQ3LCAxMjAsIDEwMSwgMTEwLCA5OSwgNTgsIDY5LCAxMTAsIDk5LCAxMTQsIDEyMSwgMTEyLCAxMTYsIDEwMSwgMTAwLCA2OCwgOTcsIDExNiwgOTcsIDYyXQ==</credmanagement:encryptedData></credmanagement:key></credmanagement:recoverableKeys></credmanagement:IssueTokenCredentialsRequest></cs:payload><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#12345678-1234-4444-8000-123456789012"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>ZegeBKq8gU+afipUU9OQLC5dqpDzClEcxZmlw0wKMBM=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>E8nLeQeNhLLpl1pPhCO7PQw1c2vQ5SFlRAG1AJL/7wu0vIfFb+mneiTAS1eTqc+u0oBxdq4ubESm
viIj2G1Sjk7V/6RWVg9BQtCO8V3dkK37g9ES1kytDQVnKjd/d6urToB5JvkYs3dmwy3UMokJ+fAp
1gYq71EaJvAt5XRsi3oGEFZisgRvV++YjU7+mBK4zNTFShwSJ3eujD18+N/0g+OxI7wsUg7Q1XA1
OXI59ZYkzXOGz567eniddFrvlEVxCRVY3kMH+AefzTSNsXi1FObz+YueNSLUzSm+uWldoqectG5Z
xGVTKNZFMzQFK3FMg4y1mkd8HmdPz6qBVJLvQw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
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
ZLCP64EJEfE1mGxCJg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></cs:CSMessage>""".getBytes("UTF-8")

	byte[] key1Data = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"/><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
			"<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"/><ds:KeyInfo>\n" +
			"<ds:X509Data>\n" +
			"<ds:X509Certificate>\n" +
			"MIIDcTCCAlmgAwIBAgIEZf08dzANBgkqhkiG9w0BAQsFADBpMRAwDgYDVQQGEwdVbmtub3duMRAw\n" +
			"DgYDVQQIEwdVbmtub3duMRAwDgYDVQQHEwdVbmtub3duMRAwDgYDVQQKEwd0ZXN0b3JnMRAwDgYD\n" +
			"VQQLEwdVbmtub3duMQ0wCwYDVQQDEwRrZXkxMB4XDTE1MDcwNjEwNDYwMloXDTM1MDMyMzEwNDYw\n" +
			"MlowaTEQMA4GA1UEBhMHVW5rbm93bjEQMA4GA1UECBMHVW5rbm93bjEQMA4GA1UEBxMHVW5rbm93\n" +
			"bjEQMA4GA1UEChMHdGVzdG9yZzEQMA4GA1UECxMHVW5rbm93bjENMAsGA1UEAxMEa2V5MTCCASIw\n" +
			"DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKEFZfEUkqVw3fe9YfPuK+X/GdAJgw2zvZ8QNY3J\n" +
			"X/dJjMjefjDlZIkAM1zaVzjxiu94UhrS/CEL+ouLWgRi3dvtOYCsilkTjl6NPKwPFkU1EfRVOVnP\n" +
			"aJoaqeLLvDck+iN/f+0xtOd1YY6vZZivPeXAOIonMWprxzaFUi///1tL5QSQ09FUR6EHNPtFk8Aj\n" +
			"CGF7j7Y1DCwayfYYe5auyPvRNbJ2IkmEemrWina8uV6v2gqIhjj3HPe8idUkQfsbd7Cn5036ETLb\n" +
			"NIHCF9MhAQO4VvScmucaZZcbJAsc6uJ/djCX5Omfqm2E7DWpDQDHKLG1fln65txJpPa23WTa5fEC\n" +
			"AwEAAaMhMB8wHQYDVR0OBBYEFM1cn0IBTznpUe1AXJKrOrvsoofRMA0GCSqGSIb3DQEBCwUAA4IB\n" +
			"AQCPuSHK/1NX+nWby67SRC/xYpYenLqyjh6vdrxA8AfqOuZq0HNoGPmAQc6HQn3aX1FJ+6sViohl\n" +
			"1SqI38F9raB8Opqg8e0zONEZV1FNtS2V7Sx/IA0WcxnsoMuWReYKqVR+yffqsgn89q3MUWwuD9Yx\n" +
			"sSRjPxCeBd7arAgZv72PriiqxvvFCGoXrX5Prng8euS/gIeDQZBNEWC3MzbLty8QwMqKFd0+V2fz\n" +
			"LaRMArYLp0nS3TwF24KdgaKuSyA0nq1j/ZNyi/TowrNPA4FLE2f/1akjn3mvgpn62XQoPO1BfZCq\n" +
			"utkUJrOx5P7ZIr91erXUfsQbPDsQkcjAi3IPJFAr\n" +
			"</ds:X509Certificate>\n" +
			"</ds:X509Data>\n" +
			"</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>Xqi3bx0NPW3yD+BLlLAP8FnViylfBRm/E8HWiDO2yzr5pEzKmVGoN+7Wy4AgQEXCaKmm7LmnftER\n" +
			"z82peN4/rke0fSAt4ZDlxOdV4M8u/l06nXA/Q9PbIxJ6WpTb9I/khxd9fMxeJsUEAxKAP3VauVYe\n" +
			"bJSwI3QM3URBmAH9BwEYWxlDVqg4HUAFP08MivuM6H8hGNB9llqz4BF6oaJSUEK6+aWt1LboPfcp\n" +
			"NaiiNt6kC7djqJT7I9aQOrYDsd2N+DqTFPAiaeDdysn7tmQ/4MQipEhhznHP1woxVGm4OC6qJbL6\n" +
			"KzClMRTBhABy2X6ThY72QXM6sGOAflEjNC6tew==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>WhMgNqXy9R80qtsMN6LlHw3Zen1lEsbjt33/w+GxtxL+Tj1/mPAW9WihuSSUAcwhBsohmTvl7zIX\n" +
			"NsatKaralj7y2d6LFEeZPDU8IPyeV6Lib8X8dwsm+sr5ejVdzyO0srKG+ff8khaQ08L4Y0w0nFuM\n" +
			"YD60hJpgGQWoOWSGvyAbJa8HMtljpOK4uX0QB2oGf4Dg7SgUZ8wC1/Oe3Bf4o0QjPvQioqn5PG9L\n" +
			"73wG17fpeTbSvou65dyHeUa106tOztnrB6IKpvZOTexN6JlPJe+ITJySPE6ZW0uZWM2pqWUEZzZ6\n" +
			"rSZ83fO2aTFtyNHcGJfkvk7TStoRbVF/IsgTNQMQA0vwBLOhrxtxAFZWZoFptB+O8sfORpiCIYSn\n" +
			"e8fXr3S7YNujfnzwqdA7tOQiQm/b2lZFH3kJJQTldCLVh90yhhe9gKJX+NaaJYrDXshlx7U5zHjS\n" +
			"3+ufMy6OFqVkzbG5KZGhvyHN6T0+pd0rLMRi6S9dyI0mpasCr1is24fs8ng07izn7M1Y2TFV8z9/\n" +
			"M+KPZruJ+dmm341BB3K52R/PYmg0FYFFo+237vWgn0vE4pQ1vjFjAz3+ySFk9aK6N8aqU0BXT9yP\n" +
			"YVTcAdjJGPtRSHrB9M+QGD859j72yQDrVv+ItUuK2o2XWb+V+7zulDBLfIpw8+qnySaE9B7fvyeY\n" +
			"t5mGB4jEN7xvfgZnL9Q5kV6Imdd8UzCYX7cP/gw1vNySlLNQ87U0P1YIu293cSrrIFUw+jdHJrbC\n" +
			"+WH4HHrXLX9LJHZzbphaCW8NUXTO1ZVxo7LeWj7CUdGY/It3YH9Kwjk7dlHXhFnTru5K6CZA3KRp\n" +
			"m57SpVzTrfAdPwpWrveGwwh7JhkyhLZormen/fq1WrchOIU/nIJvo/9qZxJofPMQPReIBgkDetre\n" +
			"Oxhsbo+jG6YtSFmWXtu5Zrj9cquVxcaJdJ5oeun4T06Bz4DBF1Hp6fHbgiX2BrGxJWb/DEAAl1oy\n" +
			"fcSjVSh+fkzsPlDU9xmCP45/pfDTh7ihE/DoWnYQli4knNUkiGuzJaXVWybvjPj93tctbCo2mgX2\n" +
			"U+OzUHNc9Rl6z03xOnJasTVrPKo59KHN88jQIWb9FBZ7RXhiNTrXn5SxXpWoltmF+lTp7CwRl4Qx\n" +
			"5b65Q3zQ0p+k4WAzKLevF9PZocCOB94PD1yv/FJYligMYMXj3mJXHIyNT9wUTXULIzMmh5RpszKM\n" +
			"92nVxI7qCJZCk6OBPeM9caImVcpV4Jqrm48+mMZHZWt7/paAJ5ZdD6HkLpWqiyUGH+Cc43of67r1\n" +
			"boyRiNKn5f1AqwHJED99Il+EYxq+TRL1ZJ5P5iZ/jRu96RNiV7itHLYB/kvI1PYNpLQdDX1xQ6sD\n" +
			"kN7eEw/81kCHr1huf8QDKgqbdg+uFudHxMniJ9Q/nU/GfhIBM8n0DqlcYZngxmKwOymMuzT3K4kF\n" +
			"ZGO6VbMluga/PjJu3+WTZNT94+Vmw3iwaN+dy7djNhs8UKdTUk4ImarBeUHYBOO6E3oEMLJZTD9y\n" +
			"hlasSiUm4fWZ5b64cj7Qe587+xXGcercohKKRZ0PQAkrayG1xAoeJkTb4vCn9m0FO/e2ZF4CQo63\n" +
			"pQx+KW0tnYU96/1anPtarCDYfYxAvSJD5Cs9Z6DDyuCwqMb9adzfuEWRkzXKTQErN9Zr38mApDDi\n" +
			"sZWJyy7BmqnBTjvxf5I7I3DU+THG9IhWhYr+dhMPGfyxxWCJk9KT4Mgb5Cpnu3uSGbVBU0qj4GKi\n" +
			"3RoZ9fmpqw5kaUGaTcJVB6uhFO+DzHZMhbxfvfNCp6eNMXP9EHzJIysTt1x8aacVHxCFD1qLfGPJ\n" +
			"f9McaITIpKyJTLcCl0As5BylI2znWbknA4aH5u8/wVTmHosvIvqepMU4PMMNDgGKirQQVcj/uMMo\n" +
			"m+eAxb1zcfL2PkBgnzgpSgmnHJix8Qn2kpT/TK9xW6D/YtyvEl3azv+YQrmv8hM=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>".getBytes("UTF-8")

	byte[] key2Data = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"/><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
			"<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"/><ds:KeyInfo>\n" +
			"<ds:X509Data>\n" +
			"<ds:X509Certificate>\n" +
			"MIIDcTCCAlmgAwIBAgIEZf08dzANBgkqhkiG9w0BAQsFADBpMRAwDgYDVQQGEwdVbmtub3duMRAw\n" +
			"DgYDVQQIEwdVbmtub3duMRAwDgYDVQQHEwdVbmtub3duMRAwDgYDVQQKEwd0ZXN0b3JnMRAwDgYD\n" +
			"VQQLEwdVbmtub3duMQ0wCwYDVQQDEwRrZXkxMB4XDTE1MDcwNjEwNDYwMloXDTM1MDMyMzEwNDYw\n" +
			"MlowaTEQMA4GA1UEBhMHVW5rbm93bjEQMA4GA1UECBMHVW5rbm93bjEQMA4GA1UEBxMHVW5rbm93\n" +
			"bjEQMA4GA1UEChMHdGVzdG9yZzEQMA4GA1UECxMHVW5rbm93bjENMAsGA1UEAxMEa2V5MTCCASIw\n" +
			"DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKEFZfEUkqVw3fe9YfPuK+X/GdAJgw2zvZ8QNY3J\n" +
			"X/dJjMjefjDlZIkAM1zaVzjxiu94UhrS/CEL+ouLWgRi3dvtOYCsilkTjl6NPKwPFkU1EfRVOVnP\n" +
			"aJoaqeLLvDck+iN/f+0xtOd1YY6vZZivPeXAOIonMWprxzaFUi///1tL5QSQ09FUR6EHNPtFk8Aj\n" +
			"CGF7j7Y1DCwayfYYe5auyPvRNbJ2IkmEemrWina8uV6v2gqIhjj3HPe8idUkQfsbd7Cn5036ETLb\n" +
			"NIHCF9MhAQO4VvScmucaZZcbJAsc6uJ/djCX5Omfqm2E7DWpDQDHKLG1fln65txJpPa23WTa5fEC\n" +
			"AwEAAaMhMB8wHQYDVR0OBBYEFM1cn0IBTznpUe1AXJKrOrvsoofRMA0GCSqGSIb3DQEBCwUAA4IB\n" +
			"AQCPuSHK/1NX+nWby67SRC/xYpYenLqyjh6vdrxA8AfqOuZq0HNoGPmAQc6HQn3aX1FJ+6sViohl\n" +
			"1SqI38F9raB8Opqg8e0zONEZV1FNtS2V7Sx/IA0WcxnsoMuWReYKqVR+yffqsgn89q3MUWwuD9Yx\n" +
			"sSRjPxCeBd7arAgZv72PriiqxvvFCGoXrX5Prng8euS/gIeDQZBNEWC3MzbLty8QwMqKFd0+V2fz\n" +
			"LaRMArYLp0nS3TwF24KdgaKuSyA0nq1j/ZNyi/TowrNPA4FLE2f/1akjn3mvgpn62XQoPO1BfZCq\n" +
			"utkUJrOx5P7ZIr91erXUfsQbPDsQkcjAi3IPJFAr\n" +
			"</ds:X509Certificate>\n" +
			"</ds:X509Data>\n" +
			"</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>JUUijEehihofBcT11ZUfmtlykznLDso8aGuBmehjqqoXeLLCCgL8YvIKp1cBAPfp5tccVYAgU80t\n" +
			"5BNePVnp62sbBUCsr3PZLtcPno2ZiHLXwaFPhUcOnDZx7AD/BXOONMI5yaEqb/dNbrP4YQUUkUXS\n" +
			"wqzdJvfxl7auw6OJnkfpQOLrxDQ+OYueKBsT5gsrzScIoEIGMg25UsHiU/1iE4pbLGD5rBDzM9sv\n" +
			"JZ2veycM0/9o41WmXVMxhyEKSDWXng9AxgCYHXQPKEOBtSLeofgxT2DhxWiPQu4txk5e8JEI3RXL\n" +
			"A7TfgnGmg80zLsoHbGBrPlrtYyRDYKYhHhMrpQ==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>NbriPW+rC6rjTw4qn0ejnA7zrGQbuPIauIHPXc1OrhUFMgLvhzDK3i8hYVGXYkbq7A/RF5Sp3h+l\n" +
			"r068/jr3jKjdHtElkYVgoGugKM+jN1JqByx9ApSRzmCGS6gVPY7j/uCc80XFB/qBZwiqW/tfuaeU\n" +
			"nvftgmwXmHG5ooCLJp0/lAH1WR7iKMVfEDsAnZR6I6uV0Lr+heHWj1hwiiy4r5HyZBq4QozsKnlK\n" +
			"zgdTvXt/4DUG7m+sHDdJ7tlCSF/HCv0SozsVeR9lgnZkLTO9m2xXa7QLDfzB65eQidm12b8iuB/B\n" +
			"T5NvCY3P4ieEIjTCJPCQH0cDmQ5W8vpQpe7/8iL/wdNCrVMWWxmgfRIwU33Xj/0ncSTH7ocmlsIA\n" +
			"r7yRtAcT4hI3lRyWYnpzxy8YW+mpKqNxdJdVooDe+b/YYs5HT+m914SSsM37UeoVmfNnFwOy8gwN\n" +
			"VqM0etLNsnLvjrS9OMWrZlnc3/TXHopHk/fHPoiAW5sT/2zI0graeSihuRxroeUrTWlMkWmyjz9v\n" +
			"mr/wjlbRgQXHDAwqEyZeJFAFLsSFNsvxa6TKSjr+UEAEC5IgXiYuflFMgvhftwiumxLjvgIcueof\n" +
			"laa5T6lKSV0ymsi42GnA+QX76SqFVpA6CT7bUNcoLLud09Zlo41BsNbKQhAJDf2LzfQTy496EguB\n" +
			"ldPWt0pGfLNiym5005mP7jFrVns4kkTnLLUeggycR4VXZRKCWfP3GH0CY9OCmOCMW8ysZwoV7sMT\n" +
			"m4EDnKOXaHcE0r5C3D2tU5ztIpLuRR2TCW7nct3zkN8m3zj0aAmXD8GncJDIO+IFQ/006Cn7Fskj\n" +
			"PivWLZCczm8RaqXX0oVWHQK4jq/PNpoQe+kxmafH9+NuZLSGApM8KbSqyXYOq2aDHM6P/kAH0S4c\n" +
			"lDtja3+fl2F6m8eYiICckl5c6UCmN9Hupm3bfJCXXuiTaKTnhzooomoSjQO7ZEVwhfcDQn6DLSXt\n" +
			"IYfyCmj5ENDBw3B6c+tVedA4x1UHtZvkGxHH3AJad3U8snxttx1ScGDbx+eTiiQ+f0Iq6/zZBk+M\n" +
			"3++qRmrIsvTSAMDieQ9rZ7gmcGHufV0YPVPFEaTwsruaWDXYSQYzyyCjQkCdkT6ryJSwMUm7PyaM\n" +
			"2ONswOjPDo42oYwYDEImWj8p7r1Ro3SfmkxgKFd6OODMh6/Vg7lmPiGx2+OiCvuPxodEOb8/cKo0\n" +
			"omsLRbYWt4G0WIrwQA/TZ0nTj5FENfNoVgYDvkCV3Yv8zaHHw4C75HO2rYi7P9kj5B2W+tgSO/z/\n" +
			"Y88Dhm9kENcJea8F7OBsU0MXhbry9fdZRUk4eL67qHp8Y0GAxmtQ36D7qRtrOCq1X8vl3pnuUcx0\n" +
			"vg3paA0r3wMCbv9mN8noSSA9JaDixMCBa6YGipWKGmMybGcX7e3iJ7qk5BsmpX5Tbd//+Suz6pL1\n" +
			"iorirfs4Jo1gWao6BPsxWobsjEgaRu/leRgtZ/YDaSB4i9N90SB6/v7oEvSAuBBkBUMfSOmT5YdJ\n" +
			"M5GZkX01RzJl8edOtNJkUGtfv42WTWVSEzer4SeY/AqFNdYjGvlY+yqlAWWIRXOtXcDesKVT5/37\n" +
			"2uSFZjmDLYSHMuQGyU7ck82HMWduVrCptYgrYzzljPF54ErzhWdlswdT/S2iba9dyLpWQkfAcJXv\n" +
			"qUo6lfDoEdQUX2d+hDIFN41dtYG/N22ZnemcWB9DjF22ASVv4iU3cBCNnMBwNtkdU9OqnqnEWZBo\n" +
			"i00t39vDU+k9a2LjroUUYyRNXbb//Zv0esJ+7TdSS9hmPyNVNY0QG1vfxu2QdwMI/1PvCrK5+POO\n" +
			"Av1oIPkxDdga7p6nxsrWyVL1rYj670FHiN+WrJt9EDgQ7lVnHuIm53l02y5qGb+6zbD9b2l2c9+Q\n" +
			"IS0WJtrC6XSmD1xymQlQ65rRYcrxHUR7VUnN0saxL8hElSlQh2ZnuoQpDEj5DmM=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>".getBytes("UTF-8")

	byte[] getUsersRequestV2_0With2_1Data =  """<?xml version="1.0" encoding="UTF-8" standalone="no"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:ae="http://certificateservices.org/xsd/autoenroll2_x" xmlns:auth="http://certificateservices.org/xsd/authorization2_0" xmlns:credmanagement="http://certificateservices.org/xsd/credmanagement2_0" xmlns:csexd="http://certificateservices.org/xsd/csexport_data_1_0" xmlns:csexp="http://certificateservices.org/xsd/cs_export_protocol2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:key="http://certificateservices.org/xsd/sensitivekeys" xmlns:keystoremgmt="http://certificateservices.org/xsd/keystoremgmt2_0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="2.0" timeStamp="2017-03-16T16:28:40.600+01:00" version="2.0" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd"><cs:name>GetUsersRequest</cs:name><cs:sourceId>SOMESOURCEID</cs:sourceId><cs:destinationId>SOMESOURCEID</cs:destinationId><cs:organisation>someorg</cs:organisation><cs:originator><cs:credential><cs:credentialRequestId>123</cs:credentialRequestId><cs:uniqueId>SomeOriginatorUniqueId</cs:uniqueId><cs:displayName>SomeOrignatorDisplayName</cs:displayName><cs:serialNumber>SomeSerialNumber</cs:serialNumber><cs:issuerId>SomeIssuerId</cs:issuerId><cs:status>100</cs:status><cs:credentialType>SomeCredentialType</cs:credentialType><cs:credentialSubType>SomeCredentialSubType</cs:credentialSubType><cs:attributes><cs:attribute><cs:key>someattrkey</cs:key><cs:value>someattrvalue</cs:value></cs:attribute></cs:attributes><cs:usages><cs:usage>someusage</cs:usage></cs:usages><cs:credentialData>MTIzNDVBQkNFRg==</cs:credentialData><cs:issueDate>1970-01-01T01:00:01.234+01:00</cs:issueDate><cs:expireDate>1970-01-01T01:00:02.234+01:00</cs:expireDate><cs:validFromDate>1970-01-01T01:00:03.234+01:00</cs:validFromDate></cs:credential></cs:originator><cs:payload><credmanagement:GetUsersRequest><credmanagement:uniqueId>someuniqueid</credmanagement:uniqueId><credmanagement:exactMatch>true</credmanagement:exactMatch><credmanagement:startIndex>5</credmanagement:startIndex><credmanagement:resultSize>10</credmanagement:resultSize></credmanagement:GetUsersRequest></cs:payload><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#12345678-1234-4444-8000-123456789012"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>QhfnaIPlCsD+Ly0hvO+IHTP8Jjuo+0/qjyfrPYJvg0Q=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>V2ZcsgUU2UwZDCHNMRAcvHzLnK6gzNpF02c5E2KuMQTTZG7qlEsqdcxCaW+Iew83ZvHr+tN0jAub
etbXs+E+SXfQsxqt192JYuOszmHq1GMvE/XaINLKiBYGKHn9X3j9yRBE6kEncu2m8uBBIRemuoZi
zldI8I/3Akfw9H+0/ByR0olW+49lJ59xFmIyCG+hfQuNpHheXH907vQMnR/8lOKnFgAUECzzhraS
6NGQnlvQlMjnA9etZr9Nk5o4JAqIF6eqYn26snOwUeMXOcpQoAXZrlQvrEGAHxMS8PNHdL0y7YzA
/rMLnuS3V+PX0Co51F+rqupZFqw0cHXM/UEdVw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
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
ZLCP64EJEfE1mGxCJg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></cs:CSMessage>""".getBytes("UTF-8")

byte[] validGetUsersRequestV2_0 = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:ae="http://certificateservices.org/xsd/autoenroll2_x" xmlns:auth="http://certificateservices.org/xsd/authorization2_0" xmlns:credmanagement="http://certificateservices.org/xsd/credmanagement2_0" xmlns:csexd="http://certificateservices.org/xsd/csexport_data_1_0" xmlns:csexp="http://certificateservices.org/xsd/cs_export_protocol2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:key="http://certificateservices.org/xsd/sensitivekeys" xmlns:keystoremgmt="http://certificateservices.org/xsd/keystoremgmt2_0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="2.0" timeStamp="2017-03-16T16:28:40.864+01:00" version="2.0" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd"><cs:name>GetUsersRequest</cs:name><cs:sourceId>SOMESOURCEID</cs:sourceId><cs:destinationId>SOMESOURCEID</cs:destinationId><cs:organisation>someorg</cs:organisation><cs:originator><cs:credential><cs:credentialRequestId>123</cs:credentialRequestId><cs:uniqueId>SomeOriginatorUniqueId</cs:uniqueId><cs:displayName>SomeOrignatorDisplayName</cs:displayName><cs:serialNumber>SomeSerialNumber</cs:serialNumber><cs:issuerId>SomeIssuerId</cs:issuerId><cs:status>100</cs:status><cs:credentialType>SomeCredentialType</cs:credentialType><cs:credentialSubType>SomeCredentialSubType</cs:credentialSubType><cs:attributes><cs:attribute><cs:key>someattrkey</cs:key><cs:value>someattrvalue</cs:value></cs:attribute></cs:attributes><cs:usages><cs:usage>someusage</cs:usage></cs:usages><cs:credentialData>MTIzNDVBQkNFRg==</cs:credentialData><cs:issueDate>1970-01-01T01:00:01.234+01:00</cs:issueDate><cs:expireDate>1970-01-01T01:00:02.234+01:00</cs:expireDate><cs:validFromDate>1970-01-01T01:00:03.234+01:00</cs:validFromDate></cs:credential></cs:originator><cs:payload><credmanagement:GetUsersRequest><credmanagement:uniqueId>someuniqueid</credmanagement:uniqueId><credmanagement:exactMatch>true</credmanagement:exactMatch></credmanagement:GetUsersRequest></cs:payload><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#12345678-1234-4444-8000-123456789012"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>fcZH1Wq4T9VwU5rm/KxIMl+wV7tOnKtc4NeG33rQYgg=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>c9Z2MqmvthrJ0uXsr12ct+EwSfB3qFVPTMyEjPc4Y/wgrNUDm9dB7ihbQxU1VPN6ka6MIt0P877k
6YnebRKsNHJHoFheVzqAS9oQJJct4ytVgHA2mzWu9NLySgap+HWhlmuZUVDAkY1iYrbjmZ8EOSX6
Z7Zs5ftR3w4/u3zXbQhEO48lQG4fGPihP/oY9dchtmYi/bY+/RdYbaIpQmibiBIUqs+74Nlu9e84
uF6glmRQMoHYBWtdaDvu8peHbyBL5wU3KylprCzPvivZWNrVUu0ONgCswT7bBxZaHhDiSpUCck18
3i20xeC0fwUvNwUaGlXBIEREVggbQz8p6qcNKA==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
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
ZLCP64EJEfE1mGxCJg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></cs:CSMessage>""".getBytes("UTF-8")

	byte[] getTokensRequestV2_0With2_1Data =  """<?xml version="1.0" encoding="UTF-8" standalone="no"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:ae="http://certificateservices.org/xsd/autoenroll2_x" xmlns:auth="http://certificateservices.org/xsd/authorization2_0" xmlns:credmanagement="http://certificateservices.org/xsd/credmanagement2_0" xmlns:csexd="http://certificateservices.org/xsd/csexport_data_1_0" xmlns:csexp="http://certificateservices.org/xsd/cs_export_protocol2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:key="http://certificateservices.org/xsd/sensitivekeys" xmlns:keystoremgmt="http://certificateservices.org/xsd/keystoremgmt2_0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="2.0" timeStamp="2017-03-16T16:44:37.857+01:00" version="2.0" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd"><cs:name>GetTokensRequest</cs:name><cs:sourceId>SOMESOURCEID</cs:sourceId><cs:destinationId>SOMESOURCEID</cs:destinationId><cs:organisation>someorg</cs:organisation><cs:payload><credmanagement:GetTokensRequest><credmanagement:serialNumber>someserial</credmanagement:serialNumber><credmanagement:exactMatch>true</credmanagement:exactMatch><credmanagement:startIndex>3</credmanagement:startIndex><credmanagement:resultSize>20</credmanagement:resultSize></credmanagement:GetTokensRequest></cs:payload><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#12345678-1234-4444-8000-123456789012"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>Ep/sAtMZ3NSI3MTyGKlGHnGM9Man92euDWNjxY+2gNc=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>By/99teyY+z8Q1nEu8inxK4Veen0JEhNCJFGA7Nbxl0gEerwtT5RvIYy3woWXAW40SMvWkpMRzzf
XTsdWrmz2NhG9sNme4VR3enKrkWDlOrhw/23oWjBmkka51qy/N2hjl9TGCyZacUeAwG1Hu9coUSx
Nw4xVtq4SW80/Tgwj02FLekDM+nf4ThD6OvFLYLmRyOEkaJa0XBjDobuq+kttHq5xEF+CXCfOIhJ
zfMrVwdWQ0RngWpmzGyNGU/DLe6XCC6JBqs7CrHHU7fiKshHaSwCmZ1F624Aax4I+skikIoVFaGc
53UJtWkIlkWFsUrqTphQteZKr3wnQSOXiJ1tsA==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
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
ZLCP64EJEfE1mGxCJg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></cs:CSMessage>""".getBytes("UTF-8")

	byte[] changeTokenStatusRequestV2_2_With2_3Data = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:a="http://certificateservices.org/xsd/cs_agent_protocol2_0" xmlns:ae="http://certificateservices.org/xsd/autoenroll2_x" xmlns:auth="http://certificateservices.org/xsd/authorization2_0" xmlns:credmanagement="http://certificateservices.org/xsd/credmanagement2_0" xmlns:csexd="http://certificateservices.org/xsd/csexport_data_1_0" xmlns:csexp="http://certificateservices.org/xsd/cs_export_protocol2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:key="http://certificateservices.org/xsd/sensitivekeys" xmlns:keystoremgmt="http://certificateservices.org/xsd/keystoremgmt2_0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="2.2" timeStamp="2019-04-03T13:11:16.785+02:00" version="2.2" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd"><cs:name>ChangeTokenStatusRequest</cs:name><cs:sourceId>SOMEREQUESTER</cs:sourceId><cs:destinationId>SOMESOURCEID</cs:destinationId><cs:organisation>someorg</cs:organisation><cs:originator><cs:credential><cs:credentialRequestId>123</cs:credentialRequestId><cs:uniqueId>SomeOriginatorUniqueId</cs:uniqueId><cs:displayName>SomeOrignatorDisplayName</cs:displayName><cs:serialNumber>SomeSerialNumber</cs:serialNumber><cs:issuerId>SomeIssuerId</cs:issuerId><cs:status>100</cs:status><cs:credentialType>SomeCredentialType</cs:credentialType><cs:credentialSubType>SomeCredentialSubType</cs:credentialSubType><cs:attributes><cs:attribute><cs:key>someattrkey</cs:key><cs:value>someattrvalue</cs:value></cs:attribute></cs:attributes><cs:usages><cs:usage>someusage</cs:usage></cs:usages><cs:credentialData>MTIzNDVBQkNFRg==</cs:credentialData><cs:issueDate>1970-01-01T01:00:01.234+01:00</cs:issueDate><cs:expireDate>1970-01-01T01:00:02.234+01:00</cs:expireDate><cs:validFromDate>1970-01-01T01:00:03.234+01:00</cs:validFromDate></cs:credential></cs:originator><cs:payload><credmanagement:ChangeTokenStatusRequest><credmanagement:tokenSerialNumber>someTokenSerial</credmanagement:tokenSerialNumber><credmanagement:credentialFilter><credmanagement:credentialTypeFilters><credmanagement:credentialTypeFilter><credmanagement:credentialType>x509certificate</credmanagement:credentialType><credmanagement:credentialSubType>SomeCredSubType1</credmanagement:credentialSubType></credmanagement:credentialTypeFilter><credmanagement:credentialTypeFilter><credmanagement:credentialType>x509certificate</credmanagement:credentialType><credmanagement:credentialSubType>SomeCredSubType2</credmanagement:credentialSubType></credmanagement:credentialTypeFilter></credmanagement:credentialTypeFilters></credmanagement:credentialFilter><credmanagement:newCredentialStatus>100</credmanagement:newCredentialStatus><credmanagement:reasonInformation>someReasonInformation</credmanagement:reasonInformation></credmanagement:ChangeTokenStatusRequest></cs:payload><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#12345678-1234-4444-8000-123456789012"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>3acJRey3S2rxvfUz5Sz+2twEF2uK8lwaxOpDc0cLPOk=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>IKjJ5Sx/IcFDnL7mNw+B3EA11/JQO+GRf36vEXyo9pk5IkRaAAIQ4LbEo3H8yA/fJVEewOSTK1PA
W35htGJQfViUPUtAKycGL/DBZj04dfgUb6LHiDvXzWF3DW8URYIz7z3W4F83k286spODYjsrY8zE
V8lFTL1jwC9yCJ6lqVBLqkwpdzMSd2UdiJ4fvzkXaxZNR3csyH9SvxbYzGJMlkOENW5gPrhLnA0q
W6Zg9YL8DF8G9+RXWTEA+IMjF6lBkiJPEeqdr1tA8t3t9Gy8Bghdbwt2Kq9DVThH4scq3TePJNIw
qbIivgxAV+VknTg+v+GwuZpqdBrSf3kaYtDd0A==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
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
ZLCP64EJEfE1mGxCJg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></cs:CSMessage>""".getBytes("UTF-8")

	byte[] validGetTokensRequestV2_0 = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:ae="http://certificateservices.org/xsd/autoenroll2_x" xmlns:auth="http://certificateservices.org/xsd/authorization2_0" xmlns:credmanagement="http://certificateservices.org/xsd/credmanagement2_0" xmlns:csexd="http://certificateservices.org/xsd/csexport_data_1_0" xmlns:csexp="http://certificateservices.org/xsd/cs_export_protocol2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:key="http://certificateservices.org/xsd/sensitivekeys" xmlns:keystoremgmt="http://certificateservices.org/xsd/keystoremgmt2_0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="2.0" timeStamp="2017-03-16T16:44:37.612+01:00" version="2.0" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd"><cs:name>GetTokensRequest</cs:name><cs:sourceId>SOMESOURCEID</cs:sourceId><cs:destinationId>SOMESOURCEID</cs:destinationId><cs:organisation>someorg</cs:organisation><cs:payload><credmanagement:GetTokensRequest><credmanagement:serialNumber>someserial</credmanagement:serialNumber><credmanagement:exactMatch>true</credmanagement:exactMatch></credmanagement:GetTokensRequest></cs:payload><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#12345678-1234-4444-8000-123456789012"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>xIdcTxz8NtKedoEnSEAeGhEh6c05D/YhX269OH6lArU=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Kasg5v3BjOECEUh/LMQCymFLA2//BH6E5sJ7AHgvjJb9R2p5ttWGDfo9vOB0CPZSj0tQ6KomiEhr
qXp8QHwCs1/qP8GCaAI/qC+uZDXFlONWhhaQsjs574wR4bFWmyTuygMUc0bUyKPcxZeThzykwCXZ
8J5Pj+xUEEc30MyC8vRIXF/1aJ5kjR4NYl54R44QSgHmrfdtUiIMtAHqx+3coPEsyx+Ct6oRjQ4W
JQ0QZBnvi2w9qesERDkrxbFtxuQDIIjQYnIxKRmPmMbx/lC1pAqE/nlGwj+YFyK8hVOQ8DWvPZnH
8N30varDgj/UrAdB47SWnGIU+EXJss4iBS2Xww==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
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
ZLCP64EJEfE1mGxCJg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></cs:CSMessage>""".getBytes("UTF-8")

	byte[] ver2_0IssueTokenCredentialMessageWithDepartment = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:ae="http://certificateservices.org/xsd/autoenroll2_x" xmlns:auth="http://certificateservices.org/xsd/authorization2_0" xmlns:credmanagement="http://certificateservices.org/xsd/credmanagement2_0" xmlns:csexd="http://certificateservices.org/xsd/csexport_data_1_0" xmlns:csexp="http://certificateservices.org/xsd/cs_export_protocol2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:key="http://certificateservices.org/xsd/sensitivekeys" xmlns:keystoremgmt="http://certificateservices.org/xsd/keystoremgmt2_0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="2.0" timeStamp="2017-03-17T07:48:17.525+01:00" version="2.0" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd"><cs:name>IssueTokenCredentialsRequest</cs:name><cs:sourceId>SOMEREQUESTER</cs:sourceId><cs:destinationId>SOMESOURCEID</cs:destinationId><cs:organisation>someorg</cs:organisation><cs:originator><cs:credential><cs:credentialRequestId>123</cs:credentialRequestId><cs:uniqueId>SomeOriginatorUniqueId</cs:uniqueId><cs:displayName>SomeOrignatorDisplayName</cs:displayName><cs:serialNumber>SomeSerialNumber</cs:serialNumber><cs:issuerId>SomeIssuerId</cs:issuerId><cs:status>100</cs:status><cs:credentialType>SomeCredentialType</cs:credentialType><cs:credentialSubType>SomeCredentialSubType</cs:credentialSubType><cs:attributes><cs:attribute><cs:key>someattrkey</cs:key><cs:value>someattrvalue</cs:value></cs:attribute></cs:attributes><cs:usages><cs:usage>someusage</cs:usage></cs:usages><cs:credentialData>MTIzNDVBQkNFRg==</cs:credentialData><cs:issueDate>1970-01-01T01:00:01.234+01:00</cs:issueDate><cs:expireDate>1970-01-01T01:00:02.234+01:00</cs:expireDate><cs:validFromDate>1970-01-01T01:00:03.234+01:00</cs:validFromDate></cs:credential></cs:originator><cs:payload><credmanagement:IssueTokenCredentialsRequest><credmanagement:tokenRequest><cs:credentialRequests><cs:credentialRequest><cs:credentialRequestId>123</cs:credentialRequestId><cs:credentialType>SomeCredentialType</cs:credentialType><cs:credentialSubType>SomeCredentialSubType</cs:credentialSubType><cs:x509RequestType>SomeX509RequestType</cs:x509RequestType><cs:credentialRequestData>MTIzNDVBQkM=</cs:credentialRequestData></cs:credentialRequest></cs:credentialRequests><cs:user>someuser</cs:user><cs:tokenContainer>SomeTokenContainer</cs:tokenContainer><cs:tokenType>SomeTokenType</cs:tokenType><cs:tokenClass>SomeTokenClass</cs:tokenClass><cs:departmentName>SomeDepartment</cs:departmentName></credmanagement:tokenRequest></credmanagement:IssueTokenCredentialsRequest></cs:payload><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#12345678-1234-4444-8000-123456789012"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>iiCymH5En3BYs4MA8WKKKgM7gdiZ7JpqNAJxKQYyZXQ=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>ELcrM0+fXwENO6+1CUOzxW5EdctO/pGSCOdrodY0Jb/EtS74kasekXEjGpNPMQ4mKMtVm97H/3D7
v5hxNvgfixXTM75sBwjLWKCTBAiTnnTaAQF0CJccZ7gohKnkLDp1fUvr8NkBw0M/ACBpsEfLYSbU
KA1JTm8UauQ+Bzb3nsQib5NvGn/TEdCopblV/K0RDrKwQpFBr3acH4148DIUT3n30Do3Yd3wWmyZ
Ifijdl+5hjlP4B8uKwZkwQ4oAVbIqMGu2Kg7QL8RkK4jm6VAlgddtm0F3VUGtNHfsRuouSHy+fI4
ZOjqqtiPOdJYRpp3LDBNxhFFfO6XFWmy6SamGw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
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
ZLCP64EJEfE1mGxCJg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></cs:CSMessage>""".getBytes("UTF-8")

	def issueTokenCredentialWithRenewandInvalidVersion= """<?xml version="1.0" encoding="UTF-8"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:a="http://certificateservices.org/xsd/cs_agent_protocol2_0" xmlns:ae="http://certificateservices.org/xsd/autoenroll2_x" xmlns:auth="http://certificateservices.org/xsd/authorization2_0" xmlns:credmanagement="http://certificateservices.org/xsd/credmanagement2_0" xmlns:csexd="http://certificateservices.org/xsd/csexport_data_1_0" xmlns:csexp="http://certificateservices.org/xsd/cs_export_protocol2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:key="http://certificateservices.org/xsd/sensitivekeys" xmlns:keystoremgmt="http://certificateservices.org/xsd/keystoremgmt2_0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="2.2" timeStamp="2018-02-02T14:41:25.558+01:00" version="2.1" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd">
  <cs:name>IssueTokenCredentialsRequest</cs:name>
  <cs:sourceId>SOMESOURCEID</cs:sourceId>
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
      <cs:issueDate>1970-01-01T01:00:01.234+01:00</cs:issueDate>
      <cs:expireDate>1970-01-01T01:00:02.234+01:00</cs:expireDate>
      <cs:validFromDate>1970-01-01T01:00:03.234+01:00</cs:validFromDate>
    </cs:credential>
  </cs:originator>
  <cs:payload>
    <credmanagement:IssueTokenCredentialsRequest>
      <credmanagement:tokenRequest>
        <cs:credentialRequests>
          <cs:credentialRequest>
            <cs:credentialRequestId>123</cs:credentialRequestId>
            <cs:credentialType>SomeCredentialType</cs:credentialType>
            <cs:credentialSubType>SomeCredentialSubType</cs:credentialSubType>
            <cs:x509RequestType>SomeX509RequestType</cs:x509RequestType>
            <cs:credentialRequestData>MTIzNDVBQkM=</cs:credentialRequestData>           
          </cs:credentialRequest>
        </cs:credentialRequests>
        <cs:user>someuser</cs:user>
        <cs:tokenContainer>SomeTokenContainer</cs:tokenContainer>
        <cs:tokenType>SomeTokenType</cs:tokenType>
        <cs:tokenClass>SomeTokenClass</cs:tokenClass>
        <cs:departmentName>SomeDepartment</cs:departmentName>
        <cs:regenerateToken>SomeOldSerial</cs:regenerateToken>
      </credmanagement:tokenRequest>
    </credmanagement:IssueTokenCredentialsRequest>
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
        <ds:DigestValue>8plLrhoD6gAJaIaY3Or4CPmGO2vhbxF2F6Grde9VUWU=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>aorMn8yZvsRSDyks7JyD42yh7qSYhv5GrvpCsbHoH4MN8Wxd3oWHHeWxvL3ClOx8lBgmyrVzxjSV
ALWDwWHmMSfYW8mPW7aQAyLg4p4f7kNQzD1rECd9tTKP11cygZhfo7a9CZDQBD3DRAA5N/4kQK95
KKre4DVDNX6clNNaXIIS0OHbBU9yE6V7auaBbPbFbFLKOGyR+nLhN/bdhXk8ECwqmVrUBI/JbgJg
q20L6CbrIYXNgzoLedR4wxR+kHd5OK0PVglOAQtZ3r070Ll2RPT7hCHdzLYlhoakV38dHy4vIO1A
I+eWw+9bSwrm1ybdrexzZwWPTJoPB5KoftfnoA==</ds:SignatureValue>
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
}
