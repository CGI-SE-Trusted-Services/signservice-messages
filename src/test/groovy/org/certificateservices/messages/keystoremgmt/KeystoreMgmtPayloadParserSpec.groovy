package org.certificateservices.messages.keystoremgmt

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.certificateservices.messages.csmessages.CSMessageParserManager;

import javax.xml.datatype.DatatypeFactory;

import org.apache.xml.security.Init;
import org.certificateservices.messages.DummyMessageSecurityProvider;
import org.certificateservices.messages.TestUtils;
import org.certificateservices.messages.csmessages.CSMessageResponseData;
import org.certificateservices.messages.csmessages.DefaultCSMessageParser;
import org.certificateservices.messages.csmessages.PayloadParserRegistry;
import org.certificateservices.messages.csmessages.jaxb.Attribute;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.Credential;
import org.certificateservices.messages.csmessages.jaxb.CredentialRequest;
import org.certificateservices.messages.csmessages.jaxb.Organisation;
import org.certificateservices.messages.keystoremgmt.jaxb.CredentialRequestParams;
import org.certificateservices.messages.keystoremgmt.jaxb.KeyInfo;
import org.certificateservices.messages.keystoremgmt.jaxb.KeyStatus;
import org.certificateservices.messages.keystoremgmt.jaxb.KeyStore;
import org.certificateservices.messages.keystoremgmt.jaxb.KeyStoreStatus;
import org.certificateservices.messages.keystoremgmt.jaxb.ObjectFactory;
import org.certificateservices.messages.keystoremgmt.jaxb.X509CredentialRequestParams;
import org.certificateservices.messages.utils.MessageGenerateUtils;

import spock.lang.Specification

import java.security.Security;

import static org.certificateservices.messages.TestUtils.*
import static org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.*

class KeystoreMgmtPayloadParserSpec extends Specification {
	
	KeystoreMgmtPayloadParser pp;
	ObjectFactory of = new ObjectFactory()
	org.certificateservices.messages.csmessages.jaxb.ObjectFactory csMessageOf = new org.certificateservices.messages.csmessages.jaxb.ObjectFactory()
	
	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Init.init();
	}
	
	def setup(){
		setupRegisteredPayloadParser();
		
		pp = PayloadParserRegistry.getParser(KeystoreMgmtPayloadParser.NAMESPACE);
	}
	
	def "Verify that JAXBPackage(), getNameSpace(), getSchemaAsInputStream(), getSupportedVersions(), getDefaultPayloadVersion() returns the correct values"(){
		expect:
		pp.getJAXBPackage() == "org.certificateservices.messages.keystoremgmt.jaxb"
		pp.getNameSpace() == "http://certificateservices.org/xsd/keystoremgmt2_0"
		pp.getSchemaAsInputStream("2.0") != null
		pp.getDefaultPayloadVersion() == "2.0"
		pp.getSupportedVersions() == ["2.0"] as String[]
	}

	def "Verify that generateGetAvailableKeyStoreInfoRequest() generates a valid xml message and generateGetAvailableKeyStoreInfoResponse() generates a valid CSMessageResponseData"(){
		when:
		CSMessageParserManager.getCSMessageParser().sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.generateGetAvailableKeyStoreInfoRequest(TEST_ID, "SOMESOURCEID", "someorg", createOriginatorCredential(), null)
        //printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.GetAvailableKeyStoreInfoRequest
		then:
		messageContainsPayload requestMessage, "keystoremgmt:GetAvailableKeyStoreInfoRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","GetAvailableKeyStoreInfoRequest", createOriginatorCredential(), CSMessageParserManager.getCSMessageParser())
		
		when:
		CSMessageParserManager.getCSMessageParser().sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.generateGetAvailableKeyStoreInfoResponse("SomeRelatedEndEntity", request, genKeystores(), null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.GetAvailableKeyStoreInfoResponse
		
		then:
		messageContainsPayload rd.responseData, "keystoremgmt:GetAvailableKeyStoreInfoResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "GetAvailableKeyStoreInfoResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","GetAvailableKeyStoreInfoResponse", createOriginatorCredential(), CSMessageParserManager.getCSMessageParser())
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.keyStores.keyStore[0].providerName == "someprovname"
		
		expect:
		pp.parseMessage(rd.responseData)
		
	}

	def "Verify that generateGenerateCredentialRequestRequest() generates a valid xml message and generateGenerateCredentialRequestResponse() generates a valid CSMessageResponseData"(){
		when:
		CSMessageParserManager.getCSMessageParser().sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.generateGenerateCredentialRequestRequest(TEST_ID, "SOMESOURCEID", "someorg", "someprovname","someapp",createCredentialRequestParams(),createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.GenerateCredentialRequestRequest
		then:
		messageContainsPayload requestMessage, "keystoremgmt:GenerateCredentialRequestRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","GenerateCredentialRequestRequest", createOriginatorCredential(), CSMessageParserManager.getCSMessageParser())
		
		payloadObject.credentialRequestParams.baseRequestParams.alias == "somealias"
		
		when:
		CSMessageParserManager.getCSMessageParser().sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.generateGenerateCredentialRequestResponse("SomeRelatedEndEntity", request, genCredentialRequest(), null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.GenerateCredentialRequestResponse
		
		then:
		messageContainsPayload rd.responseData, "keystoremgmt:GenerateCredentialRequestResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "GenerateCredentialRequestResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","GenerateCredentialRequestResponse", createOriginatorCredential(), CSMessageParserManager.getCSMessageParser())
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.credentialRequest.credentialRequestId == "1"
		
		expect:
		pp.parseMessage(rd.responseData)
		
		when: "Test with X509CredentialParams"
		CSMessageParserManager.getCSMessageParser().sourceId = "SOMEREQUESTER"
		requestMessage = pp.generateGenerateCredentialRequestRequest(TEST_ID, "SOMESOURCEID", "someorg", "someprovname","someapp",createX509CredentialRequestParams(),createOriginatorCredential(), null)
		//openXML(requestMessage)
		xml = slurpXml(requestMessage)
		payloadObject = xml.payload.GenerateCredentialRequestRequest
		then:
		messageContainsPayload requestMessage, "keystoremgmt:GenerateCredentialRequestRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","GenerateCredentialRequestRequest", createOriginatorCredential(), CSMessageParserManager.getCSMessageParser())
		
		payloadObject.credentialRequestParams.x509CredentialRequestParams.alias == "somealias"
		
		cleanup:
		CSMessageParserManager.getCSMessageParser().sourceId = "SOMESOURCEID"
		
	}
	
	def "Verify that generateRemoveKeyRequest() generates a valid xml message and generateRemoveKeyResponse() generates a valid CSMessageResponseData"(){
		when:
		CSMessageParserManager.getCSMessageParser().sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.generateRemoveKeyRequest(TEST_ID, "SOMESOURCEID", "someorg", "someprovname","somealias",createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.RemoveKeyRequest
		then:
		messageContainsPayload requestMessage, "keystoremgmt:RemoveKeyRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","RemoveKeyRequest", createOriginatorCredential(), CSMessageParserManager.getCSMessageParser())
		
		payloadObject.keyStoreProviderName == "someprovname"
		payloadObject.organisationShortName == "someorg"
		payloadObject.alias == "somealias"
		
		when:
		CSMessageParserManager.getCSMessageParser().sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.generateRemoveKeyResponse("SomeRelatedEndEntity", request, null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.RemoveKeyResponse
		
		then:
		messageContainsPayload rd.responseData, "keystoremgmt:RemoveKeyResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "RemoveKeyResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","RemoveKeyResponse", createOriginatorCredential(), CSMessageParserManager.getCSMessageParser())
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
			
		expect:
		pp.parseMessage(rd.responseData)
		
	}
	
	def "Verify that generateAttachCredentialsRequest() generates a valid xml message and generateAttachCredentialsResponse() generates a valid CSMessageResponseData"(){
		when:
		CSMessageParserManager.getCSMessageParser().sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.generateAttachCredentialsRequest(TEST_ID, "SOMESOURCEID", "someorg", "someprovname","somealias",createCredentials(), createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.AttachCredentialsRequest
		then:
		messageContainsPayload requestMessage, "keystoremgmt:AttachCredentialsRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","AttachCredentialsRequest", createOriginatorCredential(), CSMessageParserManager.getCSMessageParser())
		
		payloadObject.keyStoreProviderName == "someprovname"
		payloadObject.organisationShortName == "someorg"
		payloadObject.alias == "somealias"
		payloadObject.credentials.credential.size() == 2
		payloadObject.credentials.credential[0].credentialRequestId == 1
		payloadObject.credentials.credential[1].credentialRequestId == 2
		
		when:
		CSMessageParserManager.getCSMessageParser().sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.generateAttachCredentialsResponse("SomeRelatedEndEntity", request, null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.AttachCredentialsResponse
		
		then:
		messageContainsPayload rd.responseData, "keystoremgmt:AttachCredentialsResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "AttachCredentialsResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","AttachCredentialsResponse", createOriginatorCredential(), CSMessageParserManager.getCSMessageParser())
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
			
		expect:
		pp.parseMessage(rd.responseData)
		
	}
	
	def "Verify that generateUpdateKeyDescriptionRequest() generates a valid xml message and generateUpdateKeyDescriptionResponse() generates a valid CSMessageResponseData"(){
		when:
		CSMessageParserManager.getCSMessageParser().sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.generateUpdateKeyDescriptionRequest(TEST_ID, "SOMESOURCEID", "someorg", "someprovname","somealias","somedesc", createOriginatorCredential(), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.UpdateKeyDescriptionRequest
		then:
		messageContainsPayload requestMessage, "keystoremgmt:UpdateKeyDescriptionRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","UpdateKeyDescriptionRequest", createOriginatorCredential(), CSMessageParserManager.getCSMessageParser())
		
		payloadObject.keyStoreProviderName == "someprovname"
		payloadObject.organisationShortName == "someorg"
		payloadObject.alias == "somealias"
		payloadObject.description == "somedesc"

		
		when:
		CSMessageParserManager.getCSMessageParser().sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.generateUpdateKeyDescriptionResponse("SomeRelatedEndEntity", request, null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.UpdateKeyDescriptionResponse
		
		then:
		messageContainsPayload rd.responseData, "keystoremgmt:UpdateKeyDescriptionResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "UpdateKeyDescriptionResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","UpdateKeyDescriptionResponse", createOriginatorCredential(), CSMessageParserManager.getCSMessageParser())
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
			
		expect:
		pp.parseMessage(rd.responseData)
		
	}
	
	
	private List<KeyStore> genKeystores(){
		Organisation org = csMessageOf.createOrganisation();
		org.shortName = "orgshortname"
		org.displayName = "orgDisplayName"
		org.obfuscatedName = "obfuscatedname"
		org.issuerDistinguishedName = "CN=testdn"
		org.matchAdminWith = new BigInteger(1)
		
		KeyInfo keyInfo = of.createKeyInfo();
		keyInfo.alias = "somealias"
		keyInfo.application = "someapp"
		keyInfo.certificateRequest = "abc".getBytes()
		keyInfo.organisationShortName = "orgshortname"
		keyInfo.credentialSubType = "somecredsubtype"
		keyInfo.dateCreated = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(123000L))
		keyInfo.lastUpdated  = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(223000L))
		keyInfo.status = KeyStatus.PENDINGCERTIFICATE
		keyInfo.credentials = new KeyInfo.Credentials()
		
		KeyStore ks1 = of.createKeyStore()
		ks1.providerName ="keyprov1"
		ks1.status = KeyStoreStatus.ACTIVE;
		ks1.providerName = "someprovname"
		ks1.relatedOrganisations = new KeyStore.RelatedOrganisations()
		ks1.relatedOrganisations.organisation.add(org)
		ks1.keyInfos = new KeyStore.KeyInfos()
		ks1.keyInfos.keyInfo.add(keyInfo)
		
		
		return [ks1]
	}
	
	def createCredentialRequestParams(){
		CredentialRequestParams retval = of.createCredentialRequestParams();
		
		retval.alias = "somealias"
		retval.credentialSubType = "somecredentialsubtype"
		retval.description = "somedescription"
		retval.keyAlg = "somekeyalg"
		retval.keySpec = "somekeyspec"
		
		return retval
	}
	
	
	def genCredentialRequest(){
		CredentialRequest cr = csMessageOf.createCredentialRequest()
		
		cr.credentialRequestData = "somedata".getBytes()
		cr.credentialRequestId = 1
		cr.credentialSubType = "somecredsubtype"
		cr.credentialType = "somecredtype"
		cr.includeIssuerCredentials = false
		cr.x509RequestType = "pkcs10"
		
		return cr
	}
	
	def createX509CredentialRequestParams(){
		X509CredentialRequestParams retval = of.createX509CredentialRequestParams()
		
		retval.alias = "somealias"
		retval.credentialSubType = "somecredentialsubtype"
		retval.description = "somedescription"
		retval.keyAlg = "somekeyalg"
		retval.keySpec = "somekeyspec"
		retval.subjectDN = "CN=somedn"
		
		return retval
	}

	def createCredentials(){
		return [createCredential(1),createCredential(2)]
	}
	
	def createCredential(int id){
		Credential c = csMessageOf.createCredential();
		

		c.credentialRequestId = id
		c.credentialType = "SomeCredentialType" +id
		c.credentialSubType = "SomeCredentialSubType" +id
		c.uniqueId = "SomeOriginatorUniqueId" +id
		c.displayName = "SomeOrignatorDisplayName" +id
		c.serialNumber = "SomeSerialNumber" +id
		c.issuerId = "SomeIssuerId" +id
		c.status = 100
		c.credentialData = "12345ABCEF" +id
		
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
		Attribute attr = csMessageOf.createAttribute();
		attr.setKey("someattrkey" +id)
		attr.setValue("someattrvalue" +id)
		
		c.setAttributes(new Credential.Attributes())
		c.getAttributes().getAttribute().add(attr)

		c.setUsages(new Credential.Usages())
		c.getUsages().getUsage().add("someusage" +id)
		

		return c
	}
}
