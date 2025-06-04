package se.signatureservice.messages.sysconfig;

import org.apache.xml.security.Init
import org.bouncycastle.jce.provider.BouncyCastleProvider
import se.signatureservice.messages.csmessages.CSMessageParserManager;
import se.signatureservice.messages.csmessages.CSMessageResponseData;
import se.signatureservice.messages.csmessages.DefaultCSMessageParser;
import se.signatureservice.messages.csmessages.PayloadParserRegistry;
import se.signatureservice.messages.csmessages.jaxb.CSMessage;
import se.signatureservice.messages.csmessages.jaxb.Organisation;
import se.signatureservice.messages.sysconfig.jaxb.ConfigurationData;
import se.signatureservice.messages.sysconfig.jaxb.ObjectFactory;
import se.signatureservice.messages.sysconfig.jaxb.Property;
import se.signatureservice.messages.sysconfig.jaxb.SystemConfiguration;

import spock.lang.Specification

import java.security.Security

import static se.signatureservice.messages.TestUtils.*
import static se.signatureservice.messages.csmessages.DefaultCSMessageParserSpec.*

class SysConfigPayloadParserSpec extends Specification {
	
	SysConfigPayloadParser pp;
	ObjectFactory of = new ObjectFactory()
	se.signatureservice.messages.csmessages.jaxb.ObjectFactory csMessageOf = new se.signatureservice.messages.csmessages.jaxb.ObjectFactory()

	DefaultCSMessageParser csMessageParser
	
	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Init.init()
	}
	
	def setup(){
		setupRegisteredPayloadParser();
		csMessageParser = CSMessageParserManager.getCSMessageParser()
		pp = PayloadParserRegistry.getParser(SysConfigPayloadParser.NAMESPACE)
	}
	
	def "Verify that JAXBPackage(), getNameSpace(), getSchemaAsInputStream(), getSupportedVersions(), getDefaultPayloadVersion() returns the correct values"(){
		expect:
		pp.getJAXBPackage() == "se.signatureservice.messages.sysconfig.jaxb"
		pp.getNameSpace() == "http://certificateservices.org/xsd/sysconfig2_0"
		pp.getSchemaAsInputStream("2.0") != null
		pp.getDefaultPayloadVersion() == "2.0"
		pp.getSupportedVersions() == ["2.0"] as String[]
	}

	def "Verify that generateGetActiveConfigurationRequest() generates a valid xml message and generateGetActiveConfigurationResponse() generates a valid CSMessageResponseData"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.generateGetActiveConfigurationRequest(TEST_ID, "SOMESOURCEID", "someorg", "someapp", createOriginatorCredential(), null)
//        printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.GetActiveConfigurationRequest
		then:
		messageContainsPayload requestMessage, "sysconfig:GetActiveConfigurationRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","GetActiveConfigurationRequest", createOriginatorCredential(), csMessageParser)
		payloadObject.application == "someapp"
		payloadObject.organisationShortName == "someorg"
		
		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.generateGetActiveConfigurationResponse("SomeRelatedEndEntity", request, generateSystemConfiguration(), null)
//		printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.GetActiveConfigurationResponse
		
		then:
		messageContainsPayload rd.responseData, "sysconfig:GetActiveConfigurationResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "GetActiveConfigurationResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","GetActiveConfigurationResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		payloadObject.systemConfiguration.application == "someapp"
	
		payloadObject.systemConfiguration.configurationData.property[0].key == "somekey"
		payloadObject.systemConfiguration.configurationData.property[0].value == "somevalue"
		
		payloadObject.systemConfiguration.organisation.shortName == "orgshortname"
		payloadObject.systemConfiguration.organisation.displayName == "orgDisplayName"
		payloadObject.systemConfiguration.organisation.obfuscatedName == "obfuscatedname"
		payloadObject.systemConfiguration.organisation.matchAdminWith == "1"
		payloadObject.systemConfiguration.organisation.issuerDistinguishedName == "CN=testdn"
		
		payloadObject.systemConfiguration.adminUniqueId == "someUniqueId"
		payloadObject.systemConfiguration.adminDisplayName == "someAdmin"
		payloadObject.systemConfiguration.description == "somedescription"
		
		expect:
		pp.parseMessage(rd.responseData)

	}
	
	def "Verify that generatePublishConfigurationRequest() generates a valid xml message and generatePublishConfigurationResponse() generates a valid CSMessageResponseData"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.generatePublishConfigurationRequest(TEST_ID, "SOMESOURCEID", "someorg", generateSystemConfiguration(), createOriginatorCredential(), null)
        //printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.PublishConfigurationRequest
		then:
		messageContainsPayload requestMessage, "sysconfig:PublishConfigurationRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","PublishConfigurationRequest", createOriginatorCredential(), csMessageParser)


		payloadObject.systemConfiguration.application == "someapp"
		
		payloadObject.systemConfiguration.configurationData.property[0].key == "somekey"
		payloadObject.systemConfiguration.configurationData.property[0].value == "somevalue"
			
		payloadObject.systemConfiguration.organisation.shortName == "orgshortname"
		payloadObject.systemConfiguration.organisation.obfuscatedName == "obfuscatedname"
		payloadObject.systemConfiguration.organisation.displayName == "orgDisplayName"
		payloadObject.systemConfiguration.organisation.matchAdminWith == "1"
		payloadObject.systemConfiguration.organisation.issuerDistinguishedName == "CN=testdn"
			
		payloadObject.systemConfiguration.adminUniqueId == "someUniqueId"
		payloadObject.systemConfiguration.adminDisplayName == "someAdmin"
		payloadObject.systemConfiguration.description == "somedescription"
		
		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		
		CSMessageResponseData rd = pp.generatePublishConfigurationResponse("SomeRelatedEndEntity", request,  null)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.PublishConfigurationResponse
		
		then:
		messageContainsPayload rd.responseData, "sysconfig:PublishConfigurationResponse"
		
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "PublishConfigurationResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","PublishConfigurationResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)
		
		expect:
		pp.parseMessage(rd.responseData)

	}
	
	private SystemConfiguration generateSystemConfiguration(){
		
		Property prop = of.createProperty();
		prop.key = "somekey"
		prop.value = "somevalue"
		
		ConfigurationData configurationData = of.createConfigurationData()
		configurationData.getProperty().add(prop)
		
		Organisation org = csMessageOf.createOrganisation();
		org.shortName = "orgshortname"
		org.displayName = "orgDisplayName"
		org.obfuscatedName = "obfuscatedname"
		org.issuerDistinguishedName = "CN=testdn"
		org.matchAdminWith = new BigInteger(1)
		
		
		SystemConfiguration sc = of.createSystemConfiguration();
		sc.adminDisplayName = "someAdmin"
		sc.adminUniqueId = "someUniqueId"
		sc.application = "someapp"
		sc.organisation = org
		sc.description = "somedescription"
		sc.configurationData = configurationData
		
		return sc
	}
}
