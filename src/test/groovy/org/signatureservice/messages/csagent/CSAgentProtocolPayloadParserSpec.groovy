/************************************************************************
 *                                                                       *
 *  Certificate Service - Messages                                       *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signatureservice.messages.csagent

import org.apache.xml.security.Init
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.signatureservice.messages.csagent.jaxb.DiscoveredCredential
import org.signatureservice.messages.csagent.jaxb.DiscoveredCredentialData
import org.signatureservice.messages.csmessages.CSMessageParserManager
import org.signatureservice.messages.csmessages.CSMessageResponseData
import org.signatureservice.messages.csmessages.DefaultCSMessageParser
import org.signatureservice.messages.csmessages.DefaultCSMessageParserSpec
import org.signatureservice.messages.csmessages.PayloadParserRegistry
import org.signatureservice.messages.csmessages.jaxb.Attribute
import org.signatureservice.messages.csmessages.jaxb.CSMessage
import org.signatureservice.messages.csmessages.jaxb.ObjectFactory
import org.signatureservice.messages.utils.MessageGenerateUtils
import spock.lang.Specification

import java.security.MessageDigest
import java.security.Security

import static org.signatureservice.messages.csmessages.DefaultCSMessageParserSpec.*

class CSAgentProtocolPayloadParserSpec extends Specification {

	CSAgentProtocolPayloadParser pp
	org.signatureservice.messages.csexport.protocol.jaxb.ObjectFactory of = new org.signatureservice.messages.csexport.protocol.jaxb.ObjectFactory()
    ObjectFactory csMessageOf = new ObjectFactory()

	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Init.init()
	}

	DefaultCSMessageParser csMessageParser
	def currentTimeZone

	def setup(){
		currentTimeZone = TimeZone.getDefault()
		TimeZone.setDefault(TimeZone.getTimeZone("Europe/Stockholm"))
		setupRegisteredPayloadParser()
		csMessageParser = CSMessageParserManager.getCSMessageParser()
		pp = PayloadParserRegistry.getParser(CSAgentProtocolPayloadParser.NAMESPACE)
	}

	def cleanup(){
		TimeZone.setDefault(currentTimeZone)
	}
	
	def "Verify that JAXBPackage(), getNameSpace(), getSchemaAsInputStream(), getSupportedVersions(), getDefaultPayloadVersion() returns the correct values"(){
		expect:
		pp.getJAXBPackage() == "org.certificateservices.messages.csagent.jaxb"
		pp.getNameSpace() == "http://certificateservices.org/xsd/cs_agent_protocol2_0"
		pp.getSchemaAsInputStream("2.0") != null
		pp.getDefaultPayloadVersion() == "2.0"
		pp.getSupportedVersions() == ["2.0"] as String[]
	}


	def "Verify that genDiscoveredCredentialsRequest() generates a valid xml message and genDiscoveredCredentialsResponse() generates a valid CSMessageResponseData"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genDiscoveredCredentialsRequest(TEST_ID, "SOMESOURCEID", "someorg","someAgentId",TEST_ID,new Date(123123123L),createDiscoveredCredentials(), createOriginatorCredential( ), null)
        //printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.DiscoveredCredentialsRequest
		then:
        messageContainsPayload requestMessage, "a:DiscoveredCredentialsRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","DiscoveredCredentialsRequest", createOriginatorCredential(), csMessageParser)
		payloadObject.agentId == "someAgentId"
		payloadObject.scanId == TEST_ID
		payloadObject.scanTimeStamp == "1970-01-02T11:12:03.123+01:00"
		payloadObject.discoveredCredentials.dc.size() == 3
		payloadObject.discoveredCredentials.dc[0].h == "tSau8aNBz+blw3ftTCIoiO64H5E6EHEQqGfgCcF1jyQ="
		payloadObject.discoveredCredentials.dc[0].t == "1970-01-15T06:57:09.281+01:00"
		payloadObject.discoveredCredentials.dc[0].as.a.size() == 3
		payloadObject.discoveredCredentials.dc[0].as.a[0].key == "somekey1"
		payloadObject.discoveredCredentials.dc[0].as.a[0].value == "somevalue1"
		payloadObject.discoveredCredentials.dc[0].as.a[1].key == "somekey2"
		payloadObject.discoveredCredentials.dc[0].as.a[1].value == "somevalue2"
		payloadObject.discoveredCredentials.dc[0].as.a[2].key == "somekey3"
		payloadObject.discoveredCredentials.dc[0].as.a[2].value == "somevalue3"

		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		CSMessageResponseData rd = pp.genDiscoveredCredentialsResponse("SomeRelatedEndEntity", request, createHashes())
        //printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.DiscoveredCredentialsResponse
		then:
        messageContainsPayload rd.responseData, "a:DiscoveredCredentialsResponse"
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", DefaultCSMessageParserSpec.TEST_ID, false, "DiscoveredCredentialsResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","DiscoveredCredentialsResponse",createOriginatorCredential(), csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)

		payloadObject.unknownCredentials.h.size() == 3
		payloadObject.unknownCredentials.h[0] == "tSau8aNBz+blw3ftTCIoiO64H5E6EHEQqGfgCcF1jyQ="
		payloadObject.unknownCredentials.h[1] == "hHaN3uZZ7+r965crVRQxQbwjtuMzxw6LaNKXdKsJpUg="
		payloadObject.unknownCredentials.h[2] == "+ymo1TCdfDWxgNvXjGOkVaXR+0UUmjJkwI8a/0NSS+s="
	}

	def "Verify that genDiscoveredCredentialDataRequest() generates a valid xml message and genDiscoveredCredentialDataResponse() generates a valid CSMessageResponseData"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genDiscoveredCredentialDataRequest(TEST_ID, "SOMESOURCEID", "someorg","someAgentId",TEST_ID,new Date(123123123L),createDiscoveredDataCredentials(), createOriginatorCredential( ), null)
		//printXML(requestMessage)
		def xml = slurpXml(requestMessage)
		def payloadObject = xml.payload.DiscoveredCredentialDataRequest
		then:
		messageContainsPayload requestMessage, "a:DiscoveredCredentialDataRequest"
		verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","DiscoveredCredentialDataRequest", createOriginatorCredential(), csMessageParser)
		payloadObject.agentId == "someAgentId"
		payloadObject.scanId == TEST_ID
		payloadObject.scanTimeStamp == "1970-01-02T11:12:03.123+01:00"
		payloadObject.discoveredCredentialData.dcd.size() == 3
		payloadObject.discoveredCredentialData.dcd[0].h == "tSau8aNBz+blw3ftTCIoiO64H5E6EHEQqGfgCcF1jyQ="
		payloadObject.discoveredCredentialData.dcd[0].t == "1970-01-15T06:57:09.281+01:00"
		payloadObject.discoveredCredentialData.dcd[0].as.a.size() == 3
		payloadObject.discoveredCredentialData.dcd[0].as.a[0].key == "somekey1"
		payloadObject.discoveredCredentialData.dcd[0].as.a[0].value == "somevalue1"
		payloadObject.discoveredCredentialData.dcd[0].as.a[1].key == "somekey2"
		payloadObject.discoveredCredentialData.dcd[0].as.a[1].value == "somevalue2"
		payloadObject.discoveredCredentialData.dcd[0].as.a[2].key == "somekey3"
		payloadObject.discoveredCredentialData.dcd[0].as.a[2].value == "somevalue3"
		payloadObject.discoveredCredentialData.dcd[0].ct.size() == 0
		payloadObject.discoveredCredentialData.dcd[1].ct == "SomeType"
		payloadObject.discoveredCredentialData.dcd[2].ct.size() == 0

		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		CSMessageResponseData rd = pp.genDiscoveredCredentialDataResponse("SomeRelatedEndEntity", request)
		//printXML(rd.responseData)
		xml = slurpXml(rd.responseData)
		payloadObject = xml.payload.DiscoveredCredentialDataResponse
		then:
		messageContainsPayload rd.responseData, "a:DiscoveredCredentialDataResponse"
		verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "DiscoveredCredentialDataResponse", "SomeRelatedEndEntity"
		verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","DiscoveredCredentialDataResponse", createOriginatorCredential(), csMessageParser)
		verifySuccessfulBasePayload(payloadObject, TEST_ID)

	}

	private List<DiscoveredCredential> createDiscoveredCredentials(){
		return [
		        newDiscoveredCredential(1),
				newDiscoveredCredential(2),
				newDiscoveredCredential(3),
		]
	}

	MessageDigest d = MessageDigest.getInstance("SHA-256")
	private DiscoveredCredential newDiscoveredCredential(number){
		DiscoveredCredential dc = new DiscoveredCredential()
		dc.as = new DiscoveredCredential.As()
		dc.as.a.add(createAttribute("somekey1","somevalue1"))
		dc.as.a.add(createAttribute("somekey2","somevalue2"))
		dc.as.a.add(createAttribute("somekey3","somevalue3"))
		dc.h = createHash(number)
		dc.setT(MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1231029281L)))

		return dc
	}

	private List<DiscoveredCredentialData> createDiscoveredDataCredentials(){
		return [
				newDiscoveredCredentialData(1),
				newDiscoveredCredentialData(2, true),
				newDiscoveredCredentialData(3),
		]
	}

	private DiscoveredCredentialData newDiscoveredCredentialData(number, boolean withType=false){
		DiscoveredCredentialData dc = new DiscoveredCredentialData()
		dc.as = new DiscoveredCredential.As()
		dc.as.a.add(createAttribute("somekey1","somevalue1"))
		dc.as.a.add(createAttribute("somekey2","somevalue2"))
		dc.as.a.add(createAttribute("somekey3","somevalue3"))
		dc.h = createHash(number)
		dc.setT(MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1231029281L)))
		dc.c = CSMessageParserManager.getCSMessageParser().getMessageSecurityProvider().getSigningCertificate().encoded
		if(withType){
			dc.ct = "SomeType"
		}
		return dc
	}

	private String createHash(number){
		return Base64.encoder.encodeToString(d.digest(("message ${number}").getBytes()))
	}

	private Attribute createAttribute(String key, String value){
		Attribute a = new Attribute()
		a.key = key
		a.value = value
		return a
	}

	private List<String> createHashes(){
		return [
		        createHash(1),createHash(2),createHash(3)
		]
	}
}
