package org.signatureservice.messages.csexport.protocol

import org.apache.xml.security.Init
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.signatureservice.messages.MessageContentException
import org.signatureservice.messages.MessageProcessingException
import org.signatureservice.messages.csexport.data.CSExportDataParser
import org.certificateservices.messages.csexport.data.CSExportDataParserSpec
import org.signatureservice.messages.csexport.data.jaxb.CSExport
import org.certificateservices.messages.csexport.protocol.jaxb.*
import org.signatureservice.messages.csexport.protocol.jaxb.GetCSExportResponse
import org.signatureservice.messages.csexport.protocol.jaxb.QueryParameter
import org.signatureservice.messages.csmessages.CSMessageParserManager
import org.signatureservice.messages.csmessages.CSMessageResponseData
import org.signatureservice.messages.csmessages.DefaultCSMessageParser
import org.signatureservice.messages.csmessages.PayloadParserRegistry
import org.signatureservice.messages.csmessages.jaxb.CSMessage
import org.signatureservice.messages.csmessages.jaxb.RequestStatus
import org.signatureservice.messages.csmessages.jaxb.ObjectFactory
import spock.lang.Specification

import java.security.Security

class CSExportProtocolPayloadParserSpec extends Specification {

	CSExportProtocolPayloadParser pp;
	CSExportDataParser csExportDataParser;
	org.signatureservice.messages.csexport.protocol.jaxb.ObjectFactory of = new org.signatureservice.messages.csexport.protocol.jaxb.ObjectFactory()
    ObjectFactory csMessageOf = new ObjectFactory()

	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Init.init();
	}

	DefaultCSMessageParser csMessageParser

	def setup(){
		org.certificateservices.messages.TestUtils.setupRegisteredPayloadParser();
		csMessageParser = CSMessageParserManager.getCSMessageParser()
		pp = PayloadParserRegistry.getParser(CSExportProtocolPayloadParser.NAMESPACE);
		csExportDataParser = new CSExportDataParser(csMessageParser.messageSecurityProvider, true)
	}
	
	def "Verify that JAXBPackage(), getNameSpace(), getSchemaAsInputStream(), getSupportedVersions(), getDefaultPayloadVersion() returns the correct values"(){
		expect:
		pp.getJAXBPackage() == "org.certificateservices.messages.csexport.protocol.jaxb"
		pp.getNameSpace() == "http://certificateservices.org/xsd/cs_export_protocol2_0"
		pp.getSchemaAsInputStream("2.0") != null
		pp.getDefaultPayloadVersion() == "2.0"
		pp.getSupportedVersions() == ["2.0"] as String[]
	}


	def "Verify that genGetCSExportRequest() generates a valid xml message and genGetCSExportResponse() generates a valid CSMessageResponseData without any query paramters"(){
		when:
		csMessageParser.sourceId = "SOMEREQUESTER"
		byte[] requestMessage = pp.genGetCSExportRequest(org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.TEST_ID, "SOMESOURCEID", "someorg","1.0",null, org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.createOriginatorCredential( ), null)
        //printXML(requestMessage)
		def xml = org.certificateservices.messages.TestUtils.slurpXml(requestMessage)
		def payloadObject = xml.payload.GetCSExportRequest
		then:
        org.certificateservices.messages.TestUtils.messageContainsPayload requestMessage, "csexp:GetCSExportRequest"
        org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","GetCSExportRequest", org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.createOriginatorCredential(), csMessageParser)
		payloadObject.@exportDataVersion == "1.0"
		payloadObject.queryParameters.size() == 0
		when:
		csMessageParser.sourceId = "SOMESOURCEID"
		CSMessage request = pp.parseMessage(requestMessage)
		CSExport csExportData = csExportDataParser.genCSExport_1_xAsObject("1.0",[CSExportDataParserSpec.genOrganisation()], [CSExportDataParserSpec.genTokenType()])
		CSMessageResponseData rd = pp.genGetCSExportResponse("SomeRelatedEndEntity", request, "1.0", csExportData, null)
		//printXML(rd.responseData)
		xml = org.certificateservices.messages.TestUtils.slurpXml(rd.responseData)
		payloadObject = xml.payload.GetCSExportResponse
		
		then:
        org.certificateservices.messages.TestUtils.messageContainsPayload rd.responseData, "csexp:GetCSExportResponse"

        org.certificateservices.messages.TestUtils.verifyCSMessageResponseData  rd, "SOMEREQUESTER", org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.TEST_ID, false, "GetCSExportResponse", "SomeRelatedEndEntity"
        org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","GetCSExportResponse", org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.createOriginatorCredential(), csMessageParser)
        org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.verifySuccessfulBasePayload(payloadObject, org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.TEST_ID)


		when:
		CSMessage resp = pp.parseMessage(rd.responseData)
        GetCSExportResponse pl = resp.getPayload().any
		CSExport csExport = pp.getCSExportDataFromResponse(resp)

		then:
		pl.exportDataVersion == "1.0"
		csExport.organisations.organisation.size() == 1
		csExport.tokenTypes.tokenType.size() == 1
		csExport.signature.keyInfo.content.size() == 1

		when:
		CSMessageResponseData  unAuthFailureResponse = csMessageParser.genCSFailureResponse("UNKNOWN", requestMessage , RequestStatus.NOTAUTHORIZED, "Not authorized to process request.", "SOMESOURCEID", null)
		CSMessage failureResponse = (CSMessage) pp.parseMessage(unAuthFailureResponse.responseData, false, false)
		pp.getCSExportDataFromResponse(failureResponse)

		then:
		def e = thrown(MessageProcessingException)
		assert e.message.equals("Failure CSExport response; status: " + RequestStatus.NOTAUTHORIZED.toString() + ", message: Not authorized to process request.")

		when:
		unAuthFailureResponse = csMessageParser.genCSFailureResponse("UNKNOWN", requestMessage , RequestStatus.APPROVALREQUIRED, "Approval is required to process request.", "SOMESOURCEID", null)
		failureResponse = (CSMessage) pp.parseMessage(unAuthFailureResponse.responseData, false, false)
		pp.getCSExportDataFromResponse(failureResponse)

		then:
		e = thrown(MessageProcessingException)
		assert e.message.equals("Failure CSExport response; status: " + RequestStatus.APPROVALREQUIRED.toString() + ", message: Approval is required to process request.")

		when:
		unAuthFailureResponse = csMessageParser.genCSFailureResponse("UNKNOWN", requestMessage , RequestStatus.ERROR, "Error occurred to process request.", "SOMESOURCEID", null)
		failureResponse = (CSMessage) pp.parseMessage(unAuthFailureResponse.responseData, false, false)
		pp.getCSExportDataFromResponse(failureResponse)

		then:
		e = thrown(MessageProcessingException)
		assert e.message.equals("Failure CSExport response; status: " + RequestStatus.ERROR.toString() + ", message: Error occurred to process request.")

		when:
		unAuthFailureResponse = csMessageParser.genCSFailureResponse("UNKNOWN", requestMessage , RequestStatus.ILLEGALARGUMENT, "Wrong argument found in the request.", "SOMESOURCEID", null)
		failureResponse = (CSMessage) pp.parseMessage(unAuthFailureResponse.responseData, false, false)
		pp.getCSExportDataFromResponse(failureResponse)

		then:
		e = thrown(MessageContentException)
		assert e.message.equals("Failure CSExport response; status: " + RequestStatus.ILLEGALARGUMENT.toString() + ", message: Wrong argument found in the request.")
	}

	def "Verify that generation using query parameters generates valid XML"(){
		setup:
        QueryParameter q1 = new QueryParameter()
		q1.type = "SomeType1"
		q1.value = "SomeValue"
		QueryParameter q2 = new QueryParameter()
		q2.type = "SomeType2"

		when:
		byte[] requestMessage = pp.genGetCSExportRequest(org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.TEST_ID, "SOMESOURCEID", "someorg","1.0",[q1, q2], org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.createOriginatorCredential( ), null)
		//printXML(requestMessage)
		def xml = org.certificateservices.messages.TestUtils.slurpXml(requestMessage)
		def payloadObject = xml.payload.GetCSExportRequest
		then:
		payloadObject.queryParameters.size() == 1
		payloadObject.queryParameters.queryParameter.size() == 2
		payloadObject.queryParameters.queryParameter[0].type == "SomeType1"
		payloadObject.queryParameters.queryParameter[0].value == "SomeValue"
		payloadObject.queryParameters.queryParameter[1].type == "SomeType2"

		when:
		pp.parseMessage(pp.genGetCSExportRequest(org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.TEST_ID, "SOMESOURCEID", "someorg","1.0",[new QueryParameter()], org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.createOriginatorCredential( ), null));
		then:
		thrown MessageContentException
	}

}
