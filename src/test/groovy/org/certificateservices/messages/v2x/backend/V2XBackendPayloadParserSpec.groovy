package org.certificateservices.messages.v2x.backend

import org.apache.xml.security.Init
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Base64
import org.certificateservices.messages.csmessages.CSMessageParserManager
import org.certificateservices.messages.csmessages.CSMessageResponseData
import org.certificateservices.messages.csmessages.DefaultCSMessageParser
import org.certificateservices.messages.csmessages.PayloadParserRegistry
import org.certificateservices.messages.csmessages.jaxb.CSMessage
import org.certificateservices.messages.v2x.backend.jaxb.ValidityUnitType
import org.certificateservices.messages.v2x.registration.V2XPayloadParser
import org.certificateservices.messages.v2x.registration.jaxb.ObjectFactory
import spock.lang.Specification

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Security

import static org.certificateservices.messages.TestUtils.*
import static org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.*
import static org.certificateservices.messages.v2x.registration.V2XPayloadParserSpec.genRegions

/**
 * Unit tests for V2XBackendPayloadParser
 *
 * @author Philip Vendil 2020-05-30
 */
class V2XBackendPayloadParserSpec extends Specification {

    V2XBackendPayloadParser pp
    ObjectFactory of = new ObjectFactory()
    org.certificateservices.messages.csmessages.jaxb.ObjectFactory csMessageOf = new org.certificateservices.messages.csmessages.jaxb.ObjectFactory()

    DefaultCSMessageParser csMessageParser

    KeyPair signKeys

    def setupSpec(){
        Security.addProvider(new BouncyCastleProvider())
        Init.init()

        // Use english - make test locale independent.
        Locale.setDefault(new Locale("en", "US"))
    }

    def setup(){
        setupRegisteredPayloadParser()
        csMessageParser = CSMessageParserManager.getCSMessageParser()
        pp = PayloadParserRegistry.getParser(V2XBackendPayloadParser.NAMESPACE)

        KeyPairGenerator kf = KeyPairGenerator.getInstance("EC","BC")
        kf.initialize(ECNamedCurveTable.getParameterSpec("P-256"))
        signKeys = kf.generateKeyPair()
    }

    def "Verify that JAXBPackage(), getNameSpace(), getSchemaAsInputStream(), getSupportedVersions(), getDefaultPayloadVersion() returns the correct values"(){
        expect:
        pp.getJAXBPackage() == "org.certificateservices.messages.v2x.backend.jaxb"
        pp.getNameSpace() == "http://certificateservices.org/xsd/v2x_backend_2_0"
        pp.getSchemaAsInputStream("2.0") != null
        pp.getDefaultPayloadVersion() == "2.0"
        pp.getSupportedVersions() == ["2.0"] as String[]
        pp.getRelatedSchemas("2.0") == [V2XPayloadParser.V2X_XSD_SCHEMA_2_0_RESOURCE_LOCATION] as String[]
    }

    def "Verify that generateSignECRequest() generates a valid xml message and generateSignECResponse() generates a valid CSMessageResponseData"(){
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        byte[] requestMessage = pp.generateSignECRequest(TEST_ID, "SOMESOURCEID",  "someorg",
                "SomeITSId", 1,2,"someEAName", "someECProfile", ValidityUnitType.HOURS, 100,
                 genRegions([1,2,3]),"SomeVerificationKeys".getBytes("UTF-8"),"SomeEncryptionKeys".getBytes("UTF-8"),  createOriginatorCredential(), null)
        printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.SignECRequest
        then:
        messageContainsPayload requestMessage, "v2xb:SignECRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","SignECRequest", createOriginatorCredential(), csMessageParser)

        payloadObject.canonicalId == "SomeITSId"
        payloadObject.eaName == "someEAName"
        payloadObject.assuranceLevel == 1
        payloadObject.confidenceLevel == 2
        payloadObject.validityUnit == "hours"
        payloadObject.validityDuration == 100
        payloadObject.ecProfile == "someECProfile"
        payloadObject.regions.identifiedRegions.countryOnly.size() == 3
        payloadObject.regions.identifiedRegions.countryOnly[0] == 1
        payloadObject.regions.identifiedRegions.countryOnly[1] == 2
        payloadObject.regions.identifiedRegions.countryOnly[2] == 3
        payloadObject.publicVerificationKey == new String(Base64.encode("SomeVerificationKeys".getBytes("UTF-8")))
        payloadObject.publicEncryptionKey == new String(Base64.encode("SomeEncryptionKeys".getBytes("UTF-8")))

        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage)


        CSMessageResponseData rd = pp.generateSignECResponse("SomeRelatedEndEntity", request,  "SomeITSId",
                "ok", "someMessage", "SomeResponseData".getBytes("UTF-8"))
        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.SignECResponse

        then:
        messageContainsPayload rd.responseData, "v2xb:SignECResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "SignECResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","SignECResponse", createOriginatorCredential(), csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)
        payloadObject.canonicalId == "SomeITSId"
        payloadObject.responseCode == "ok"
        payloadObject.message == "someMessage"
        payloadObject.responseData == new String(Base64.encode("SomeResponseData".getBytes("UTF-8")))

    }

    def "Verify that generateSignECRequest() generates a valid xml message with minimal values and generateSignECResponse() generates a valid CSMessageResponseData"(){
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        byte[] requestMessage = pp.generateSignECRequest(TEST_ID, "SOMESOURCEID",  "someorg",
                "SomeITSId", null,null,"someEAName", "someECProfile", null, null,
                null,"SomeVerificationKeys".getBytes("UTF-8"),null,  null, null)
        printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.SignECRequest
        then:
        messageContainsPayload requestMessage, "v2xb:SignECRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","SignECRequest", null, csMessageParser)

        payloadObject.canonicalId == "SomeITSId"
        payloadObject.eaName == "someEAName"
        payloadObject.ecProfile == "someECProfile"
        payloadObject.publicVerificationKey == new String(Base64.encode("SomeVerificationKeys".getBytes("UTF-8")))

        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage)


        CSMessageResponseData rd = pp.generateSignECResponse("SomeRelatedEndEntity", request,  "SomeITSId",
                "ok", null, "SomeResponseData".getBytes("UTF-8"))
        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.SignECResponse

        then:
        messageContainsPayload rd.responseData, "v2xb:SignECResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "SignECResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","SignECResponse", null, csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)
        payloadObject.canonicalId == "SomeITSId"
        payloadObject.responseCode == "ok"
        payloadObject.responseData == new String(Base64.encode("SomeResponseData".getBytes("UTF-8")))

    }

    def "Verify that generateSignErrorRequest() generates a valid xml message and generateSignErrorResponse() generates a valid CSMessageResponseData"(){
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        byte[] requestMessage = pp.generateSignErrorRequest(TEST_ID, "SOMESOURCEID",  "someorg",
                "SomeITSId", "someEA", "ok", "someMessage", createOriginatorCredential(), null)
        printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.SignErrorRequest
        then:
        messageContainsPayload requestMessage, "v2xb:SignErrorRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","SignErrorRequest", createOriginatorCredential(), csMessageParser)

        payloadObject.canonicalId == "SomeITSId"
        payloadObject.eaName == "someEA"
        payloadObject.responseCode == "ok"
        payloadObject.message == "someMessage"

        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage)


        CSMessageResponseData rd = pp.generateSignErrorResponse("SomeRelatedEndEntity", request,  "SomeITSId",
                "ok", "someMessage", "SomeResponseData".getBytes("UTF-8"))
        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.SignErrorResponse

        then:
        messageContainsPayload rd.responseData, "v2xb:SignErrorResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "SignErrorResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","SignErrorResponse", createOriginatorCredential(), csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)
        payloadObject.canonicalId == "SomeITSId"
        payloadObject.responseCode == "ok"
        payloadObject.message == "someMessage"
        payloadObject.responseData == new String(Base64.encode("SomeResponseData".getBytes("UTF-8")))

    }
}
