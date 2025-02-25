package org.signatureservice.messages.v2x.backend

import org.apache.xml.security.Init
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Base64
import org.signatureservice.messages.csmessages.CSMessageParserManager
import org.signatureservice.messages.csmessages.CSMessageResponseData
import org.signatureservice.messages.csmessages.DefaultCSMessageParser
import org.signatureservice.messages.csmessages.PayloadParserRegistry
import org.signatureservice.messages.csmessages.jaxb.CSMessage
import org.signatureservice.messages.v2x.backend.jaxb.ValidityUnitType
import org.signatureservice.messages.v2x.registration.V2XPayloadParser
import org.signatureservice.messages.v2x.registration.jaxb.ObjectFactory
import spock.lang.Specification

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Security

import static org.signatureservice.messages.TestUtils.*
import static org.signatureservice.messages.v2x.registration.V2XPayloadParserSpec.genRegions
import static org.signatureservice.messages.csmessages.DefaultCSMessageParserSpec.*

/**
 * Unit tests for V2XBackendPayloadParser
 *
 * @author Philip Vendil 2020-05-30
 */
class V2XBackendPayloadParserSpec extends Specification {

    V2XBackendPayloadParser pp
    ObjectFactory of = new ObjectFactory()
    org.signatureservice.messages.csmessages.jaxb.ObjectFactory csMessageOf = new org.signatureservice.messages.csmessages.jaxb.ObjectFactory()

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
        pp.getJAXBPackage() == "org.signatureservice.messages.v2x.backend.jaxb"
        pp.getNameSpace() == "http://certificateservices.org/xsd/v2x_backend_2_0"
        pp.getSchemaAsInputStream("2.0") != null
        pp.getDefaultPayloadVersion() == "2.0"
        pp.getSupportedVersions() == ["2.0"] as String[]
        pp.getRelatedSchemas("2.0") == [V2XPayloadParser.V2X_XSD_SCHEMA_2_0_RESOURCE_LOCATION] as String[]
    }

    def "Verify that generateSignECRequest() generates a valid xml message and generateSignECResponse() generates a valid CSMessageResponseData"(){
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        byte[] requestMessage = pp.generateSignCertRequest(TEST_ID, "SOMESOURCEID",  "someorg",
                "SomeITSId", 1,2,"someEAId", "someECProfile", ValidityUnitType.HOURS, 100,
                 genRegions([1,2,3]),"SomeVerificationKeys".getBytes("UTF-8"),"SomeEncryptionKeys".getBytes("UTF-8"),"SomeRequestHash".getBytes("UTF-8"),  createOriginatorCredential(), null)
        printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.SignCertRequest
        then:
        messageContainsPayload requestMessage, "v2xb:SignCertRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","SignCertRequest", createOriginatorCredential(), csMessageParser)

        payloadObject.canonicalId == "SomeITSId"
        payloadObject.caId == "someEAId"
        payloadObject.assuranceLevel == 1
        payloadObject.confidenceLevel == 2
        payloadObject.validityUnit == "hours"
        payloadObject.validityDuration == 100
        payloadObject.profileName == "someECProfile"
        payloadObject.regions.identifiedRegions.countryOnly.size() == 3
        payloadObject.regions.identifiedRegions.countryOnly[0] == 1
        payloadObject.regions.identifiedRegions.countryOnly[1] == 2
        payloadObject.regions.identifiedRegions.countryOnly[2] == 3
        payloadObject.publicVerificationKey == new String(Base64.encode("SomeVerificationKeys".getBytes("UTF-8")))
        payloadObject.publicEncryptionKey == new String(Base64.encode("SomeEncryptionKeys".getBytes("UTF-8")))
        payloadObject.requestHash == new String(Base64.encode("SomeRequestHash".getBytes("UTF-8")))

        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage)


        CSMessageResponseData rd = pp.generateSignCertResponse("SomeRelatedEndEntity", request,  "SomeITSId",
                "ok", "someMessage", "SomeResponseData".getBytes("UTF-8"))
        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.SignCertResponse

        then:
        messageContainsPayload rd.responseData, "v2xb:SignCertResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "SignCertResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","SignCertResponse", createOriginatorCredential(), csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)
        payloadObject.canonicalId == "SomeITSId"
        payloadObject.responseCode == "ok"
        payloadObject.message == "someMessage"
        payloadObject.responseData == new String(Base64.encode("SomeResponseData".getBytes("UTF-8")))

    }

    def "Verify that generateSignCertRequest() generates a valid xml message with minimal values and generateSignECResponse() generates a valid CSMessageResponseData"(){
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        byte[] requestMessage = pp.generateSignCertRequest(TEST_ID, "SOMESOURCEID",  "someorg",
                "SomeITSId", null,null,"someEAId", "someECProfile", null, null,
                null,"SomeVerificationKeys".getBytes("UTF-8"),null,  "SomeRequestHash".getBytes("UTF-8"), null, null)
        printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.SignCertRequest
        then:
        messageContainsPayload requestMessage, "v2xb:SignCertRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","SignCertRequest", null, csMessageParser)

        payloadObject.canonicalId == "SomeITSId"
        payloadObject.caId == "someEAId"
        payloadObject.profileName == "someECProfile"
        payloadObject.publicVerificationKey == new String(Base64.encode("SomeVerificationKeys".getBytes("UTF-8")))
        payloadObject.requestHash == new String(Base64.encode("SomeRequestHash".getBytes("UTF-8")))
        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage)


        CSMessageResponseData rd = pp.generateSignCertResponse("SomeRelatedEndEntity", request,  "SomeITSId",
                "ok", null, "SomeResponseData".getBytes("UTF-8"))
        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.SignCertResponse

        then:
        messageContainsPayload rd.responseData, "v2xb:SignCertResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "SignCertResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","SignCertResponse", null, csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)
        payloadObject.canonicalId == "SomeITSId"
        payloadObject.responseCode == "ok"
        payloadObject.responseData == new String(Base64.encode("SomeResponseData".getBytes("UTF-8")))

    }

    def "Verify that generateSignErrorRequest() generates a valid xml message and generateSignErrorResponse() generates a valid CSMessageResponseData"(){
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        byte[] requestMessage = pp.generateSignErrorRequest(TEST_ID, "SOMESOURCEID",  "someorg",
                "SomeITSId", "someEAId", "ok", "someMessage", "SomeRequestHash".getBytes("UTF-8"),createOriginatorCredential(), null)
        printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.SignErrorRequest
        then:
        messageContainsPayload requestMessage, "v2xb:SignErrorRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","SignErrorRequest", createOriginatorCredential(), csMessageParser)

        payloadObject.canonicalId == "SomeITSId"
        payloadObject.caId == "someEAId"
        payloadObject.responseCode == "ok"
        payloadObject.message == "someMessage"
        payloadObject.requestHash == new String(Base64.encode("SomeRequestHash".getBytes("UTF-8")))

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
