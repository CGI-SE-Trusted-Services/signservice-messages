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
package org.certificateservices.messages.signrequest

import org.apache.xml.security.Init
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.certificateservice.testutils.TestPKIA
import org.certificateservices.messages.csmessages.CSMessageParserManager
import org.certificateservices.messages.csmessages.CSMessageResponseData
import org.certificateservices.messages.csmessages.DefaultCSMessageParser
import org.certificateservices.messages.csmessages.PayloadParserRegistry
import org.certificateservices.messages.csmessages.jaxb.CSMessage
import org.certificateservices.messages.signrequest.jaxb.ObjectFactory
import org.certificateservices.messages.signrequest.jaxb.SignRequestTask
import org.certificateservices.messages.signrequest.jaxb.SignResponseTask
import org.certificateservices.messages.utils.CertUtils
import spock.lang.Shared
import spock.lang.Specification

import java.security.Security
import java.security.cert.Certificate

import static org.certificateservices.messages.TestUtils.*
import static org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.*

/**
 * Unit tests for SignRequestPayloadParser
 *
 * @author Philip Vendil 2019-10-03
 */
class SignRequestPayloadParserSpec extends Specification {

    SignRequestPayloadParser pp
    ObjectFactory of = new ObjectFactory()
    org.certificateservices.messages.csmessages.jaxb.ObjectFactory csMessageOf = new org.certificateservices.messages.csmessages.jaxb.ObjectFactory()

    @Shared Certificate rootCACert
    @Shared Certificate policyCACert
    @Shared Certificate subCACert
    @Shared Certificate endEntityCert

    def setupSpec(){
        Security.addProvider(new BouncyCastleProvider())
        Init.init()

        rootCACert = CertUtils.getCertificateChainfromPem(TestPKIA.TEST_ROOT_CA_CERT_PEM.bytes)[0]
        policyCACert = CertUtils.getCertificateChainfromPem(TestPKIA.TEST_POLICY_CA_CERT_PEM.bytes)[0]
        subCACert = CertUtils.getCertificateChainfromPem(TestPKIA.TEST_SERVER_CA_CERT_PEM.bytes)[0]
        endEntityCert = CertUtils.getCertificateChainfromPem(TestPKIA.TEST_SERVER_CERT_PEM.bytes)[0]
    }

    DefaultCSMessageParser csMessageParser
    def currentTimeZone



    def setup(){
        currentTimeZone = TimeZone.getDefault()
        TimeZone.setDefault(TimeZone.getTimeZone("Europe/Stockholm"))
        setupRegisteredPayloadParser()
        csMessageParser = CSMessageParserManager.getCSMessageParser()
        pp = PayloadParserRegistry.getParser(SignRequestPayloadParser.NAMESPACE)
    }

    def cleanup(){
        TimeZone.setDefault(currentTimeZone)
    }

    def "Verify that JAXBPackage(), getNameSpace(), getSchemaAsInputStream(), getSupportedVersions(), getDefaultPayloadVersion() returns the correct values"(){
        expect:
        pp.getJAXBPackage() == "org.certificateservices.messages.signrequest.jaxb"
        pp.getNameSpace() == "http://certificateservices.org/xsd/signrequest2_0"
        pp.getSchemaAsInputStream("2.0") != null
        pp.getDefaultPayloadVersion() == "2.0"
        pp.getSupportedVersions() == ["2.0"] as String[]
    }


    def "Verify that genSignRequest() generates a valid xml message and genSignResponse() generates a valid CSMessageResponseData"(){
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        SignRequestTask sr1 = pp.genSignRequestTask("1","someSignType1", "someKeyId1", null, "abc".bytes)
        SignRequestTask sr2 = pp.genSignRequestTask("2","someSignType2", "someKeyId2", null, "abc".bytes)
        byte[] requestMessage = pp.genSignRequest(TEST_ID, "SOMESOURCEID", "someorg",[sr1, sr2] ,createOriginatorCredential( ), null)
        //printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.SignRequest
        then:
        messageContainsPayload requestMessage, "sign:SignRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","SignRequest", createOriginatorCredential(), csMessageParser)
        payloadObject.signRequestTasks.signRequestTask.size() == 2
        def task1 = payloadObject.signRequestTasks.signRequestTask[0]
        task1.signTaskId == "1"
        task1.signType == "someSignType1"
        task1.keyId == "someKeyId1"
        task1.signRequestData == "YWJj"
        def task2 = payloadObject.signRequestTasks.signRequestTask[1]
        task2.signTaskId == "2"
        task2.signType == "someSignType2"
        task2.keyId == "someKeyId2"
        task2.signRequestData == "YWJj"

        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage)
        SignResponseTask resp1 = pp.genSignResponseTask("1","someSignType1", "someKeyId1", null, "abc".bytes, null, "def".bytes)
        SignResponseTask resp2 = pp.genSignResponseTask("2","someSignType2", "someKeyId2", [createAttribute("key1","value1"),createAttribute("key2","value2")], "abc".bytes, [endEntityCert,subCACert,policyCACert,rootCACert], "def".bytes)
        CSMessageResponseData rd = pp.genSignResponse("SomeRelatedEndEntity", request, [resp1,resp2])
//        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.SignResponse
        then:
        messageContainsPayload rd.responseData, "sign:SignResponse"
        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "SignResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","SignResponse",createOriginatorCredential(), csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)

        payloadObject.signResponseTasks.signResponseTask.size() == 2
        def r1 =  payloadObject.signResponseTasks.signResponseTask[0]
        r1.signTaskId == "1"
        r1.signType == "someSignType1"
        r1.keyId == "someKeyId1"
        r1.signResponseData == "YWJj"
        r1.publicKey == "ZGVm"
        def r2 =  payloadObject.signResponseTasks.signResponseTask[1]
        r2.signTaskId == "2"
        r2.signType == "someSignType2"
        r2.keyId == "someKeyId2"
        r2.attributes.attribute.size() == 2
        r2.attributes.attribute[0].key == "key1"
        r2.attributes.attribute[0].value == "value1"
        r2.attributes.attribute[1].key == "key2"
        r2.attributes.attribute[1].value == "value2"
        r2.signResponseData == "YWJj"
        r2.certificateChain.certificateData.size() == 4
        r2.publicKey == "ZGVm"
    }


    def "Verify that genSignRequestTask() populates a sign request task correctly"(){
        when: // generate minimal sign request task
        SignRequestTask t1 = pp.genSignRequestTask("1","someSignType1", "someKeyId1", null, "abc".bytes)
        then:
        t1.signTaskId == "1"
        t1.signType == "someSignType1"
        t1.keyId == "someKeyId1"
        t1.attributes == null
        t1.signRequestData == "abc".bytes

        when: // Generate sign request with all elements set.
        SignRequestTask t2 = pp.genSignRequestTask("1","someSignType1", "someKeyId1", [createAttribute("key1","value1"),createAttribute("key2","value2")], "abc".bytes)
        then:
        t2.signTaskId == "1"
        t2.signType == "someSignType1"
        t2.keyId == "someKeyId1"
        t2.attributes.attribute.size()
        t2.attributes.attribute[0].key == "key1"
        t2.attributes.attribute[0].value == "value1"
        t2.attributes.attribute[1].key == "key2"
        t2.attributes.attribute[1].value == "value2"
        t2.signRequestData == "abc".bytes
    }

    def "Verify that genSignResponseTask() populates a sign response task correctly"(){
        when: // generate minimal sign response task
        SignResponseTask t1 = pp.genSignResponseTask("1","someSignType1", "someKeyId1", null, "abc".bytes, null, "def".bytes)
        then:
        t1.signTaskId == "1"
        t1.signType == "someSignType1"
        t1.keyId == "someKeyId1"
        t1.attributes == null
        t1.signResponseData == "abc".bytes
        t1.certificateChain == null
        t1.publicKey == "def".bytes

        when: // Generate sign response with all elements set.
        SignResponseTask t2 = pp.genSignResponseTask("1","someSignType1", "someKeyId1", [createAttribute("key1","value1"),createAttribute("key2","value2")], "abc".bytes, [endEntityCert,subCACert,policyCACert,rootCACert], "def".bytes)
        then:
        t2.signTaskId == "1"
        t2.signType == "someSignType1"
        t2.keyId == "someKeyId1"
        t2.attributes.attribute.size()
        t2.attributes.attribute[0].key == "key1"
        t2.attributes.attribute[0].value == "value1"
        t2.attributes.attribute[1].key == "key2"
        t2.attributes.attribute[1].value == "value2"
        t2.signResponseData == "abc".bytes
        t2.certificateChain.certificateData.size() == 4
        CertUtils.getCertfromByteArray(t2.certificateChain.certificateData[0]) == endEntityCert
        CertUtils.getCertfromByteArray(t2.certificateChain.certificateData[1]) == subCACert
        CertUtils.getCertfromByteArray(t2.certificateChain.certificateData[2]) == policyCACert
        CertUtils.getCertfromByteArray(t2.certificateChain.certificateData[3]) == rootCACert
        t2.publicKey == "def".bytes
    }


}
