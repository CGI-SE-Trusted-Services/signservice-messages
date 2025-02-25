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
package org.signatureservice.messages.signrequest

import org.apache.xml.security.Init
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.certificateservice.testutils.TestPKIA
import org.signatureservice.messages.csmessages.CSMessageParserManager
import org.signatureservice.messages.csmessages.CSMessageResponseData
import org.signatureservice.messages.csmessages.DefaultCSMessageParser
import org.signatureservice.messages.csmessages.PayloadParserRegistry
import org.signatureservice.messages.csmessages.jaxb.CSMessage
import org.signatureservice.messages.signrequest.jaxb.GetPubKeyRequestTask
import org.signatureservice.messages.signrequest.jaxb.GetPubKeyResponseTask
import org.signatureservice.messages.signrequest.jaxb.ObjectFactory
import org.signatureservice.messages.signrequest.jaxb.SignRequestTask
import org.signatureservice.messages.signrequest.jaxb.SignResponseTask
import org.signatureservice.messages.utils.CertUtils
import spock.lang.Shared
import spock.lang.Specification

import java.security.Security
import java.security.cert.Certificate

import static org.signatureservice.messages.TestUtils.*
import static org.signatureservice.messages.csmessages.DefaultCSMessageParserSpec.*

/**
 * Unit tests for SignRequestPayloadParser
 *
 * @author Philip Vendil 2019-10-03
 */
class SignRequestPayloadParserSpec extends Specification {

    SignRequestPayloadParser pp
    ObjectFactory of = new ObjectFactory()
    org.signatureservice.messages.csmessages.jaxb.ObjectFactory csMessageOf = new org.signatureservice.messages.csmessages.jaxb.ObjectFactory()

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
        pp.getJAXBPackage() == "org.signatureservice.messages.signrequest.jaxb"
        pp.getNameSpace() == "http://certificateservices.org/xsd/signrequest2_0"
        pp.getSchemaAsInputStream("2.0") != null
        pp.getSchemaAsInputStream("2.1") != null
        pp.getDefaultPayloadVersion() == "2.1"
        pp.getSupportedVersions() == ["2.0","2.1"] as String[]
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

    def "Verify that genGetPubKeyRequest() generates a valid xml message and genGetPubKeyResponse() generates a valid CSMessageResponseData"(){
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        GetPubKeyRequestTask t1 = pp.genGetPubKeyRequestTask("1","someSignType1", "someKeyId1", null)
        GetPubKeyRequestTask t2 = pp.genGetPubKeyRequestTask("2","someSignType2", "someKeyId2", null)
        byte[] requestMessage = pp.genGetPubKeyRequest(TEST_ID, "SOMESOURCEID", "someorg",[t1, t2] ,createOriginatorCredential( ), null)
        printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.GetPubKeyRequest
        then:
        messageContainsPayload requestMessage, "sign:GetPubKeyRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg","GetPubKeyRequest", createOriginatorCredential(), csMessageParser)
        payloadObject.getPubKeyRequestTasks.getPubKeyRequestTask.size() == 2
        def task1 = payloadObject.getPubKeyRequestTasks.getPubKeyRequestTask[0]
        task1.taskId == "1"
        task1.signType == "someSignType1"
        task1.keyId == "someKeyId1"
        def task2 = payloadObject.getPubKeyRequestTasks.getPubKeyRequestTask[1]
        task2.taskId == "2"
        task2.signType == "someSignType2"
        task2.keyId == "someKeyId2"

        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage)
        GetPubKeyResponseTask resp1 = pp.genGetPubKeyResponseTask("1","someSignType1", "someKeyId1", null, null, "def".bytes)
        GetPubKeyResponseTask resp2 = pp.genGetPubKeyResponseTask("2","someSignType2", "someKeyId2", [createAttribute("key1","value1"),createAttribute("key2","value2")],  [endEntityCert,subCACert,policyCACert,rootCACert], "def".bytes)
        CSMessageResponseData rd = pp.genGetPubKeyResponse("SomeRelatedEndEntity", request, [resp1,resp2])
//        printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.GetPubKeyResponse
        then:
        messageContainsPayload rd.responseData, "sign:GetPubKeyResponse"
        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "GetPubKeyResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","GetPubKeyResponse",createOriginatorCredential(), csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)

        payloadObject.getPubKeyResponseTasks.getPubKeyResponseTask.size() == 2
        def r1 =  payloadObject.getPubKeyResponseTasks.getPubKeyResponseTask[0]
        r1.taskId == "1"
        r1.signType == "someSignType1"
        r1.keyId == "someKeyId1"
        r1.publicKey == "ZGVm"
        def r2 =  payloadObject.getPubKeyResponseTasks.getPubKeyResponseTask[1]
        r2.taskId == "2"
        r2.signType == "someSignType2"
        r2.keyId == "someKeyId2"
        r2.attributes.attribute.size() == 2
        r2.attributes.attribute[0].key == "key1"
        r2.attributes.attribute[0].value == "value1"
        r2.attributes.attribute[1].key == "key2"
        r2.attributes.attribute[1].value == "value2"
        r2.certificateChain.certificateData.size() == 4
        r2.publicKey == "ZGVm"
    }


    def "Verify that genGetPubKeyRequestTask() populates a GetPubKey request task correctly"(){
        when: // generate minimal sign request task
        GetPubKeyRequestTask t1 = pp.genGetPubKeyRequestTask("1","someSignType1", "someKeyId1", null)
        then:
        t1.taskId == "1"
        t1.signType == "someSignType1"
        t1.keyId == "someKeyId1"
        t1.attributes == null

        when: // Generate sign request with all elements set.
        GetPubKeyRequestTask t2 = pp.genGetPubKeyRequestTask("1","someSignType1", "someKeyId1", [createAttribute("key1","value1"),createAttribute("key2","value2")])
        then:
        t2.taskId == "1"
        t2.signType == "someSignType1"
        t2.keyId == "someKeyId1"
        t2.attributes.attribute.size()
        t2.attributes.attribute[0].key == "key1"
        t2.attributes.attribute[0].value == "value1"
        t2.attributes.attribute[1].key == "key2"
        t2.attributes.attribute[1].value == "value2"
    }

    def "Verify that genGetPubKeyResponseTask() populates a GetPubKey response task correctly"(){
        when: // generate minimal sign response task
        GetPubKeyResponseTask t1 = pp.genGetPubKeyResponseTask("1","someSignType1", "someKeyId1", null, null, "def".bytes)
        then:
        t1.taskId == "1"
        t1.signType == "someSignType1"
        t1.keyId == "someKeyId1"
        t1.attributes == null
        t1.certificateChain == null
        t1.publicKey == "def".bytes

        when: // Generate sign response with all elements set.
        GetPubKeyResponseTask t2 = pp.genGetPubKeyResponseTask("1","someSignType1", "someKeyId1", [createAttribute("key1","value1"),createAttribute("key2","value2")],  [endEntityCert,subCACert,policyCACert,rootCACert], "def".bytes)
        then:
        t2.taskId == "1"
        t2.signType == "someSignType1"
        t2.keyId == "someKeyId1"
        t2.attributes.attribute.size()
        t2.attributes.attribute[0].key == "key1"
        t2.attributes.attribute[0].value == "value1"
        t2.attributes.attribute[1].key == "key2"
        t2.attributes.attribute[1].value == "value2"
        t2.certificateChain.certificateData.size() == 4
        CertUtils.getCertfromByteArray(t2.certificateChain.certificateData[0]) == endEntityCert
        CertUtils.getCertfromByteArray(t2.certificateChain.certificateData[1]) == subCACert
        CertUtils.getCertfromByteArray(t2.certificateChain.certificateData[2]) == policyCACert
        CertUtils.getCertfromByteArray(t2.certificateChain.certificateData[3]) == rootCACert
        t2.publicKey == "def".bytes
    }
}
