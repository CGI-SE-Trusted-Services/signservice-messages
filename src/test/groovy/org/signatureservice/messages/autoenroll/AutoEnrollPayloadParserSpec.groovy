package org.signatureservice.messages.autoenroll

import org.apache.xml.security.Init
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.signatureservice.messages.MessageContentException
import org.signatureservice.messages.autoenroll.jaxb.CheckStatusResponse
import org.signatureservice.messages.autoenroll.jaxb.ClientActionRequest
import org.signatureservice.messages.autoenroll.jaxb.ObjectFactory
import org.signatureservice.messages.autoenroll.jaxb.PerformFetchExistingTokensAction
import org.signatureservice.messages.autoenroll.jaxb.PerformGenerateCredentialRequestAction
import org.signatureservice.messages.autoenroll.jaxb.PerformRemoveCredentialsAction
import org.signatureservice.messages.autoenroll.jaxb.PerformedFetchExistingTokensAction
import org.signatureservice.messages.autoenroll.jaxb.PerformedGenerateCredentialRequestAction
import org.signatureservice.messages.autoenroll.jaxb.PerformedRemoveCredentialsAction
import org.signatureservice.messages.autoenroll.jaxb.TokenData
import org.signatureservice.messages.credmanagement.CredManagementPayloadParserSpec
import org.signatureservice.messages.csmessages.CSMessageParserManager
import org.signatureservice.messages.csmessages.CSMessageResponseData
import org.signatureservice.messages.csmessages.DefaultCSMessageParser
import org.signatureservice.messages.csmessages.PayloadParserRegistry
import org.signatureservice.messages.csmessages.jaxb.CSMessage
import org.signatureservice.messages.csmessages.jaxb.Credential
import org.signatureservice.messages.csmessages.jaxb.CredentialRequest
import org.signatureservice.messages.sensitivekeys.jaxb.EncodedKey
import org.signatureservice.messages.sensitivekeys.jaxb.KeyDataType
import org.signatureservice.messages.utils.CSMessageUtils
import spock.lang.Specification

import java.security.Security

import static org.signatureservice.messages.TestUtils.*
import static org.signatureservice.messages.TestUtils.*
import static org.signatureservice.messages.csmessages.DefaultCSMessageParserSpec.*

/**
 * Created by philip on 02/03/17.
 */
class AutoEnrollPayloadParserSpec extends Specification {

    AutoEnrollPayloadParser pp;
    ObjectFactory of = new ObjectFactory()
    org.signatureservice.messages.csmessages.jaxb.ObjectFactory csMessageOf = new org.signatureservice.messages.csmessages.jaxb.ObjectFactory()
    org.signatureservice.messages.sensitivekeys.jaxb.ObjectFactory sensitivekeysOf = new org.signatureservice.messages.sensitivekeys.jaxb.ObjectFactory()

    Credential wrappingCredential = CredManagementPayloadParserSpec.createCredential()
    Credential credential = wrappingCredential
    CredentialRequest credentialRequest = CredManagementPayloadParserSpec.createCredentialRequest()


    def setupSpec(){
        Security.addProvider(new BouncyCastleProvider())
        Init.init();
    }

    DefaultCSMessageParser csMessageParser

    def setup(){
        setupRegisteredPayloadParser();
        csMessageParser = CSMessageParserManager.getCSMessageParser()
        pp = PayloadParserRegistry.getParser(AutoEnrollPayloadParser.NAMESPACE);
    }

    def "Verify that JAXBPackage(), getNameSpace(), getSchemaAsInputStream(), getSupportedVersions(), getDefaultPayloadVersion() returns the correct values"(){
        expect:
        pp.getJAXBPackage() == "org.signatureservice.messages.autoenroll.jaxb"
        pp.getNameSpace() == "http://certificateservices.org/xsd/autoenroll2_x"
        pp.getSchemaAsInputStream("2.0") != null
        pp.getDefaultPayloadVersion() == "2.0"
        pp.getSupportedVersions() == ["2.0"] as String[]
    }

    def "Verify that CheckStatusRequest and CheckStatusResponse is generated correctly"() {
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"
        byte[] requestMessage = pp.genCheckStatusRequest(TEST_ID, "SOMESOURCEID", "someorg", [pp.genCheckStatusRequestType("SMIME", [credential]),pp.genCheckStatusRequestType("SECURENETWORK", [credential])], createOriginatorCredential(), null)
        //printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.CheckStatusRequest
        then:
        messageContainsPayload requestMessage, "ae:CheckStatusRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg", "CheckStatusRequest", createOriginatorCredential(), csMessageParser, false)

        payloadObject.type[0].autoEnrollmentProfile == "SMIME"
        payloadObject.type[0].currentCredentials.credential.size() == 1
        payloadObject.type[1].autoEnrollmentProfile == "SECURENETWORK"
        payloadObject.type[1].currentCredentials.credential.size() == 1

        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage, false, false)

        CheckStatusResponse.Type.PerformActions sMimePerformActions = of.createCheckStatusResponseTypePerformActions()
        sMimePerformActions.setFetchExistingTokens(pp.genPerformFetchExistingTokensAction())

        CheckStatusResponse.Type.PerformActions secureNetworkPerformActions = of.createCheckStatusResponseTypePerformActions()
        secureNetworkPerformActions.setRemoveCredentials(pp.genPerformRemoveCredentialsAction([credential]))

        List types = [pp.genCheckStatusResponseType("SMIME",sMimePerformActions),
                      pp.genCheckStatusResponseType("SECURENETWORK",secureNetworkPerformActions)]

        CSMessageResponseData rd = pp.genCheckStatusResponse("SomeRelatedEndEntity", request,types, null)
        //printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.CheckStatusResponse

        then:
        messageContainsPayload rd.responseData, "ae:CheckStatusResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "CheckStatusResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","CheckStatusResponse", createOriginatorCredential(), csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)

        payloadObject.type[0].autoEnrollmentProfile == "SMIME"
        payloadObject.type[0].performActions.fetchExistingTokens.size() == 1
        payloadObject.type[1].autoEnrollmentProfile == "SECURENETWORK"
        payloadObject.type[1].performActions.removeCredentials.credential.size() == 1
        when:
        CSMessage r = pp.parseMessage(rd.responseData)
        then:
        CSMessageUtils.getPayload(r).type.size() == 2
    }

    def "Verify that ClientActionRequest and ClientActionResponse is generated correctly"() {
        when:
        csMessageParser.sourceId = "SOMEREQUESTER"

        ClientActionRequest.Type.Actions smimeActions = of.createClientActionRequestTypeActions()
        smimeActions.setFetchExistingTokens(pp.genPerformedFetchExistingTokensAction())

        ClientActionRequest.Type.Actions secureNetworkActions = of.createClientActionRequestTypeActions()
        secureNetworkActions.setRemoveCredentials(pp.genPerformedRemoveCredentialsAction([credential]))

        List types = [pp.genClientActionRequestType("SMIME", [credential], smimeActions),
                                                pp.genClientActionRequestType("SECURENETWORK", [credential], secureNetworkActions)]

        byte[] requestMessage = pp.genClientActionRequest(TEST_ID, "SOMESOURCEID", "someorg", types, createOriginatorCredential(), null)
        //printXML(requestMessage)
        def xml = slurpXml(requestMessage)
        def payloadObject = xml.payload.ClientActionRequest
        then:
        messageContainsPayload requestMessage, "ae:ClientActionRequest"
        verifyCSHeaderMessage(requestMessage, xml, "SOMEREQUESTER", "SOMESOURCEID", "someorg", "ClientActionRequest", createOriginatorCredential(), csMessageParser, false)

        payloadObject.type[0].autoEnrollmentProfile == "SMIME"
        payloadObject.type[0].currentCredentials.credential.size() == 1
        payloadObject.type[0].actions.fetchExistingTokens.size() == 1
        payloadObject.type[1].autoEnrollmentProfile == "SECURENETWORK"
        payloadObject.type[1].currentCredentials.credential.size() == 1
        payloadObject.type[1].actions.removeCredentials.credential.size() == 1

        when:
        csMessageParser.sourceId = "SOMESOURCEID"
        CSMessage request = pp.parseMessage(requestMessage, false, false)

        CheckStatusResponse.Type.PerformActions sMimePerformActions = of.createCheckStatusResponseTypePerformActions()
        sMimePerformActions.setFetchExistingTokens(pp.genPerformFetchExistingTokensAction())

        CheckStatusResponse.Type.PerformActions secureNetworkPerformActions = of.createCheckStatusResponseTypePerformActions()
        secureNetworkPerformActions.setRemoveCredentials(pp.genPerformRemoveCredentialsAction([credential]))

        EncodedKey encodedKey = sensitivekeysOf.createEncodedKey()
        encodedKey.algorithm = "AES"
        encodedKey.data = "somedata".bytes
        encodedKey.format = "RAW"

        KeyDataType keyData = sensitivekeysOf.createKeyDataType();
        keyData.setSymmetricKey(encodedKey)
        TokenData td = pp.genTokenData(credential,keyData)

        types = [pp.genClientActionResponseType("SMIME",[td]),
                 pp.genClientActionResponseType("SECURENETWORK",null)]

        CSMessageResponseData rd = pp.genClientActionResponse("SomeRelatedEndEntity", request,types, null)
        //printXML(rd.responseData)
        xml = slurpXml(rd.responseData)
        payloadObject = xml.payload.ClientActionResponse

        then:
        messageContainsPayload rd.responseData, "ae:ClientActionResponse"

        verifyCSMessageResponseData  rd, "SOMEREQUESTER", TEST_ID, false, "ClientActionResponse", "SomeRelatedEndEntity"
        verifyCSHeaderMessage(rd.responseData, xml, "SOMESOURCEID", "SOMEREQUESTER", "someorg","ClientActionResponse", createOriginatorCredential(), csMessageParser)
        verifySuccessfulBasePayload(payloadObject, TEST_ID)

        payloadObject.type[0].autoEnrollmentProfile == "SMIME"
        payloadObject.type[0].tokenDatas.tokenData.credential.size() == 1
        payloadObject.type[0].tokenDatas.tokenData.key.size() == 1
        payloadObject.type[1].autoEnrollmentProfile == "SECURENETWORK"
        payloadObject.type[1].tokenDatas.size() == 0
        when:
        CSMessage r = pp.parseMessage(rd.responseData)
        then:
        CSMessageUtils.getPayload(r).type.size() == 2
    }
    // Test client action request and response

    def "Verify that genPerformFetchExistingTokensAction generates a PerformFetchExistingTokensAction element"(){
        expect:
        pp.genPerformFetchExistingTokensAction() instanceof PerformFetchExistingTokensAction
    }

    def "Verify that genPerformGenerateCredentialRequestAction generates a PerformGenerateCredentialRequestAction element"(){
        when:
        PerformGenerateCredentialRequestAction a = pp.genPerformGenerateCredentialRequestAction(true,wrappingCredential,"SomeSubType", ["x509cn_cn": "Test 1", "x509cn_c": "SE"])
        then:
        a instanceof PerformGenerateCredentialRequestAction
        a.keyRecoverable == true
        a.wrappingCredential == wrappingCredential
        a.credentialSubType == "SomeSubType"
        a.tokenRequestAttributes.tokenRequestAttribute.size() == 2
        a.tokenRequestAttributes.tokenRequestAttribute[0].key == "x509cn_cn"
        a.tokenRequestAttributes.tokenRequestAttribute[0].value == "Test 1"
        a.tokenRequestAttributes.tokenRequestAttribute[1].key == "x509cn_c"
        a.tokenRequestAttributes.tokenRequestAttribute[1].value == "SE"
        when:
        a = pp.genPerformGenerateCredentialRequestAction(false,null,"SomeSubType",["x509cn_cn": "Test 1"])
        then:
        a.keyRecoverable == false
        a.wrappingCredential == null
        a.tokenRequestAttributes.tokenRequestAttribute.size() == 1
        a.tokenRequestAttributes.tokenRequestAttribute[0].key == "x509cn_cn"
        a.tokenRequestAttributes.tokenRequestAttribute[0].value == "Test 1"
        when:
        pp.genPerformGenerateCredentialRequestAction(true,null,"SomeSubType",["x509cn_cn": "Test 1"])
        then:
        thrown MessageContentException
        when:
        pp.genPerformGenerateCredentialRequestAction(false,null,"SomeSubType", null)
        then:
        thrown MessageContentException
        when:
        pp.genPerformGenerateCredentialRequestAction(false,null,"SomeSubType", [:])
        then:
        thrown MessageContentException
        when:
        pp.genPerformGenerateCredentialRequestAction(false,null,null, ["x509cn_cn": "Test 1"])
        then:
        thrown MessageContentException
    }

    def "Verify that genPerformRemoveCredentialsAction generates a PerformRemoveCredentialsAction element"(){
        when:
        PerformRemoveCredentialsAction a = pp.genPerformRemoveCredentialsAction([credential])
        then:
        a instanceof PerformRemoveCredentialsAction
        a.credential.size() == 1
        a.credential[0] == credential

        when:
        pp.genPerformRemoveCredentialsAction(null)
        then:
        thrown MessageContentException

        when:
        pp.genPerformRemoveCredentialsAction([])
        then:
        thrown MessageContentException
    }

    def "Verify that genPerformedFetchExistingTokensAction generates a PerformedFetchExistingTokensAction element"(){
        when:
        PerformedFetchExistingTokensAction a = pp.genPerformedFetchExistingTokensAction()
        then:
        a instanceof PerformedFetchExistingTokensAction
        a.wrappingCredential == null
        when:
        a = pp.genPerformedFetchExistingTokensAction(wrappingCredential)
        then:
        a.wrappingCredential == wrappingCredential
    }

    def "Verify that genPerformedGenerateCredentialRequestActiongenerates a PerformedGenerateCredentialRequestAction element"(){
        when:
        PerformedGenerateCredentialRequestAction a = pp.genPerformedGenerateCredentialRequestAction(credentialRequest,null)
        then:
        a instanceof PerformedGenerateCredentialRequestAction
        a.credentialRequest == credentialRequest
        a.encryptedKey == null
        when:
        a = pp.genPerformedGenerateCredentialRequestAction(credentialRequest,"abc".bytes)
        then:
        a instanceof PerformedGenerateCredentialRequestAction
        a.credentialRequest == credentialRequest
        a.encryptedKey == "abc".bytes
        when:
        pp.genPerformedGenerateCredentialRequestAction(null,null)
        then:
        thrown MessageContentException
    }


    def "Verify that genPerformedRemoveCredentialsAction generates a PerformedRemoveCredentialsAction element"(){
        when:
        PerformedRemoveCredentialsAction a = pp.genPerformedRemoveCredentialsAction([credential])
        then:
        a instanceof PerformedRemoveCredentialsAction
        a.credential.size() == 1
        a.credential[0] == credential

        when:
        pp.genPerformedRemoveCredentialsAction(null)
        then:
        thrown MessageContentException

        when:
        pp.genPerformedRemoveCredentialsAction([])
        then:
        thrown MessageContentException
    }

    def "Verify that genTokenData generates valid TokenData structures"(){
        setup:
        KeyDataType keyData = sensitivekeysOf.createKeyDataType();

        when:
        TokenData td = pp.genTokenData(credential)
        then:
        td.credential == credential
        td.key == null
        when:
        td = pp.genTokenData(credential, keyData)
        then:
        td.credential == credential
        td.key == keyData
        when:
        pp.genTokenData(null)
        then:
        thrown(MessageContentException)

        when:
        td = pp.genTokenData(credential, "abc".bytes)
        then:
        td.credential == credential
        td.encryptedKey == "abc".bytes
        when:
        pp.genTokenData(null, "abc".bytes)
        then:
        thrown(MessageContentException)
    }



}
