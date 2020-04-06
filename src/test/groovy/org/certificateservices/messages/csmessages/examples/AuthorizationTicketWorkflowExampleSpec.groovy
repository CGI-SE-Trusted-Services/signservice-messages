package org.certificateservices.messages.csmessages.examples

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.certificateservices.messages.utils.XMLSigner

import java.security.Security
import java.security.cert.X509Certificate;

import javax.xml.bind.JAXBElement;

import org.certificateservices.messages.MessageSecurityProvider;
import org.certificateservices.messages.SimpleMessageSecurityProvider;
import org.certificateservices.messages.TestUtils;
import org.certificateservices.messages.assertion.AssertionPayloadParser;
import org.certificateservices.messages.assertion.AttributeQueryData;
import org.certificateservices.messages.assertion.AttributeQueryTypeEnum;
import org.certificateservices.messages.assertion.AuthorizationAssertionData;
import org.certificateservices.messages.assertion.ResponseStatusCodes
import org.certificateservices.messages.saml2.assertion.jaxb.AssertionType;
import org.certificateservices.messages.credmanagement.CredManagementPayloadParser;
import org.certificateservices.messages.credmanagement.jaxb.ChangeCredentialStatusRequest;
import org.certificateservices.messages.credmanagement.jaxb.ChangeCredentialStatusResponse
import org.certificateservices.messages.csmessages.CSMessageParser;
import org.certificateservices.messages.csmessages.CSMessageParserManager;
import org.certificateservices.messages.csmessages.CSMessageResponseData
import org.certificateservices.messages.csmessages.PayloadParserRegistry;
import org.certificateservices.messages.csmessages.constants.AvailableCredentialTypes
import org.certificateservices.messages.csmessages.jaxb.CSMessage
import org.certificateservices.messages.csmessages.jaxb.Credential;
import org.certificateservices.messages.csmessages.jaxb.CredentialRequest
import org.certificateservices.messages.csmessages.jaxb.ObjectFactory
import org.certificateservices.messages.csmessages.jaxb.RequestStatus;
import org.certificateservices.messages.csmessages.jaxb.TokenRequest;
import org.certificateservices.messages.saml2.protocol.jaxb.ResponseType
import org.certificateservices.messages.utils.MessageGenerateUtils;

import spock.lang.Shared

/**
 * Examples on how to use the API when using a distributed authorization scheme.
 * <p>
 * This example only deals with the message generation aspects of the workflow. 
 * 
 * @author Philip Vendil
 *
 */
class AuthorizationTicketWorkflowExampleSpec extends ExampleSpecification {
	
	// Simplest configuration using signing and encryption keystore with same key.
	// The KEYSTORELOCATION and TRUSTSTORE locations is replaeced in this script for the test to run.
	static def exampleConfig = """
simplesecurityprovider.signingkeystore.path=KEYSTORELOCATION
simplesecurityprovider.signingkeystore.password=tGidBq0Eep
simplesecurityprovider.signingkeystore.alias=test
simplesecurityprovider.trustkeystore.path=TRUSTSTORELOCATION
simplesecurityprovider.trustkeystore.password=foo123

csmessage.sourceid=SomeClientSystem
"""


	@Shared X509Certificate receipient
	
	@Shared ObjectFactory of = new ObjectFactory();
	
	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Properties config = getConfig(exampleConfig)
		
		// Required initialization code, only needed once for an application.
		
		// Start with setting up MessageSecurityProvider, one implementation is SimpleMessageSecurityProvider
		// using Java key stores to store it's signing and encryption keys.
		MessageSecurityProvider secProv = new SimpleMessageSecurityProvider(config);
		// This mocking is for testing only (to avoid failure due to expired certificates)
		XMLSigner.systemTime = TestUtils.mockSystemTime("2013-10-01")
		
		// Create and initialize the Default Message Provider with the security provider.
		// For client should the usually not need a reference to the CSMessageParser, use the PayloadParser
		// from PayloadParserRegistry should have all the necessary functions.
		CSMessageParserManager.initCSMessageParser(secProv, config)
		
		// Receipient key of Server endpoint decrypting the encrypted user data.
		receipient = secProv.getDecryptionCertificate(MessageSecurityProvider.DEFAULT_DECRYPTIONKEY)
	}
	
	def "Example of Authorization Ticket Workflow"(){
		setup: "For this example we will need the credential management and assertion payload parser"
		CredManagementPayloadParser cmpp = PayloadParserRegistry.getParser(CredManagementPayloadParser.NAMESPACE);
		AssertionPayloadParser app = PayloadParserRegistry.getParser(AssertionPayloadParser.NAMESPACE);
		
		// On the server side we also need a reference to the CSMessageParser, after initialization it can be optained by calling CSMessageParserManager.getCSMessageParser()
		CSMessageParser mp = CSMessageParserManager.getCSMessageParser()
		when: "Step 1: The client requests it's authorization roles from a local respitory"
		// On Client:
		// Generate a Distributed Authorization Request AttributeQuery
		byte[] attributeQuery = app.genDistributedAuthorizationRequest("SomeUserId")
		// This query is sent to the local user repostory with a attribute query interface, (CS Proxy)
		
		// On User Repository:
		// Parse the query and lookup the User Data for the given user
		AttributeQueryData attributeQueryData = app.parseAttributeQuery(attributeQuery)
		// The repository looks up type of query and subject Id and performs the lookup

		then:
		attributeQueryData.type == AttributeQueryTypeEnum.AUTHORIZATION_TICKET
		attributeQueryData.subjectId == "SomeUserId"
		
		when:
		// The repository then looks up the applicable roles the user has locally .
	
		// The repostory then generates a authorization ticket that is sent back to the client, all roles are encrypted for the server to see only. 
		List<String> roles = ["SomeRole1","SomeRole2"]
		byte[] samlpAuthorizationTicket = app.genDistributedAuthorizationTicket(attributeQueryData.getID(), "SomeIssuer", new Date(System.currentTimeMillis() - 15000L), new Date(System.currentTimeMillis() + 15000L), attributeQueryData.subjectId, roles, [receipient])
		// the SAMLP response is sent back to the client.
		
		// On Client:
		// The client then parses the samlp response
		ResponseType samlPResponse = app.parseAttributeQueryResponse(samlpAuthorizationTicket)
		
		then:
		// Make sure the response was an success
		samlPResponse.getStatus().getStatusCode().getValue() == ResponseStatusCodes.SUCCESS.getURIValue()
		
		when: "Step 2: Use the Authtorization ticket in a request message"
		// On Client:
		// Then extract Assertion from response
		JAXBElement<AssertionType> authorizationTicket = app.getAssertionFromResponseType(samlPResponse)

		// Include the ticket among the assertions.
		byte[] request = cmpp.genChangeCredentialStatusRequest(MessageGenerateUtils.generateRandomUUID(), "SomeServerSystem", "SomeOrg", "CN=SomeIssuerId", "1234", 100, "10", null, [authorizationTicket]);
		// This request is sent to server
		
		// On Server:
		// The server will parse the request.
		CSMessage serverRequest = cmpp.parseMessage(request)

		// Get the payload 
		ChangeCredentialStatusRequest requestPayload = cmpp.getPayload(serverRequest)
		// Get the assertions
		List<JAXBElement<AssertionType>> assertions = app.getAssertionsFromCSMessage(serverRequest)
		// To get the roles it first need to be decrypted
		AuthorizationAssertionData authTicketData = app.parseAndDecryptAssertion(assertions.get(0))
		
		then:
		// It now possible for the server to use the data inside the decrypted UserData ticket
		authTicketData.getSubjectId() == "SomeUserId"
		authTicketData.getRoles()[0] == "SomeRole1"
		authTicketData.getRoles()[1] == "SomeRole2"
		
		// Important, before processing the request MUST the server verify that the signing of the request message and subjectId of the ticket match.
		
		when:
		// On Server:
		// If the user have the required role in his ticket or configured locally the request can proceed.
		CSMessageResponseData processedResponse = cmpp.genChangeCredentialStatusResponse("SomeRelatedEndEntity", serverRequest, "CN=SomeIssuerId", "1234", 100, "10", null, null)
		// The actual data sent back to the client is:
		byte[] processedResponseData = processedResponse.getResponseData();
		
		// On Client
		// The client receives the response
		CSMessage clientResponse = cmpp.parseMessage(processedResponseData)
		then:
		cmpp.getResponseStatus(clientResponse) == RequestStatus.SUCCESS
		cmpp.getPayload(clientResponse) instanceof ChangeCredentialStatusResponse
		
	
	}
	

	private TokenRequest genExampleTokenRequest(){
		CredentialRequest cr = of.createCredentialRequest();
		cr.credentialRequestId = 1
		cr.credentialType = AvailableCredentialTypes.CREDENTIAL_TYPE_X509CERTIFICATE
		cr.credentialSubType = "SomeCredentialSubtype"
		cr.x509RequestType = "SomeX509RequestType"
		cr.credentialRequestData = "SomeRequestData".getBytes()

		TokenRequest retval = of.createTokenRequest()
		retval.credentialRequests = new TokenRequest.CredentialRequests()
		retval.credentialRequests.getCredentialRequest().add(cr)
		retval.user ="SomeUserId"
		retval.tokenContainer = "SomeTokenContainer"
		retval.tokenType = "SomeTokenType"
		retval.tokenClass = "SomeTokenClass"

		return retval
	}
	
	private Credential genExampleCredential(){
		Credential c = of.createCredential();
		c.credentialRequestId = 1
		c.uniqueId = "SomeUniqueId"
		c.displayName = "SomeDisplayName"
		c.serialNumber = "SomeSerialNumber"
		c.issuerId = "SomeIssuerID"
		c.status = 100
		c.credentialType = AvailableCredentialTypes.CREDENTIAL_TYPE_X509CERTIFICATE
		c.credentialSubType = "SomeCredentialSubtype"
		c.credentialData = "SomeCredentialData".getBytes()
		c.issueDate = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date())
		c.expireDate = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date())
		c.validFromDate = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date())

		return c
	}
	

}
