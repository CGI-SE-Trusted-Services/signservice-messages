package se.signatureservice.messages.csmessages.examples

import org.bouncycastle.jce.provider.BouncyCastleProvider
import se.signatureservice.messages.TestUtils
import se.signatureservice.messages.utils.XMLSigner

import java.security.Security
import java.security.cert.X509Certificate;

import jakarta.xml.bind.JAXBElement;

import se.signatureservice.messages.MessageSecurityProvider;
import se.signatureservice.messages.SimpleMessageSecurityProvider;
import se.signatureservice.messages.assertion.AssertionPayloadParser;
import se.signatureservice.messages.assertion.AttributeQueryData;
import se.signatureservice.messages.assertion.AttributeQueryTypeEnum;
import se.signatureservice.messages.assertion.ResponseStatusCodes;
import se.signatureservice.messages.assertion.UserDataAssertionData;
import se.signatureservice.messages.saml2.assertion.jaxb.AssertionType;
import se.signatureservice.messages.credmanagement.CredManagementPayloadParser
import se.signatureservice.messages.credmanagement.jaxb.FieldValue;
import se.signatureservice.messages.credmanagement.jaxb.IssueTokenCredentialsRequest;
import se.signatureservice.messages.credmanagement.jaxb.IssueTokenCredentialsResponse;
import se.signatureservice.messages.csmessages.CSMessageParser;
import se.signatureservice.messages.csmessages.CSMessageParserManager;
import se.signatureservice.messages.csmessages.CSMessageResponseData
import se.signatureservice.messages.csmessages.PayloadParserRegistry;
import se.signatureservice.messages.csmessages.constants.AvailableCredentialTypes
import se.signatureservice.messages.csmessages.jaxb.CSMessage
import se.signatureservice.messages.csmessages.jaxb.Credential;
import se.signatureservice.messages.csmessages.jaxb.CredentialRequest
import se.signatureservice.messages.csmessages.jaxb.ObjectFactory
import se.signatureservice.messages.csmessages.jaxb.RequestStatus;
import se.signatureservice.messages.csmessages.jaxb.TokenRequest;
import se.signatureservice.messages.saml2.protocol.jaxb.ResponseType
import se.signatureservice.messages.utils.MessageGenerateUtils;

import spock.lang.Shared

/**
 * Examples on how to use the API when querying UserData from a local repository when requesting credentials.
 * 
 * <p>
 * This example only deals with the message generation aspects of the workflow. 
 * 
 * @author Philip Vendil
 *
 */
class UserDataTicketWorkflowExampleSpec extends ExampleSpecification {
	
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

	def "Example of User Data Ticket Workflow"(){
		setup: "For this example we will need the credential management and assertion payload parser"
		CredManagementPayloadParser cmpp = PayloadParserRegistry.getParser(CredManagementPayloadParser.NAMESPACE);
		AssertionPayloadParser app = PayloadParserRegistry.getParser(AssertionPayloadParser.NAMESPACE);
		
		// On the server side we also need a reference to the CSMessageParser, after initialization it can be optained by calling CSMessageParserManager.getCSMessageParser()
		CSMessageParser mp = CSMessageParserManager.getCSMessageParser()
		when: "Step 1: The client should know that it needs to complement it's data with data from a local user repository"
		// On Client:
		// Generate a UserData AttributeQuery
		byte[] attributeQuery = app.genUserDataRequest("SomeUserId","SomeTokenType")
		// This query is sent to the local user repostory with a attribute query interface, (CS Proxy)
		
		// On User Repository:
		// Parse the query and lookup the User Data for the given user
		AttributeQueryData attributeQueryData = app.parseAttributeQuery(attributeQuery)
		// The repository looks up type of query and subject Id and performs the lookup

		then:
		attributeQueryData.type == AttributeQueryTypeEnum.USER_DATA
		attributeQueryData.subjectId == "SomeUserId"
		
		when:
		// The repository then looks up "field values" in key,value pairs, same as configured for related token type.
		FieldValue f1 = new FieldValue();
		f1.setKey("username")
		f1.setValue("SomeUsername")
		FieldValue f2 = new FieldValue();
		f2.setKey("department")
		f2.setValue("Some Department")
		// The repostory then generates a user data ticket sent back to the client, all field values are encrypted for the server to see only. Display name is optional and unencrypted for
		// the client to display in it's application.
		byte[] samlpUserDataTicket = app.genUserDataTicket(attributeQueryData.getID(), "SomeIssuer", new Date(System.currentTimeMillis() - 15000L), new Date(System.currentTimeMillis() + 15000L), attributeQueryData.subjectId, "SomeDisplayName","SomeTokenType", [f1,f2], [receipient])
		// the SAMLP response is sent back to the client.
		
		// On Client:
		// The client then parses the samlp response
		ResponseType samlPResponse = app.parseAttributeQueryResponse(samlpUserDataTicket)
		
		then:
		// Make sure the response was an success
		samlPResponse.getStatus().getStatusCode().getValue() == ResponseStatusCodes.SUCCESS.getURIValue()
		
		when: "Step 2: Use the User Data ticket in the IssueTokenCredentialsRequest message"
		// On Client:
		// Then extract Assertion from response
		JAXBElement<AssertionType> userDataTicket = app.getAssertionFromResponseType(samlPResponse)
		// Generate a IssueTokenCredentialRequest with the userData included as an assertion
		FieldValue f3 = new FieldValue();
		f3.setKey("somefieldkey")
		f3.setValue("SomeFieldValue")
		
		
		TokenRequest tr = genExampleTokenRequest()
		tr.userData = of.createAssertions()
		// The user data assertion should be appended to the UserData inside the token request
		tr.userData.getAny().add(userDataTicket)
		
		
		byte[] tokenCredentialRequest = cmpp.genIssueTokenCredentialsRequest(MessageGenerateUtils.generateRandomUUID(), "SomeDestionation", "SomeOrg", tr, [f3], null, null, null)
		// This request is sent to server
		
		// On Server:
		// The server will parse the request.
		CSMessage serverTokenCredentialRequest = cmpp.parseMessage(tokenCredentialRequest)

		// Get the payload and the included user data
		IssueTokenCredentialsRequest requestPayload = cmpp.getPayload(serverTokenCredentialRequest)
		// Extract the user data ticket
		JAXBElement<AssertionType> serverUserDataTicket = requestPayload.getTokenRequest().getUserData().getAny().get(0)
		// decrypt and parse the user data ticket
		UserDataAssertionData userTicketData = app.parseAndDecryptAssertion(serverUserDataTicket)
		
		then:
		// It now possible for the server to use the data inside the decrypted UserData ticket
		userTicketData.displayName == "SomeDisplayName"
		userTicketData.getFieldValues().get(0).getKey() == "username"
		userTicketData.getFieldValues().get(1).getKey() == "department"
		
		when:
		// On Server:
		// Its now possible to generate credentials using the combined field values from the request and user data ticket.
		// and finally generate a response back to the client.
		Credential credential = genExampleCredential();
		CSMessageResponseData response = cmpp.genIssueTokenCredentialsResponse("SomeRelatedEndEntity", serverTokenCredentialRequest, [credential], null, null)
		// The actual response sent is
		byte[] responseData = response.getResponseData()
		
		// On Client
		// The client receives the response
		CSMessage clientResponse = cmpp.parseMessage(responseData)
		then:
		cmpp.getResponseStatus(clientResponse) == RequestStatus.SUCCESS
		cmpp.getPayload(clientResponse) instanceof IssueTokenCredentialsResponse
		
		// The issued credentials can be found inside the payload
		((IssueTokenCredentialsResponse) cmpp.getPayload(clientResponse)).getCredentials().getCredential().size() == 1
		
		
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
