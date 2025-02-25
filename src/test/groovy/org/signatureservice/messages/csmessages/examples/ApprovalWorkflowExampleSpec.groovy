package org.signatureservice.messages.csmessages.examples

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.signatureservice.messages.utils.XMLSigner

import java.security.Security
import java.security.cert.X509Certificate;

import javax.xml.bind.JAXBElement;

import org.signatureservice.messages.MessageSecurityProvider;
import org.signatureservice.messages.SimpleMessageSecurityProvider;
import org.certificateservices.messages.TestUtils;
import org.signatureservice.messages.assertion.AssertionData;
import org.signatureservice.messages.assertion.AssertionPayloadParser;
import org.signatureservice.messages.saml2.assertion.jaxb.AssertionType;
import org.signatureservice.messages.credmanagement.CredManagementPayloadParser;
import org.signatureservice.messages.credmanagement.jaxb.ChangeCredentialStatusResponse;
import org.signatureservice.messages.csmessages.CSMessageParser;
import org.signatureservice.messages.csmessages.CSMessageParserManager;
import org.signatureservice.messages.csmessages.CSMessageResponseData
import org.signatureservice.messages.csmessages.PayloadParserRegistry;
import org.signatureservice.messages.csmessages.constants.AvailableCredentialTypes;
import org.signatureservice.messages.csmessages.jaxb.ApprovalStatus;
import org.signatureservice.messages.csmessages.jaxb.Approver;
import org.signatureservice.messages.csmessages.jaxb.ApproverType;
import org.signatureservice.messages.csmessages.jaxb.CSMessage
import org.signatureservice.messages.csmessages.jaxb.Credential;
import org.signatureservice.messages.csmessages.jaxb.IsApprovedResponseType;
import org.signatureservice.messages.csmessages.jaxb.ObjectFactory;
import org.signatureservice.messages.csmessages.jaxb.RequestStatus
import org.signatureservice.messages.utils.MessageGenerateUtils;

import spock.lang.Shared

/**
 * Examples on how to use the API with an Approval Workflow, when a unathorized requester
 * whats to chage the status of a credential.
 * <p>
 * This example only deals with the message generation aspects of the workflow. 
 * 
 * @author Philip Vendil
 *
 */
class ApprovalWorkflowExampleSpec extends ExampleSpecification {
	
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


	@Shared X509Certificate internalSystemRecepient
	
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
		
		// Receipient key of more sensitive in-bound systems that might want to audit who approved a request. 
		internalSystemRecepient = secProv.getDecryptionCertificate(MessageSecurityProvider.DEFAULT_DECRYPTIONKEY)
		
	}
	

	
	def "Example of Approval Ticket Workflow"(){
		setup: "For this example we will need the credential management and assertion payload parser"
		CredManagementPayloadParser cmpp = PayloadParserRegistry.getParser(CredManagementPayloadParser.NAMESPACE);
		AssertionPayloadParser app = PayloadParserRegistry.getParser(AssertionPayloadParser.NAMESPACE);
		
		// On the server side we also need a reference to the CSMessageParser, after initialization it can be optained by calling CSMessageParserManager.getCSMessageParser()
		CSMessageParser mp = CSMessageParserManager.getCSMessageParser()
		when: "Step 1: Try to generate request"
		// On Client:
		byte[] request = cmpp.genChangeCredentialStatusRequest(MessageGenerateUtils.generateRandomUUID(), "SomeServerSystem", "SomeOrg", "CN=SomeIssuerId", "1234", 100, "10", null, null);
		// This message is sent to the system, which rejects it will and approval required message
		
		// On Server:
		// The server generates a FailureResponse with status APPROVALREQUIRED
		CSMessageResponseData failureResponse = mp.genCSFailureResponse("SomeRelatedEndEntity", request, RequestStatus.APPROVALREQUIRED, "You request needs an approval", "SomeClientSystem", null)
		// The actual data sent back to the client is:
		byte[] failureResponseData = failureResponse.getResponseData()
		
		// On Client:
		// To parse the failure response use your payload parser:
		CSMessage failureResponseMessage = cmpp.parseMessage(failureResponseData);
		
		then:
		// Payload parser have a help method to extract status from CS Response messages
	    cmpp.getResponseStatus(failureResponseMessage) == RequestStatus.APPROVALREQUIRED
		
		when: "Step 2: Next step is to generate an approval request for this request, this can be don immediatly if the client knows it's not authorized"
		// On Client:
		byte[] approvalRequest = cmpp.generateGetApprovalRequest(MessageGenerateUtils.generateRandomUUID(), "SomeServerSystem", "SomeOrg", request, null, null)
				
		//println new String(approvalRequest)
		
		// On Server:
		// The server will add the request for approval by the approval engine and return an approval Id in the response
		CSMessage approvalRequestMessage =  mp.parseMessage(approvalRequest)
		CSMessageResponseData getApprovalResponse =  mp.generateGetApprovalResponse("SomeRelatedEndEntity", approvalRequestMessage, "12345678", ApprovalStatus.WAITING, null)
		// The actual data sent back to the client is:
		byte[] getApprovalResponseData = getApprovalResponse.getResponseData();
		
		// On Client:
		// The client will parse the response
		CSMessage clientGetApprovalResponse = cmpp.parseMessage(getApprovalResponseData)
		then:
		cmpp.getResponseStatus(clientGetApprovalResponse) == RequestStatus.SUCCESS
		// Use the help method getPayload in payload parser to get the actual payload data.
		IsApprovedResponseType getApprovedPayload = cmpp.getPayload(clientGetApprovalResponse)
		// If server sent that approval is waiting it has also returned a request data unique approval id
		getApprovedPayload.getApprovalStatus() == ApprovalStatus.WAITING
		getApprovedPayload.getApprovalId() == "12345678"
		
		when: "Step 3: Then the client should poll the server to see if approval request has been approved or denied"
		// On Client:
		// Generate an IsApprovedRequest and send to the server
		byte[] isApprovedRequest = cmpp.generateIsApprovedRequest(MessageGenerateUtils.generateRandomUUID(), "SomeServerSystem", "SomeOrg", "12345678", null, null)
		
		// On Server:
		// The server parses the request and checks if the approval is approved or rejected
		CSMessage isApprovedRequestMessage = mp.parseMessage(isApprovedRequest)
		// if approve is an approval ticket generated and included in the response, containing the approval id and separate request ids if more than one request is allowed for one approval.
		
		// The server can optionally also include encrypted data about who approved it, this for the usecase the assertion is forwarded to inbound more sensitive systems for audit about who actually approved a request.
		// This data should remained encrypted for the clients. If no approver data is neccessary should both approvers and receipients parameters be null. 
		def approver = genExampleApprover()
		byte[] approvalTicket = app.genApprovalTicket("CN=SomeIssuer", new Date(System.currentTimeMillis() - 15000L), new Date(System.currentTimeMillis() + 15000L), "SomeSubjectId", "12345678", ["783SDFakhd3263"], "SomeServerSystem",[approver],[internalSystemRecepient])		
		JAXBElement<AssertionType> appTicket = app.parseApprovalTicket(approvalTicket)
		CSMessageResponseData isApprovedResponse = mp.generateIsApprovedResponse("SomeRelatedEndEntity", isApprovedRequestMessage, ApprovalStatus.APPROVED, [appTicket])
		// The actual data sent back to the client is:
		byte[] isApprovalResponseData = isApprovedResponse.getResponseData();
		
		
		// On Client:
		CSMessage clientIsApprovedResponse = cmpp.parseMessage(isApprovalResponseData)
		then:
		cmpp.getResponseStatus(clientIsApprovedResponse) == RequestStatus.SUCCESS
		IsApprovedResponseType isApprovedPayload = cmpp.getPayload(clientIsApprovedResponse)
		isApprovedPayload.getAssertions().size() == 1
		
		when: "Step 4: The client can then take the assertion and insert into the request message that is resent (data must be the same as in the original message)"
		// On Client:
		List<Object> requestAssertions = cmpp.getAssertions(isApprovedPayload)
		
		// If the client wants to inspect the approval assertions (Optional) it can use the method parseAssertion, this method will not decrypt approvers data and ignore
		// all Authorization and User Data Assertions in the list.
		List<AssertionData> parsedAssertionData = app.parseAssertions(requestAssertions)
		
		byte[] requestWithAssertions = cmpp.genChangeCredentialStatusRequest(MessageGenerateUtils.generateRandomUUID(), "SomeServerSystem", "SomeOrg", "CN=SomeIssuerId", "1234", 100, "10", null, requestAssertions);
		
		
		// The Server now verifies the assertion and perfroms the request, and marks the related requestid inside the approval ticket as done.
		// On Server:
		CSMessage assertionChangeCredentialStatusResponse =  mp.parseMessage(requestWithAssertions)
		CSMessageResponseData processedResponse = cmpp.genChangeCredentialStatusResponse("SomeRelatedEndEntity", assertionChangeCredentialStatusResponse, "CN=SomeIssuerId", "1234", 100, "10", null, null)
		// The actual data sent back to the client is:
		byte[] processedResponseData = processedResponse.getResponseData();
		
		// On Client:
		CSMessage clientProcessedResponse = cmpp.parseMessage(processedResponseData)
		then:
		cmpp.getResponseStatus(clientProcessedResponse) == RequestStatus.SUCCESS
		cmpp.getPayload(clientProcessedResponse) instanceof ChangeCredentialStatusResponse
	}
	

	private Approver genExampleApprover(){
		Approver retval = of.createApprover();
		retval.description = "Some description made by the approver"
		retval.approvalDate = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date())
		retval.type = ApproverType.MANUAL
		retval.credential = genExampleCredential() // credential on who approved the action.

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
