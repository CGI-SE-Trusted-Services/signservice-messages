package org.certificateservices.messages.assertion

import org.apache.xml.security.Init
import org.apache.xml.security.utils.Base64
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.certificateservices.messages.DummyMessageSecurityProvider
import org.certificateservices.messages.MessageContentException
import org.certificateservices.messages.MessageProcessingException
import org.certificateservices.messages.MessageSecurityProvider
import org.certificateservices.messages.credmanagement.CredManagementPayloadParser
import org.certificateservices.messages.credmanagement.jaxb.FieldValue
import org.certificateservices.messages.csmessages.CSMessageParserManager
import org.certificateservices.messages.csmessages.DefaultCSMessageParser
import org.certificateservices.messages.csmessages.PayloadParserRegistry
import org.certificateservices.messages.csmessages.constants.AvailableCredentialTypes
import org.certificateservices.messages.csmessages.jaxb.Approver
import org.certificateservices.messages.csmessages.jaxb.ApproverType
import org.certificateservices.messages.csmessages.jaxb.CSMessage
import org.certificateservices.messages.csmessages.jaxb.Credential
import org.certificateservices.messages.saml2.assertion.jaxb.AssertionType
import org.certificateservices.messages.saml2.assertion.jaxb.ObjectFactory
import org.certificateservices.messages.saml2.protocol.jaxb.ResponseType
import org.certificateservices.messages.utils.MessageGenerateUtils
import org.certificateservices.messages.utils.SystemTime
import org.certificateservices.messages.utils.XMLSigner
import org.w3c.dom.Document
import org.w3c.dom.Element
import org.w3c.dom.NodeList
import org.xml.sax.InputSource
import spock.lang.Specification
import spock.lang.Unroll

import javax.xml.bind.JAXBElement
import javax.xml.crypto.dsig.XMLSignature
import javax.xml.crypto.dsig.XMLSignatureFactory
import javax.xml.crypto.dsig.dom.DOMValidateContext
import javax.xml.parsers.DocumentBuilder
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.OutputKeys
import javax.xml.transform.Transformer
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

import static org.certificateservices.messages.TestUtils.*
import static org.certificateservices.messages.csmessages.DefaultCSMessageParserSpec.TEST_ID

class AssertionPayloadParserSpec extends Specification {
	
	AssertionPayloadParser pp;
	ObjectFactory of = new ObjectFactory()
	org.certificateservices.messages.csmessages.jaxb.ObjectFactory csMessageOf = new org.certificateservices.messages.csmessages.jaxb.ObjectFactory()
	org.certificateservices.messages.xenc.jaxb.ObjectFactory xencObj = new org.certificateservices.messages.xenc.jaxb.ObjectFactory()
	org.certificateservices.messages.xmldsig.jaxb.ObjectFactory dsignObj = new org.certificateservices.messages.xmldsig.jaxb.ObjectFactory()
	Calendar cal = Calendar.getInstance();
	CertificateFactory cf
	
	List<X509Certificate> twoReceiptiensValidFirst
	
	MessageSecurityProvider secProv = new DummyMessageSecurityProvider();
	
	DefaultCSMessageParser csp
	CredManagementPayloadParser credManagementPayloadParser
	
	def fv1
	def fv2


	def TimeZone currentTimeZone;
	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Init.init()
	}

	def setup(){
		currentTimeZone = TimeZone.getDefault()
		TimeZone.setDefault(TimeZone.getTimeZone("Europe/Stockholm"))

		setupRegisteredPayloadParser();
		
		pp = PayloadParserRegistry.getParser(AssertionPayloadParser.NAMESPACE);
		pp.systemTime = Mock(SystemTime)
		pp.systemTime.getSystemTime() >> new Date(1436279213000)
		pp.samlAssertionMessageParser.systemTime = pp.systemTime
		csp = CSMessageParserManager.getCSMessageParser()
		
		cf = CertificateFactory.getInstance("X.509")
		X509Certificate invalidCert = cf.generateCertificate(new ByteArrayInputStream(Base64.decode(base64Cert)))
		X509Certificate validCert = csp.messageSecurityProvider.getDecryptionCertificate(csp.messageSecurityProvider.decryptionKeyIds.iterator().next())
		
		twoReceiptiensValidFirst = [validCert,invalidCert]
		
		fv1 = new FieldValue();
		fv1.key = "someKey1"
		fv1.value = "someValue1"
		fv2 = new FieldValue();
		fv2.key = "someKey2"
		fv2.value = "someValue2"
		
		credManagementPayloadParser = PayloadParserRegistry.getParser(CredManagementPayloadParser.NAMESPACE)
	}

	def cleanup(){
		TimeZone.setDefault(currentTimeZone)
	}
	
	def "Verify that JAXBPackage(), getNameSpace(), getSchemaAsInputStream(), getSupportedVersions(), getDefaultPayloadVersion() returns the correct values"(){
		expect:
		pp.getJAXBPackage() == "org.certificateservices.messages.saml2.assertion.jaxb"
		pp.getNameSpace() == "urn:oasis:names:tc:SAML:2.0:assertion"
		pp.getSchemaAsInputStream("2.0") != null
		pp.getDefaultPayloadVersion() == "2.0"
		pp.getSupportedVersions() == ["2.0"] as String[]
	}
	
	@Unroll
	def "Verify that genDistributedAuthorizationRequest() throws MessageContentException for invalid subject id: #subjectId"(){
		when:
		pp.genAttributeQuery(subjectId, "someattr",null)
		then:
		thrown MessageContentException
		where:
		subjectId << [null,""," "]
		
	}
	
	def "Verify that schemaValidateAssertion() validates agains schema"(){
		setup:
		JAXBElement<AssertionType> assertion = pp.parseApprovalTicket(pp.genApprovalTicket("someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject","1234",["abcdef", "defcva"], null, genApprovers(),twoReceiptiensValidFirst))
		when:
		pp.schemaValidateAssertion(assertion)
		then:
		true
		when:
		assertion.getValue().issueInstant = null
		pp.schemaValidateAssertion(assertion)
		then:
		thrown MessageContentException
		
	}
	
	def "Verify that genDistributedAuthorizationRequest() generates a valid SAMLP Attribute Query"(){
		when:
		def xmlData = pp.genDistributedAuthorizationRequest("SomeSubjectId@someorg")
		//printXML(xmlData)
		def xml = new XmlSlurper().parse(new ByteArrayInputStream(xmlData))
		then:
		xml.@ID.toString().length() > 0
		xml.@IssueInstant == "2015-07-07T14:26:53.000Z"
		xml.@Version == AssertionPayloadParser.DEFAULT_ASSERTION_VERSION
		xml.Subject.NameID == "SomeSubjectId@someorg"
		xml.Attribute[0].@Name == AssertionPayloadParser.ATTRIBUTE_NAME_ROLES
	}
	
	
	def "Verify that genUserDataRequest() generates a valid SAMLP Attribute Query"(){
		when:
		def xmlData = pp.genUserDataRequest("SomeSubjectId@someorg","someTokenType")
		//printXML(xmlData)
		def xml = new XmlSlurper().parse(new ByteArrayInputStream(xmlData))
		then:
		xml.@ID.toString().length() > 0
		xml.@IssueInstant == "2015-07-07T14:26:53.000Z"
		xml.@Version == AssertionPayloadParser.DEFAULT_ASSERTION_VERSION
		xml.Subject.NameID == "SomeSubjectId@someorg"
		xml.Attribute[0].@Name == AssertionPayloadParser.ATTRIBUTE_NAME_USERDATA
		xml.Attribute[1].@Name == AssertionPayloadParser.ATTRIBUTE_NAME_TOKENTYPE
		xml.Attribute[1].AttributeValue == "someTokenType"
		
		when: // Verify that token type attribute isn't set if null
		xmlData = pp.genUserDataRequest("SomeSubjectId@someorg",null)
		//printXML(xmlData)
		xml = new XmlSlurper().parse(new ByteArrayInputStream(xmlData))
		then:
		xml.Attribute.size() == 1
		xml.Attribute[0].@Name == AssertionPayloadParser.ATTRIBUTE_NAME_USERDATA
	}
	

	
	def "Verify that genDistributedAuthorizationTicket() generates a valid authorization ticket without departments"(){
		when:
		byte[] ticketData = pp.genDistributedAuthorizationTicket("_123456789", "someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject",["role1", "role2"], twoReceiptiensValidFirst)
		//printXML(ticketData)
		
		def xml = new XmlSlurper().parse(new ByteArrayInputStream(ticketData))
		
		then:
		xml.@ID.toString().length() > 0
		xml.@IssueInstant == "2015-07-07T14:26:53.000Z"
		xml.@Version == AssertionPayloadParser.DEFAULT_ASSERTION_VERSION
		xml.@InResponseTo == "_123456789"
		xml.Status.StatusCode.@Value == ResponseStatusCodes.SUCCESS.getURIValue()
		xml.@ID.toString() != xml.Assertion.@ID.toString()
		xml.Assertion.@ID.toString().length() > 0
		xml.Assertion.@IssueInstant == "2015-07-07T14:26:53.000Z"
		xml.Assertion.@Version == AssertionPayloadParser.DEFAULT_ASSERTION_VERSION
		xml.Assertion.Issuer == "someIssuer"
		xml.Assertion.Signature.size() == 1
		verifySignature(ticketData)
		xml.Assertion.Subject.NameID == "SomeSubject"
		xml.Assertion.Conditions.@NotBefore == "2015-07-07T14:26:52.427Z"
		xml.Assertion.Conditions.@NotOnOrAfter == "2015-07-07T14:28:32.427Z"
		xml.Assertion.AttributeStatement.Attribute.size() == 1
		xml.Assertion.AttributeStatement.Attribute[0].@Name == AssertionPayloadParser.ATTRIBUTE_NAME_TYPE
		xml.Assertion.AttributeStatement.Attribute[0].AttributeValue == AssertionTypeEnum.AUTHORIZATION_TICKET.getAttributeValue()
		xml.Assertion.AttributeStatement.EncryptedAttribute.size() == 1
		
		when: "Verify that SAMLP can be modified without breaking signature"
		String replacedSamlpID = new String(ticketData, "UTF-8").replace(xml.@ID.toString(), "_InvalidID")
		then:
		verifySignature(replacedSamlpID.getBytes("UTF-8"))
		when: "Verify that Assertion can not be modified without breaking signature"
		String replacedAssertionId = new String(ticketData, "UTF-8").replace(xml.Assertion.@ID.toString(), "_InvalidID")
		verifySignature(replacedAssertionId.getBytes("UTF-8"))
		then:
		thrown Exception
		 
		when: "Decrypt and check that roles exists"
		AuthorizationAssertionData ad = pp.parseAndDecryptAssertion(pp.getAssertionFromResponseType(pp.parseAttributeQueryResponse(ticketData)))
		then:
		ad.getRoles() == ["role1", "role2"]
		ad.getDepartments() == null
		
	}

	def "Verify that genDistributedAuthorizationTicket() generates a valid authorization ticket with departments"(){
		when:
		byte[] ticketData = pp.genDistributedAuthorizationTicket("_123456789", "someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject",["role1", "role2"], ["dep1", "dep2"], twoReceiptiensValidFirst)
		//printXML(ticketData)

		def xml = new XmlSlurper().parse(new ByteArrayInputStream(ticketData))

		then:
		xml.@ID.toString().length() > 0
		xml.@IssueInstant == "2015-07-07T14:26:53.000Z"
		xml.@Version == AssertionPayloadParser.DEFAULT_ASSERTION_VERSION
		xml.@InResponseTo == "_123456789"
		xml.Status.StatusCode.@Value == ResponseStatusCodes.SUCCESS.getURIValue()
		xml.@ID.toString() != xml.Assertion.@ID.toString()
		xml.Assertion.@ID.toString().length() > 0
		xml.Assertion.@IssueInstant == "2015-07-07T14:26:53.000Z"
		xml.Assertion.@Version == AssertionPayloadParser.DEFAULT_ASSERTION_VERSION
		xml.Assertion.Issuer == "someIssuer"
		xml.Assertion.Signature.size() == 1
		verifySignature(ticketData)
		xml.Assertion.Subject.NameID == "SomeSubject"
		xml.Assertion.Conditions.@NotBefore == "2015-07-07T14:26:52.427Z"
		xml.Assertion.Conditions.@NotOnOrAfter == "2015-07-07T14:28:32.427Z"
		xml.Assertion.AttributeStatement.Attribute.size() == 1
		xml.Assertion.AttributeStatement.Attribute[0].@Name == AssertionPayloadParser.ATTRIBUTE_NAME_TYPE
		xml.Assertion.AttributeStatement.Attribute[0].AttributeValue == AssertionTypeEnum.AUTHORIZATION_TICKET.getAttributeValue()
		xml.Assertion.AttributeStatement.EncryptedAttribute.size() == 2

		when: "Decrypt and check that roles and departments exists"
		AuthorizationAssertionData ad = pp.parseAndDecryptAssertion(pp.getAssertionFromResponseType(pp.parseAttributeQueryResponse(ticketData)))
		then:
		ad.getRoles() == ["role1", "role2"]
		ad.getDepartments() == ["dep1", "dep2"]

	}
	
	def "Verify that genUserDataTicket() generates a valid user data ticket"(){
		when:
		byte[] ticketData = pp.genUserDataTicket("_123456789", "someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject","SomeDisplayName","SomeTokenType",[fv1, fv2], twoReceiptiensValidFirst)
		//printXML(ticketData)

		def xml = new XmlSlurper().parse(new ByteArrayInputStream(ticketData))
		
		then:
		xml.@ID.toString().length() > 0
		xml.Assertion.@ID.toString().length() > 0
		xml.Assertion.AttributeStatement.Attribute.size() == 3
		xml.Assertion.AttributeStatement.Attribute[0].@Name == AssertionPayloadParser.ATTRIBUTE_NAME_TYPE
		xml.Assertion.AttributeStatement.Attribute[0].AttributeValue == AssertionTypeEnum.USER_DATA.getAttributeValue()
		xml.Assertion.AttributeStatement.Attribute[1].@Name == "DisplayName"
		xml.Assertion.AttributeStatement.Attribute[1].AttributeValue == "SomeDisplayName"
		xml.Assertion.AttributeStatement.Attribute[2].@Name == "TokenType"
		xml.Assertion.AttributeStatement.Attribute[2].AttributeValue == "SomeTokenType"
		xml.Assertion.AttributeStatement.EncryptedAttribute.size() == 1
		verifySignature(ticketData)
		
		when: "Verify that if displayName and token type is null isn't related attribute set."
		byte[] ticketData2 = pp.genUserDataTicket("_123456789", "someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject",null,null,[fv1, fv2], twoReceiptiensValidFirst)
		
		xml = new XmlSlurper().parse(new ByteArrayInputStream(ticketData2))
		then:
		xml.Assertion.AttributeStatement.Attribute.size() == 1
		xml.Assertion.AttributeStatement.Attribute[0].@Name == AssertionPayloadParser.ATTRIBUTE_NAME_TYPE
		xml.Assertion.AttributeStatement.Attribute[0].AttributeValue == AssertionTypeEnum.USER_DATA.getAttributeValue()
		
		when:
		UserDataAssertionData ad = pp.parseAndDecryptAssertion(pp.getAssertionFromResponseType(pp.parseAttributeQueryResponse(ticketData)))
		then:
		ad.displayName == "SomeDisplayName"
		ad.fieldValues.size() == 2
		ad.fieldValues[0].key == "someKey1"
		ad.fieldValues[0].value == "someValue1"
		ad.fieldValues[1].key == "someKey2"
		ad.fieldValues[1].value == "someValue2"
	}
	
	
	def "Verify genApprovalTicket() generates a valid Approval ticket"(){
		when:
		byte[] ticketData = pp.genApprovalTicket("someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject","1234",["abcdef", "defcva"], "SomeDestination",genApprovers(), twoReceiptiensValidFirst)
		//printXML(ticketData)

		def xml = new XmlSlurper().parse(new ByteArrayInputStream(ticketData))
		then:	
		xml.AttributeStatement.Attribute.size() == 4
		xml.AttributeStatement.Attribute[0].@Name == AssertionPayloadParser.ATTRIBUTE_NAME_TYPE
		xml.AttributeStatement.Attribute[0].AttributeValue == AssertionTypeEnum.APPROVAL_TICKET.getAttributeValue()
		xml.AttributeStatement.Attribute[1].@Name == AssertionPayloadParser.ATTRIBUTE_NAME_DESTINATIONID
		xml.AttributeStatement.Attribute[1].AttributeValue == "SomeDestination"
		xml.AttributeStatement.Attribute[2].@Name == "ApprovalId"
		xml.AttributeStatement.Attribute[2].AttributeValue == "1234"
		xml.AttributeStatement.Attribute[3].@Name == "ApprovedRequests"
		xml.AttributeStatement.Attribute[3].AttributeValue.size() == 2
		xml.AttributeStatement.Attribute[3].AttributeValue[0] == "abcdef"
		xml.AttributeStatement.Attribute[3].AttributeValue[1] == "defcva"
		xml.AttributeStatement.EncryptedAttribute.size() == 1
		verifySignature(ticketData)
		
		when: "Verify that null as destination id sets the attribute as ANY and no approvers doesn't add any encrypted attribute"
		ticketData = pp.genApprovalTicket("someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject","1234",["abcdef", "defcva"], null, null, null)
		//println new String(ticketData)

		xml = new XmlSlurper().parse(new ByteArrayInputStream(ticketData))
		then:
		xml.AttributeStatement.Attribute.size() == 4
		xml.AttributeStatement.Attribute[1].@Name == AssertionPayloadParser.ATTRIBUTE_NAME_DESTINATIONID
		xml.AttributeStatement.Attribute[1].AttributeValue == AssertionPayloadParser.ANY_DESTINATION
		xml.AttributeStatement.EncryptedAttribute.size() == 0
	}

	
	def "Verify genFailureMessage() generates a valid Failure message"(){
		when: "Generate a message with failure message"
		byte[] samlPData = pp.genFailureMessage("_143214321", ResponseStatusCodes.REQUESTER, "Some Error")
		//println new String(samlPData)

		def xml = new XmlSlurper().parse(new ByteArrayInputStream(samlPData))
		then:
		xml.@ID.toString().length() > 0
		xml.@IssueInstant == "2015-07-07T14:26:53.000Z"
		xml.@Version == AssertionPayloadParser.DEFAULT_ASSERTION_VERSION
		xml.@InResponseTo == "_143214321"
		xml.Status.StatusCode.@Value == ResponseStatusCodes.REQUESTER.getURIValue()
		xml.Status.StatusMessage == "Some Error"
		
		when: "Generate a message without failure message"
		samlPData = pp.genFailureMessage("_143214321", ResponseStatusCodes.REQUESTER, null)
		//println new String(samlPData)

		xml = new XmlSlurper().parse(new ByteArrayInputStream(samlPData))
		then:
		xml.@ID.toString().length() > 0
		xml.@IssueInstant == "2015-07-07T14:26:53.000Z"
		xml.@Version == AssertionPayloadParser.DEFAULT_ASSERTION_VERSION
		xml.@InResponseTo == "_143214321"
		xml.Status.StatusCode.@Value == ResponseStatusCodes.REQUESTER.getURIValue()
		xml.Status.StatusMessage.toString() == ""
	}
	
	def "Verify parseAttributeQueryResponse() parses Distibuted Authorization Ticket successfully"(){
		when:
		ResponseType resp = pp.parseAttributeQueryResponse(pp.genDistributedAuthorizationTicket("_123456789","someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject",["role1", "role2"],twoReceiptiensValidFirst))
		then:
		resp.getInResponseTo() == "_123456789"
		resp.getAssertionOrEncryptedAssertion().get(0) instanceof AssertionType
	}
	
	
	def "Verify parseAttributeQueryResponse() parses User Data Ticket successfully"(){
		when:
		ResponseType resp = pp.parseAttributeQueryResponse(pp.genUserDataTicket("_123456789", "someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject","SomeDisplayName","SomeTokenType",[fv1, fv2], twoReceiptiensValidFirst))
		then:
		resp.getInResponseTo() == "_123456789"
		resp.getAssertionOrEncryptedAssertion().get(0) instanceof AssertionType
	}
	
	
	def "Verify parseAttributeQueryResponse() parses Failure Response successfully"(){
		when:
		ResponseType resp = pp.parseAttributeQueryResponse(pp.genFailureMessage("_143214321", ResponseStatusCodes.REQUESTER, "Some Error"))
		then:
		resp.getInResponseTo() == "_143214321"
		resp.getStatus().statusMessage == "Some Error"
	}
	
	def "Verify that parseApprovalTicket parses an approval ticket successfully"(){
		when:
		JAXBElement<AssertionType> assertion = pp.parseApprovalTicket(pp.genApprovalTicket("someIssuer", new Date(1436279212000), new Date(1436279412000), "SomeSubject","1234",["abcdef", "defcva"], null, genApprovers(), twoReceiptiensValidFirst))
		then:
		assertion != null
		assertion.value instanceof AssertionType
	}
	
	def "Verify getAssertionFromResponseType() returns assertion if it exists in respinse"(){
		setup:
		ResponseType resp = pp.parseAttributeQueryResponse(pp.genUserDataTicket("_123456789", "someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject","SomeDisplayName","SomeTokenType",[fv1, fv2], twoReceiptiensValidFirst))
		when:
		def assertion = pp.getAssertionFromResponseType(resp) 
		then:
		assertion instanceof JAXBElement<AssertionType>
	}
	
	def "Verify getAssertionFromResponseType() returns null if no assertion exists in respinse"(){
		setup:
		ResponseType resp = pp.parseAttributeQueryResponse(pp.genFailureMessage("_143214321", ResponseStatusCodes.REQUESTER, "Some Error"))
		when:
		def assertion = pp.getAssertionFromResponseType(resp)
		then:
		assertion == null
	}
	
	def "Verify that verifyAssertionConditions verifies notBefore and notOnOrAfter correctly"(){
	   setup:
	   def ticket = pp.getAssertionUnmarshaller().unmarshal(new ByteArrayInputStream(pp.genApprovalTicket("someIssuer", new Date(1436279212000), new Date(1436279412000), "SomeSubject","1234",["abcdef", "defcva"],null,null,null))).getValue()
	   
	   createMockedTime(1436279211000)
	   when: "Verify that MessageContent is thrown if not yet valid"
	   pp.verifyAssertionConditions(ticket)
	   then:	
	   thrown MessageContentException
	   
	   when: "Same millisecond as not before is valid"
	   createMockedTime(1436279212000)
	   pp.verifyAssertionConditions(ticket)
	   then:
	   true
	   
	   when: "inbetween no before and not on of after is valid"
	   createMockedTime(1436279213000)
	   pp.verifyAssertionConditions(ticket)
	   then:
	   true
	   
	   when: "Same millisecond as notOnOrAfter is not valid"
	   createMockedTime(1436279412000)
	   pp.verifyAssertionConditions(ticket)
	   then:
	   thrown MessageContentException
	   
	   when: "After notOnOrAfter is also not valid"
	   createMockedTime(1436279413000)
	   pp.verifyAssertionConditions(ticket)
	   then:
	   thrown MessageContentException
	}
	
	def "Verify that getCertificateFromAssertion finds the first certificate from an assertion"(){
	   setup:
	   JAXBElement<AssertionType> assertion = pp.parseApprovalTicket(pp.genApprovalTicket("someIssuer", new Date(1436279212000), new Date(1436279412000), "SomeSubject","1234",["abcdef", "defcva"],null, null, null))
	   when:
	   X509Certificate cert = pp.getCertificateFromAssertion(assertion)
	   then:
	   cert != null
	   
	   when: "No X509Certificate in key info will throw MessageContentException"
	   assertion = pp.getAssertionUnmarshaller().unmarshal(new ByteArrayInputStream(assertionWithNoX509Data))
	   pp.getCertificateFromAssertion(assertion)
	   then:
	   thrown MessageContentException
	}
	
	
	def "Test to getAssertionsFromCSMessage() from a ChangeCredentialStatusRequest with two assertions"(){
		setup:
		ResponseType ticketResp =  pp.parseAttributeQueryResponse(pp.genDistributedAuthorizationTicket("_123456789", "someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject",["role1", "role2"], twoReceiptiensValidFirst))
		JAXBElement<AssertionType> ticketAssertion = pp.getAssertionFromResponseType(ticketResp)
		JAXBElement<AssertionType> approvalResp = pp.parseApprovalTicket(pp.genApprovalTicket("someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject","1234",["abcdef", "defcva"],null, genApprovers(),twoReceiptiensValidFirst))
		def assertions = [approvalResp, ticketAssertion]
		
		byte[] requestData = credManagementPayloadParser.genChangeCredentialStatusRequest(TEST_ID, "somedst", "someorg", "someissuer", "123", 100, "", null, assertions)
		CSMessage csMessage = credManagementPayloadParser.parseMessage(requestData)
		
		when:
		List result = pp.getAssertionsFromCSMessage(csMessage)
		then:
		result.size() == 2
		result[0].value instanceof AssertionType
		result[1].value instanceof AssertionType
		result[0].value != result[1].value
		
	}

	def "Verify that getAssertionType finds the correct assertion type for each type of assertion"(){
		setup:
		ResponseType userDataResp =  pp.parseAttributeQueryResponse(pp.genUserDataTicket("_123456789", "someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject","SomeDisplayName","SomeTokenType",[fv1, fv2], twoReceiptiensValidFirst))
		ResponseType ticketResp =  pp.parseAttributeQueryResponse(pp.genDistributedAuthorizationTicket("_123456789", "someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject",["role1", "role2"], twoReceiptiensValidFirst))
		JAXBElement<AssertionType> userDataAssertion = pp.getAssertionFromResponseType(userDataResp)
		JAXBElement<AssertionType> ticketAssertion = pp.getAssertionFromResponseType(ticketResp)
		JAXBElement<AssertionType> approvalResp = pp.parseApprovalTicket(pp.genApprovalTicket("someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject","1234",["abcdef", "defcva"],null, genApprovers(), twoReceiptiensValidFirst))
	
		expect:
		pp.getTypeOfAssertion(userDataAssertion) == AssertionTypeEnum.USER_DATA
		pp.getTypeOfAssertion(ticketAssertion) == AssertionTypeEnum.AUTHORIZATION_TICKET
		pp.getTypeOfAssertion(approvalResp) == AssertionTypeEnum.APPROVAL_TICKET
		
		when:
		approvalResp.value.statementOrAuthnStatementOrAuthzDecisionStatement[0].attributeOrEncryptedAttribute[0].attributeValue[0] = "INVALID"
		pp.getTypeOfAssertion(approvalResp)
		
		then:
		thrown MessageContentException

	}
	
	def "Verify that parseAssertion filters out authorization and user data tickets and returns undecrypted approval tickets"(){
		setup:
		ResponseType userDataResp =  pp.parseAttributeQueryResponse(pp.genUserDataTicket("_123456789", "someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject","SomeDisplayName","SomeTokenType",[fv1, fv2], twoReceiptiensValidFirst))
		ResponseType ticketResp =  pp.parseAttributeQueryResponse(pp.genDistributedAuthorizationTicket("_123456789", "someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject",["role1", "role2"], twoReceiptiensValidFirst))
		JAXBElement<AssertionType> userDataAssertion = pp.getAssertionFromResponseType(userDataResp)
		JAXBElement<AssertionType> authAssertion = pp.getAssertionFromResponseType(ticketResp)
		JAXBElement<AssertionType> approvalResp = pp.parseApprovalTicket(pp.genApprovalTicket("someIssuer", new Date(1436279212427), new Date(1436279312427), "SomeSubject","1234",["abcdef", "defcva"],null, genApprovers(), twoReceiptiensValidFirst))
	
		when:
		List<AssertionData> pa = pp.parseAssertions([userDataAssertion, authAssertion, approvalResp])
		
		then:
		pa.size() == 1
		pa[0] instanceof ApprovalAssertionData
		pa[0].approvers == null
		
	}
	
	/*
	 * parseAttributeQuery is tested in AttributeQueryDataSpec
	 */

	private def createMockedTime(long currentTime){
		pp.systemTime = Mock(SystemTime)
		pp.systemTime.getSystemTime() >> new Date(currentTime)
		pp.samlAssertionMessageParser.systemTime = pp.systemTime
	}	

    private void verifySignature(byte[] message) throws Exception{
		try{
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setNamespaceAware(true);
			DocumentBuilder builder = factory.newDocumentBuilder();
			Document doc = builder.parse(new InputSource(new ByteArrayInputStream(message)));

			Element signature = doc.getElementsByTagName("ds:Signature").item(0);

			if(signature == null){
				throw new MessageContentException("Required digital signature not found in message.");
			}
			
			X509Certificate signerCert = null
			NodeList certList = signature.getElementsByTagNameNS(XMLSigner.XMLDSIG_NAMESPACE, "X509Certificate");
			if(certList.getLength() > 0){
				String certData = certList.item(0).getFirstChild().getNodeValue();
				if(certData != null){
					signerCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.decode(certData)));
				}
			}
			
			if(signerCert == null){
				throw new MessageContentException("Invalid signature, no related certificate found.")
			}
			

			DOMValidateContext validationContext = new DOMValidateContext(signerCert.getPublicKey(), signature);
			validationContext.setIdAttributeNS(pp.assertionSignatureLocationFinder.getSignatureLocations(doc)[0], null, "ID");
			XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM",new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
			XMLSignature sig =  signatureFactory.unmarshalXMLSignature(validationContext);
			if(!sig.validate(validationContext)){
				throw new MessageContentException("Error, signed message didn't pass validation.");
			}
			
		}catch(Exception e){
			if(e instanceof MessageContentException ){
				throw (MessageContentException) e;
			}
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageContentException("Error validating signature of message: " + e.getMessage(),e);
		}
	}
	
	static def genApprovers(){
		def ap1 = new Approver()
		ap1.type = ApproverType.MANUAL
		ap1.approvalDate = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1436279213000))
		ap1.description = "Some Approval"
		ap1.credential = genCredential()
		
		def ap2 = new Approver()
		ap2.type = ApproverType.AUTOMATIC
		ap2.approvalDate = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1436279214000))
		ap2.credential = genCredential()
		
		return [ap1, ap2]
	}

	static Credential genCredential(){
		Credential c = new Credential()
		c.credentialRequestId = 1
		c.uniqueId = "SomeUniqueId"
		c.displayName = "SomeDisplayName"
		c.serialNumber = "SomeSerialNumber"
		c.issuerId = "SomeIssuerID"
		c.status = 100
		c.credentialType = AvailableCredentialTypes.CREDENTIAL_TYPE_X509CERTIFICATE
		c.credentialSubType = "SomeCredentialSubtype"
		c.credentialData = "SomeCredentialData".getBytes()
		c.issueDate = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1436279213000))
		c.expireDate = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1436279213000))
		c.validFromDate = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1436279213000))

		return c
	}
	
	private String docToString(Document doc) throws Exception {

		ByteArrayOutputStream bo = new ByteArrayOutputStream();

		TransformerFactory factory = TransformerFactory.newInstance();
		Transformer transformer = factory.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		transformer.setOutputProperty(OutputKeys.INDENT, "yes");
		DOMSource source = new DOMSource(doc);
		StreamResult result = new StreamResult(bo);
		transformer.transform(source, result);

		bo.close();
		return new String(bo.toByteArray(),"UTF-8")
		
	}

	public static byte[] base64Cert =("MIIDLTCCAhWgAwIBAgIIYmVP6xQ/t3QwDQYJKoZIhvcNAQEFBQAwJDETMBEGA1UE" +
		"AwwKVGVzdCBlSURDQTENMAsGA1UECgwEVGVzdDAeFw0xMTEwMjExNDM2MzlaFw0z" +
		"MTEwMjExNDM2MzlaMCQxEzARBgNVBAMMClRlc3QgZUlEQ0ExDTALBgNVBAoMBFRl" +
		"c3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDecUf5if2UdWbV/HIj" +
		"h6U3XIymmh28wo8VVxPIbV1A8Yxz7QaMkP8vqaDwHnB1B6mHEjn4VyVogxWxI70I" +
		"wPudUL+Oxkc9ZL7H7zkbi6l2d/n85PjyZvdarCwcBzpEqIRsc+Wa3bGFKBpdZjwL" +
		"XjuuI4YWx+uUrQ96X+WusvFcb8C4Ru3w/K8Saf7yLJNvqmTJrgAOeKY49Jnp9V5x" +
		"9dGe+xpHR3t2xhJ5HXhm+SeUsrH5fHXky7/OVKvLPOXSve+1KHpyp+eOxxgYozTh" +
		"5k+viL0pP9G3AbEPp1mXtxCNzRjUgNlG0BDSIbowD5JciLkz8uYbamLzoUiz1KzZ" +
		"uCfXAgMBAAGjYzBhMB0GA1UdDgQWBBT6HyWgz7ykq9BxTCaULtOIjen3bDAPBgNV" +
		"HRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFPofJaDPvKSr0HFMJpQu04iN6fdsMA4G" +
		"A1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQUFAAOCAQEAbG7Y+rm82Gz1yIWVFKBf" +
		"XxDee7UwX2pyKdDfvRf9lFLxXv4LKBnuM5Zlb2RPdAAe7tTMtnYDwOWs4Uniy57h" +
		"YrCKU3v80u4uZoH8FNCG22APWQ+xa5UQtuq0yRf2xp2e4wjGZLQZlYUbePAZEjle" +
		"0E2YIa/kOrlvy5Z62sj24yczBL9uHfWpQUefA1+R9JpbOj0WEk+rAV0xJ2knmC/R" +
		"NzHWz92kL6UKUFzyBXBiBbY7TSVjO+bV/uPaTEVP7QhJk4Cahg1a7h8iMdF78ths" +
		"+xMeZX1KyiL4Dpo2rocZAvdL/C8qkt/uEgOjwOTdmoRVxkFWcm+DRNa26cclBQ4t" +
		"Vw==").getBytes();
  
	public static byte[] assertionWithNoX509Data = ("""<?xml version="1.0" encoding="UTF-8" standalone="no"?><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" ID="_AA6A0B1D-6DBD-4256-88FB-AFF2D2A122C1" IssueInstant="2015-07-07T16:26:53.000+02:00" Version="2.0"><saml:Issuer>someIssuer</saml:Issuer><ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_AA6A0B1D-6DBD-4256-88FB-AFF2D2A122C1"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>p2dIvIXjLGuuYaB7Lql7Am4qIzNz62qnQVr7Cc8DpUQ=</DigestValue></Reference></SignedInfo><SignatureValue>MdcKaOnYLG9ILCvAEM1xfc929mR/WYTg4TUBIlLvv8L34SBY1GMwA0T/GKfAziiurmo9OQvRmLPD
QAHj+RRx1GXRsezrpgYuTm5dq11GkkS15zWJzHvG/NAf4EnpMDn/DqZLQUSxY7HFhAkGFPAW/nSn
OUXtU9haVi1+MpFYdmkWU7RUraJM2reJug62a9Mt4Yvz1yCPidnpY0poJv1c0OkkC8KKSVp3cuhj
t1UioDhSaZKnCFxz/OnM56jGdw13dG+joHMn7vna7YqODDzur2bmv6LhIWWCPza97qkrDbLvRZtQ
yXlrlG1nRYcnV2oaFAbqF2HgrOOBigkhsOOmRQ==</SignatureValue><KeyInfo><KeyName>asdf</KeyName></KeyInfo></ds:Signature><saml:Subject><saml:NameID>SomeSubject</saml:NameID></saml:Subject><saml:Conditions NotBefore="2015-07-07T16:26:52.000+02:00" NotOnOrAfter="2015-07-07T16:30:12.000+02:00"/><saml:AttributeStatement><saml:Attribute Name="ApprovalId"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">1234</saml:AttributeValue></saml:Attribute><saml:Attribute Name="ApprovedRequests"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">abcdef</saml:AttributeValue><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">defcva</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>""").getBytes("UTF-8")
	
}
