package org.certificateservices.messages.saml2

import org.bouncycastle.util.encoders.Base64
import org.certificateservices.messages.ContextMessageSecurityProvider
import org.certificateservices.messages.MessageContentException
import org.certificateservices.messages.assertion.AssertionPayloadParser
import org.certificateservices.messages.assertion.ResponseStatusCodes
import org.certificateservices.messages.authorization.AuthorizationPayloadParser
import org.certificateservices.messages.credmanagement.CredManagementPayloadParser
import org.certificateservices.messages.credmanagement.jaxb.IssueTokenCredentialsRequest
import org.certificateservices.messages.csmessages.DefaultCSMessageParser
import org.certificateservices.messages.csmessages.jaxb.CSMessage
import org.certificateservices.messages.saml2.assertion.SAMLAssertionMessageParser
import org.certificateservices.messages.saml2.assertion.jaxb.*
import org.certificateservices.messages.saml2.protocol.SAMLProtocolMessageParser
import org.certificateservices.messages.saml2.protocol.jaxb.ExtensionsType
import org.certificateservices.messages.saml2.protocol.jaxb.ResponseType
import org.certificateservices.messages.utils.MessageGenerateUtils
import org.certificateservices.messages.utils.SystemTime
import org.certificateservices.messages.xenc.jaxb.EncryptedDataType
import org.w3c.dom.Document
import spock.lang.IgnoreIf

import javax.xml.bind.JAXBElement

import static org.certificateservices.messages.TestUtils.printXML
import static org.certificateservices.messages.TestUtils.slurpXml
import static org.certificateservices.messages.ContextMessageSecurityProvider.DEFAULT_CONTEXT

class BaseSAMLMessageParserSpec extends CommonSAMLMessageParserSpecification {

	BaseSAMLMessageParser bsmp;
	SAMLProtocolMessageParser spmp;

	BaseSAMLMessageParser.SimpleConditionLookup scl = new BaseSAMLMessageParser.SimpleConditionLookup(1000L);


	def setup(){
		spmp = new SAMLProtocolMessageParser();
		spmp.init(secProv, null);
		spmp.systemTime = mockedSystemTime

		bsmp = spmp;



	}



	def "Verify that init with custom JAXB and Schema setting is initialized properly"(){
	   setup:
	    Properties c = new Properties();
		c.setProperty(BaseSAMLMessageParser.SETTING_CUSTOM_JAXBCLASSPATH, "org.certificateservices.messages.csmessages.jaxb:org.certificateservices.messages.credmanagement.jaxb:org.certificateservices.messages.authorization.jaxb")
		c.setProperty(BaseSAMLMessageParser.SETTING_CUSTOM_SCHEMALOCATIONS, DefaultCSMessageParser.CSMESSAGE_XSD_SCHEMA_2_0_RESOURCE_LOCATION + ":" + CredManagementPayloadParser.CREDMANAGEMENT_XSD_SCHEMA_2_0_RESOURCE_LOCATION + ":" + AuthorizationPayloadParser.AUTHORIZATION_XSD_SCHEMA_2_0_RESOURCE_LOCATION)
		SAMLAssertionMessageParser p = new SAMLAssertionMessageParser()
		def customMock = Mock(SAMLParserCustomisations)
		customMock.getCustomJAXBClasspath() >> "org.certificateservices.messages.csmessages.jaxb:org.certificateservices.messages.credmanagement.jaxb:org.certificateservices.messages.authorization.jaxb"
		customMock.getCustomSchemaLocations() >> [DefaultCSMessageParser.CSMESSAGE_XSD_SCHEMA_2_0_RESOURCE_LOCATION , CredManagementPayloadParser.CREDMANAGEMENT_XSD_SCHEMA_2_0_RESOURCE_LOCATION , AuthorizationPayloadParser.AUTHORIZATION_XSD_SCHEMA_2_0_RESOURCE_LOCATION]
		when:
		p.init(secProv, customMock);
		then:
		p.customJAXBClasspath == "org.certificateservices.messages.csmessages.jaxb:org.certificateservices.messages.credmanagement.jaxb:org.certificateservices.messages.authorization.jaxb"
		p.customSchemaLocations.length == 3
		p.customSchemaLocations[0] == DefaultCSMessageParser.CSMESSAGE_XSD_SCHEMA_2_0_RESOURCE_LOCATION
		p.customSchemaLocations[1] == CredManagementPayloadParser.CREDMANAGEMENT_XSD_SCHEMA_2_0_RESOURCE_LOCATION
		p.customSchemaLocations[2] == AuthorizationPayloadParser.AUTHORIZATION_XSD_SCHEMA_2_0_RESOURCE_LOCATION
		p.getJAXBContext().createJAXBIntrospector().getElementName(new IssueTokenCredentialsRequest()) != null
		when:
		Object o = p.parseMessage(DEFAULT_CONTEXT,csMessageData,false)
		then:
		o instanceof CSMessage
		p.schemaValidate(o)
		when:
		o.setID(null);
		p.schemaValidate(o)
		then:
		thrown MessageContentException
	}
	
	def "Verify genFailureMessage() generates a valid Failure message"(){
		when: "Generate a message with failure message"
		byte[] samlPData = bsmp.genFailureMessage(DEFAULT_CONTEXT,"_143214321", ResponseStatusCodes.REQUESTER, "Some Error")
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
		samlPData = bsmp.genFailureMessage(DEFAULT_CONTEXT,"_143214321", ResponseStatusCodes.REQUESTER, null)
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


	
	def "Verify getAssertionFromResponseType() returns null if no assertion exists in respinse"(){
		setup:
		ResponseType resp = spmp.parseMessage(DEFAULT_CONTEXT,bsmp.genFailureMessage(DEFAULT_CONTEXT,"_143214321", ResponseStatusCodes.REQUESTER, "Some Error"), false)
		when:
		def assertion = bsmp.getAssertionFromResponseType(resp)
		then:
		assertion == null
	}
	
	def "Verify that verifyAssertionConditions verifies notBefore and notOnOrAfter correctly"(){
	   setup:
	   def ticket = samp.generateSimpleAssertion("someIssuer", new Date(1436279212000), new Date(1436279412000), "SomeSubject",null).getValue()

	   createMockedTime(1436279210000)
	   when: "Verify that MessageContent is thrown if not yet valid"
	   bsmp.verifyAssertionConditions(ticket, scl)
	   then:	
	   thrown MessageContentException
	   
	   when: "Same millisecond as not before is valid"
	   createMockedTime(1436279212000)
	   bsmp.verifyAssertionConditions(ticket, scl)
	   then:
	   true
	   
	   when: "inbetween no before and not on of after is valid"
	   createMockedTime(1436279213000)
	   bsmp.verifyAssertionConditions(ticket, scl)
	   then:
	   true
	   
	   when: "Same millisecond as notOnOrAfter is not valid"
	   createMockedTime(1436279413000)
	   bsmp.verifyAssertionConditions(ticket, scl)
	   then:
	   thrown MessageContentException
	   
	   when: "After notOnOrAfter is also not valid"
	   createMockedTime(1436279414000)
	   bsmp.verifyAssertionConditions(ticket, scl)
	   then:
	   thrown MessageContentException
	}

	def "Verify that conditions that contains OneTime or AudienceRestriction throws MessageContentException for SimpleConditionsLookup"(){
		when: "Very basic conditions is ok"
		ConditionsType conditionsType = genValidConditionsType();
		bsmp.verifyConditions(conditionsType, "SomeType", "SomeId", scl)
		then:
		true
		when:
		conditionsType = genValidConditionsType();
		conditionsType.conditionOrAudienceRestrictionOrOneTimeUse.add(of.createOneTimeUseType());
		bsmp.verifyConditions(conditionsType, "SomeType", "SomeId", scl)
		then:
		thrown MessageContentException
		when:
		AudienceRestrictionType art = of.createAudienceRestrictionType();
		art.audience.add("SomeAudience")
		conditionsType = genValidConditionsType();
		conditionsType.conditionOrAudienceRestrictionOrOneTimeUse.add(art);
		bsmp.verifyConditions(conditionsType, "SomeType", "SomeId",scl)
		then:
		thrown MessageContentException
	}

	def "Verify that verifyConditions verifies OneTime properly"(){
		setup:
		def conditionLookup = Mock(BaseSAMLMessageParser.ConditionLookup)
		2 * conditionLookup.usedBefore(_) >> { args ->
			return args[0] == "1"}
		when:
		ConditionsType conditionsType = genValidConditionsType();
		conditionsType.conditionOrAudienceRestrictionOrOneTimeUse.add(of.createOneTimeUseType())
		bsmp.verifyConditions(conditionsType, "SomeTyp2","1", conditionLookup)
		then:
		thrown MessageContentException
		when:
		bsmp.verifyConditions(conditionsType, "SomeTyp2","2", conditionLookup)
		then:
		true
	}

	def "Verify that verifyConditions verifies AudienceRestriction properly"(){
		setup:
		def conditionLookup = Mock(BaseSAMLMessageParser.ConditionLookup)
		6 * conditionLookup.getThisAudienceId() >> {
			"ThisAudienceId"}
		when:
		AudienceRestrictionType audienceRestriction = of.createAudienceRestrictionType();
		audienceRestriction.audience.add("AudienceId1")
		audienceRestriction.audience.add("AudienceId2")
		ConditionsType conditionsType = genValidConditionsType();
		conditionsType.conditionOrAudienceRestrictionOrOneTimeUse.add(audienceRestriction)
		bsmp.verifyConditions(conditionsType, "SomeTyp2","1", conditionLookup)
		then:
		thrown MessageContentException
		when: "Verify that the is an OR operation inside a condition"
		audienceRestriction.audience.add("ThisAudienceId")
		bsmp.verifyConditions(conditionsType, "SomeTyp2","2", conditionLookup)
		then:
		true
		when: "Verify that the is an AND operation between conditions"
		AudienceRestrictionType audienceRestriction2 = of.createAudienceRestrictionType();
		audienceRestriction2.audience.add("AudienceId1")
		conditionsType.conditionOrAudienceRestrictionOrOneTimeUse.add(audienceRestriction2)
		bsmp.verifyConditions(conditionsType, "SomeTyp2","1", conditionLookup)
		then:
		thrown MessageContentException
		when:
		audienceRestriction2.audience.add("ThisAudienceId")
		bsmp.verifyConditions(conditionsType, "SomeTyp2","2", conditionLookup)
		then:
		true
	}

	def "Generate full SAMLP FailureMessage and verify that it is populated correctly"(){
		when:
		NameIDType issuer = of.createNameIDType();
		issuer.setValue("SomeIssuer");

		ExtensionsType extensions = samlpOf.createExtensionsType()
		extensions.any.add(dsignObj.createKeyName("SomeKeyName"))

		SubjectType subject = of.createSubjectType()
		NameIDType subjectNameId =of.createNameIDType()
		subjectNameId.setValue("SomeSubject");
		subject.getContent().add(of.createNameID(subjectNameId));


		byte[] failureMessage = bsmp.genFailureMessage(DEFAULT_CONTEXT,"SomeResponseId", issuer,"SomeDestination","SomeConsent", extensions
		,ResponseStatusCodes.RESPONDER,"SomeFailureMessage", true);

		def xml = slurpXml(failureMessage)
		//printXML(failureMessage)

		then:
		xml.@Consent == "SomeConsent"
		xml.@Destination == "SomeDestination"
		xml.@ID.toString().startsWith("_")
		xml.@IssueInstant.toString().startsWith("20")
		xml.@Version == "2.0"

		xml.Issuer == "SomeIssuer"
		xml.Signature.SignedInfo.size() == 1
		xml.Extensions.KeyName == "SomeKeyName"
		xml.Status.StatusCode.@Value == "urn:oasis:names:tc:SAML:2.0:status:Responder"
		xml.Status.StatusMessage == "SomeFailureMessage"

		when:
		ResponseType rt = bsmp.parseMessage(DEFAULT_CONTEXT,failureMessage, true)

		then:
		rt.getIssuer().value == "SomeIssuer"

		when:
		failureMessage = bsmp.genFailureMessage(null,null, null,null,null, null
				,ResponseStatusCodes.RESPONDER,null, false);

		xml = slurpXml(failureMessage)
		//printXML(failureMessage)
		then:
		xml.Status.StatusCode.@Value == "urn:oasis:names:tc:SAML:2.0:status:Responder"
		xml.Signature.SignedInfo.size() == 0

		when:
		rt = bsmp.parseMessage(null,failureMessage, false)
		then:
		rt.status.statusCode.value == "urn:oasis:names:tc:SAML:2.0:status:Responder"

		when: "Verify that unsigned message throws exception if signature is required"
		bsmp.parseMessage(DEFAULT_CONTEXT,failureMessage, true)
		then:
		thrown MessageContentException

	}

	def "Verify that decryptAssertion decrypts all encrypted attributes."(){
		setup:

		AttributeType encryptedAttributeType = of.createAttributeType();
		encryptedAttributeType.setName("SomeEncryptedAttribute");
		encryptedAttributeType.getAttributeValue().add("SomeValue")
		JAXBElement<AttributeType> encryptedAttribute = of.createAttribute(encryptedAttributeType);


		JAXBElement<EncryptedDataType> encryptedData = (JAXBElement<EncryptedDataType>) bsmp.getUnmarshaller().unmarshal(bsmp.xmlEncrypter.encryptElement(encryptedAttribute, twoReceiptiensValidFirst, true));
		EncryptedElementType encryptedElementType1 = of.createEncryptedElementType();
		encryptedElementType1.setEncryptedData(encryptedData.getValue());

		List<Object> attributes = [encryptedElementType1]

		JAXBElement<AssertionType> assertion = samp.generateSimpleAssertion("someIssuer", new Date(1436279212000), new Date(1436279412000), "SomeSubject",attributes)
		expect:
		assertion.getValue().getStatementOrAuthnStatementOrAuthzDecisionStatement().get(0).getAttributeOrEncryptedAttribute().get(0) instanceof EncryptedElementType
		assertion.getValue().getStatementOrAuthnStatementOrAuthzDecisionStatement().get(0).getAttributeOrEncryptedAttribute().size() == 1

		when:
		assertion = bsmp.decryptAssertion(DEFAULT_CONTEXT,assertion)
		then:
		assertion.getValue().getStatementOrAuthnStatementOrAuthzDecisionStatement().get(0).getAttributeOrEncryptedAttribute().get(0) instanceof AttributeType
		assertion.getValue().getStatementOrAuthnStatementOrAuthzDecisionStatement().get(0).getAttributeOrEncryptedAttribute().size() == 1
	}

	def "Verify that generate simple genSuccessfulSAMLPResponse returns a XML message as expected"(){
		setup:
		def assertion = samp.generateSimpleAssertion("someIssuer", new Date(1436279212000), new Date(1436279412000), "SomeSubject",null);
		when:
		ResponseType responseType = bsmp.genSuccessfulSAMLPResponse("SomeInResponseTo", assertion).value

		then:
		responseType.getID().startsWith("_")
		responseType.getInResponseTo() == "SomeInResponseTo"
		responseType.getIssueInstant() != null
		responseType.status.statusCode.value == ResponseStatusCodes.SUCCESS.getURIValue()
		responseType.version == BaseSAMLMessageParser.DEFAULT_SAML_VERSION
		responseType.getAssertionOrEncryptedAssertion().size() == 1

	}

	@IgnoreIf({ System.properties['os.name'].toLowerCase().startsWith('windows') })
	def "Verify marshallDoc and unmarshallDoc works correctly"(){
		when:
		Document doc = samp.unmarshallDoc(csMessageData)

		then:
		doc.getDocumentElement().getElementsByTagNameNS("http://certificateservices.org/xsd/csmessages2_0", "name").length > 0

		when:
		byte[] messageData = samp.marshallDoc(doc)

		then:
		messageData == csMessageData

	}


	// getCertificateFromAssertion is tested in AssertionPaylodParserSpec

    // genSuccessfulSAMLPResponse is tested in AssertionPaylodParserSpec


	private def createMockedTime(long currentTime){
		bsmp.systemTime = Mock(SystemTime)
		bsmp.systemTime.getSystemTime() >> new Date(currentTime)
		samp.systemTime  = bsmp.systemTime
	}	



	private ConditionsType genValidConditionsType(){
		ConditionsType conditionsType = of.createConditionsType()
		conditionsType.setNotBefore(MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1436279212000)))
		conditionsType.setNotOnOrAfter(MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(1436279412000)))
		return conditionsType;
	}
  
	public static byte[] assertionWithNoX509Data = ("""<?xml version="1.0" encoding="UTF-8" standalone="no"?><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" ID="_AA6A0B1D-6DBD-4256-88FB-AFF2D2A122C1" IssueInstant="2015-07-07T16:26:53.000+02:00" Version="2.0"><saml:Issuer>someIssuer</saml:Issuer><ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_AA6A0B1D-6DBD-4256-88FB-AFF2D2A122C1"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>p2dIvIXjLGuuYaB7Lql7Am4qIzNz62qnQVr7Cc8DpUQ=</DigestValue></Reference></SignedInfo><SignatureValue>MdcKaOnYLG9ILCvAEM1xfc929mR/WYTg4TUBIlLvv8L34SBY1GMwA0T/GKfAziiurmo9OQvRmLPD
QAHj+RRx1GXRsezrpgYuTm5dq11GkkS15zWJzHvG/NAf4EnpMDn/DqZLQUSxY7HFhAkGFPAW/nSn
OUXtU9haVi1+MpFYdmkWU7RUraJM2reJug62a9Mt4Yvz1yCPidnpY0poJv1c0OkkC8KKSVp3cuhj
t1UioDhSaZKnCFxz/OnM56jGdw13dG+joHMn7vna7YqODDzur2bmv6LhIWWCPza97qkrDbLvRZtQ
yXlrlG1nRYcnV2oaFAbqF2HgrOOBigkhsOOmRQ==</SignatureValue><KeyInfo><KeyName>asdf</KeyName></KeyInfo></ds:Signature><saml:Subject><saml:NameID>SomeSubject</saml:NameID></saml:Subject><saml:Conditions NotBefore="2015-07-07T16:26:52.000+02:00" NotOnOrAfter="2015-07-07T16:30:12.000+02:00"/><saml:AttributeStatement><saml:Attribute Name="ApprovalId"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">1234</saml:AttributeValue></saml:Attribute><saml:Attribute Name="ApprovedRequests"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">abcdef</saml:AttributeValue><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">defcva</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>""").getBytes("UTF-8")


	public static byte[] csMessageData = ("""<?xml version="1.0" encoding="UTF-8" standalone="no"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:auth="http://certificateservices.org/xsd/authorization2_0" xmlns:credmanagement="http://certificateservices.org/xsd/credmanagement2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:keystoremgmt="http://certificateservices.org/xsd/keystoremgmt2_0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="2.0" timeStamp="2017-01-03T21:23:35.517+03:00" version="2.0" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd"><cs:name>IsIssuerRequest</cs:name><cs:sourceId>SOMEREQUESTER</cs:sourceId><cs:destinationId>SOMESOURCEID</cs:destinationId><cs:organisation>someorg</cs:organisation><cs:originator><cs:credential><cs:credentialRequestId>123</cs:credentialRequestId><cs:uniqueId>SomeOriginatorUniqueId</cs:uniqueId><cs:displayName>SomeOrignatorDisplayName</cs:displayName><cs:serialNumber>SomeSerialNumber</cs:serialNumber><cs:issuerId>SomeIssuerId</cs:issuerId><cs:status>100</cs:status><cs:credentialType>SomeCredentialType</cs:credentialType><cs:credentialSubType>SomeCredentialSubType</cs:credentialSubType><cs:attributes><cs:attribute><cs:key>someattrkey</cs:key><cs:value>someattrvalue</cs:value></cs:attribute></cs:attributes><cs:usages><cs:usage>someusage</cs:usage></cs:usages><cs:credentialData>MTIzNDVBQkNFRg==</cs:credentialData><cs:issueDate>1970-01-01T03:00:01.234+01:00</cs:issueDate><cs:expireDate>1970-01-01T03:00:02.234+01:00</cs:expireDate><cs:validFromDate>1970-01-01T03:00:03.234+01:00</cs:validFromDate></cs:credential></cs:originator><cs:payload><credmanagement:IsIssuerRequest><credmanagement:issuerId>someIssuerId</credmanagement:issuerId></credmanagement:IsIssuerRequest></cs:payload><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#12345678-1234-4444-8000-123456789012"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>q2AO2wjreWtVHjCP2AWwYDjPeCpN3JRdC8vqEfyKWM0=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>MpD4UDsLvmkonQrt5lUNk1t+rJ9Ow9pqpuckHWGXaZ1WLw3cB7p4Y9M3ipJmp8JbwL/0Rq9FotWg
6XjRwfaa6DyIf5udxNHPSct4gVaUR1DcugSONqvLspggqq6TspZLYmx1TJ0jLV4KxhBW755kiRVr
c2lcsIb8URgEYJNRIYwYF6tUjMmI89ldlcsFuik1+SPUJY//p6TWzOVMgJT02NCVdONCOWtaONe+
QI+5xoxRJOhCMsGGdhKnRw/1GMWpWmA5AXNn7VZLH5KmUrJyA8Bu1hXfZ4mImi5ISLseE6ZR94kg
Lhn5cvJ823eDofkesC0bTKYXEpYM6KoQit0XJA==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
dXN0b21lcjEgQVQgU2VydmVyQ0ExGjAYBgNVBAoMEURlbW8gQ3VzdG9tZXIxIEFUMB4XDTEyMTAx
MDE0NDQwNFoXDTE0MTAxMDE0NDQwNFowKzENMAsGA1UEAwwEdGVzdDEaMBgGA1UECgwRRGVtbyBD
dXN0b21lcjEgQVQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCbDqmR4e8sgxw2Afi/
y3i/mT7WwtpW18/QfyUGpYPPxQ4bvPPn61y3jJg/dAbGHvnyQSHfIvrIJUN83q6evvk0bNZNVSEN
UEP29isE4D+KjD3PFtAzQq18P8m/8mSXMva5VTooEUSDX+VJ/6el6tnyZdc85AlIJkkkvyiDKcjh
f10yllaiVCHLunGMDXAec4DapPi5GdmSMMXyPOhRx5e+oy6b5q9XmT3C29VNVFf+tkAt3ew3BoQb
d+VrlBI4oRYq+mfbgkXU6dSKr9DRqhsbu5rU4Jdst2KClXsxaxvC0rVeKQ8iXCDKFH5glzhSYoeW
l7CI15CdQM6/so7EisSvAgMBAAGjgeMwgeAwHQYDVR0OBBYEFLpidyp0Pc46cUpJf1neFnq/rLJB
MAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUgEn+Hp9+Yxe4lOhaIPmf++Wu7SYwGAYDVR0gBBEw
DzANBgsrBgEEAYH1fgMDCTBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vYXQtY3JsLndtLm5ldC9k
ZW1vY3VzdG9tZXIxX3NlcnZlcmNhLmNybDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwDwYDVR0RBAgwBoIEdGVzdDANBgkqhkiG9w0BAQUFAAOCAQEAZxGls/mNT4GyAf9u9lg7
8sSA27sc3xFvHNogrT4yUCbYAOhLXO4HJ9XuKaFyz4bKz6JGdLaQDknDI1GUvpJLpiPTXk4cq1pp
HVt5/2QVeDCGtite4CH/YrAe4gufBqWo9q7XQeQbjil0mOUsSp1ErrcSadyT+KZoD4GXJBIVFcOI
WKL7aCHzSLpw/+DY1sEiAbStmhz0K+UrFK+FVdZn1RIWGeVClhJklLb2vNjQgPYGdd5nKyLrlA4z
ekPDDWdmmxwv4A3MG8KSnl8VBU5CmAZLR1YRaioK6xL1QaH0a16FTkn3y6GVeYUGsTeyLvLlfhgA
ZLCP64EJEfE1mGxCJg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></cs:CSMessage>""").getBytes("UTF-8")

}
