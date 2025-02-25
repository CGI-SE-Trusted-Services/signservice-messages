package org.signatureservice.messages.saml2.protocol

import org.signatureservice.messages.MessageContentException
import org.signatureservice.messages.assertion.ResponseStatusCodes
import org.signatureservice.messages.saml2.BaseSAMLMessageParser
import org.certificateservices.messages.saml2.CommonSAMLMessageParserSpecification
import org.signatureservice.messages.saml2.assertion.SAMLAssertionMessageParser
import org.signatureservice.messages.saml2.assertion.jaxb.AssertionType
import org.signatureservice.messages.saml2.assertion.jaxb.ConditionsType
import org.signatureservice.messages.saml2.assertion.jaxb.NameIDType
import org.signatureservice.messages.saml2.assertion.jaxb.SubjectType
import org.certificateservices.messages.saml2.protocol.jaxb.*
import org.signatureservice.messages.saml2.protocol.jaxb.AuthnContextComparisonType
import org.signatureservice.messages.saml2.protocol.jaxb.AuthnRequestType
import org.signatureservice.messages.saml2.protocol.jaxb.ExtensionsType
import org.signatureservice.messages.saml2.protocol.jaxb.NameIDPolicyType
import org.signatureservice.messages.saml2.protocol.jaxb.RequestedAuthnContextType
import org.signatureservice.messages.saml2.protocol.jaxb.ResponseType
import org.signatureservice.messages.saml2.protocol.jaxb.ScopingType
import org.signatureservice.messages.saml2.protocol.jaxb.StatusDetailType
import org.signatureservice.messages.sweeid2.pricipalselection1_0.PrincipalSelectionGenerator
import org.signatureservice.messages.sweeid2.pricipalselection1_0.jaxb.MatchValueType
import org.signatureservice.messages.utils.MessageGenerateUtils
import org.signatureservice.messages.sweeid2.pricipalselection1_0.jaxb.ObjectFactory

import javax.xml.bind.JAXBElement

import static org.certificateservices.messages.TestUtils.slurpXml
import static org.signatureservice.messages.ContextMessageSecurityProvider.DEFAULT_CONTEXT

class SAMLProtocolMessageParserSpec extends CommonSAMLMessageParserSpecification {


	SAMLProtocolMessageParser spmp;
	SAMLAssertionMessageParser samp;

    ObjectFactory pcsOf = new ObjectFactory()

	def setup(){
		spmp = new SAMLProtocolMessageParser();
		spmp.init(secProv);
		spmp.systemTime = mockedSystemTime

		samp = new SAMLAssertionMessageParser()
		samp.init(secProv)
		samp.systemTime = mockedSystemTime;
	}



	def "Verify that JAXBPackages(), getNameSpace(), getSignatureLocationFinder(), getDefaultSchemaLocations(), getOrganisationLookup() returns the correct values"(){
		expect:
		spmp.getJAXBPackages() == SAMLProtocolMessageParser.BASE_JAXB_CONTEXT
		spmp.getNameSpace() == BaseSAMLMessageParser.PROTOCOL_NAMESPACE
		spmp.getSignatureLocationFinder() == spmp.samlpSignatureLocationFinder
		spmp.getDefaultSchemaLocations().length== 4
		spmp.getOrganisationLookup() == null
	}


	def "Generate full AuthNRequest and verify that it is populated correctly"(){
		when:
		NameIDType issuer = of.createNameIDType();
		issuer.setValue("SomeIssuer");

        ExtensionsType extensions = samlpOf.createExtensionsType()
		extensions.any.add(dsignObj.createKeyName("SomeKeyName"))

		SubjectType subject = of.createSubjectType()
		NameIDType subjectNameId =of.createNameIDType()
		subjectNameId.setValue("SomeSubject");
		subject.getContent().add(of.createNameID(subjectNameId));

        NameIDPolicyType nameIdPolicy = samlpOf.createNameIDPolicyType()
		nameIdPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted")

		ConditionsType conditions = of.createConditionsType()
		conditions.setNotBefore(MessageGenerateUtils.dateToXMLGregorianCalendar(simpleDateFormat.parse("2016-02-01")))
		conditions.setNotOnOrAfter(MessageGenerateUtils.dateToXMLGregorianCalendar(simpleDateFormat.parse("2016-02-12")))

        RequestedAuthnContextType requestedAuthnContext = samlpOf.createRequestedAuthnContextType()
		requestedAuthnContext.authnContextClassRef.add("SomeContextClassRef")
		requestedAuthnContext.setComparison(AuthnContextComparisonType.EXACT)

        ScopingType scoping = samlpOf.createScopingType()
		scoping.setProxyCount(new BigInteger("123"))

		byte[] authNRequest = spmp.genAuthNRequest(DEFAULT_CONTEXT,"_1234512341234",true,false,"SomeProtocolBinding", 1,"http://assertionConsumerServiceURL",2,"SomeProviderName","SomeDestination","SomeConsent", issuer, extensions, subject, nameIdPolicy, conditions, requestedAuthnContext, scoping, true)

		def xml = slurpXml(authNRequest)
		//printXML(authNRequest)

		then:
		xml.@AssertionConsumerServiceIndex == "1"
		xml.@AssertionConsumerServiceURL == "http://assertionConsumerServiceURL"
		xml.@AttributeConsumingServiceIndex == "2"
		xml.@Consent == "SomeConsent"
		xml.@Destination == "SomeDestination"
		xml.@ID.toString() == "_1234512341234"
		xml.@IsPassive == "false"
		xml.@IssueInstant.toString().startsWith("20")
		xml.@ProtocolBinding == "SomeProtocolBinding"
		xml.@ProviderName == "SomeProviderName"
		xml.@Version == "2.0"

		xml.Issuer == "SomeIssuer"
		xml.Signature.SignedInfo.size() == 1
		xml.Extensions.KeyName == "SomeKeyName"
		xml.Subject.NameID == "SomeSubject"
		xml.NameIDPolicy.@Format == "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted"
		xml.Conditions.@NotBefore != null
		xml.Conditions.@NotOnOrAfter != null
		xml.RequestedAuthnContext.@Comparison == "exact"
		xml.RequestedAuthnContext.AuthnContextClassRef == "SomeContextClassRef"
		xml.Scoping.@ProxyCount == "123"
		when:
        AuthnRequestType art = spmp.parseMessage(DEFAULT_CONTEXT,authNRequest, true)

		then:
		art.getIssuer().value == "SomeIssuer"

		when:
		authNRequest = spmp.genAuthNRequest(DEFAULT_CONTEXT,"_1234512341234",true,false,"SomeProtocolBinding", 1,"http://assertionConsumerServiceURL",2,"SomeProviderName","SomeDestination","SomeConsent", issuer, extensions, subject, nameIdPolicy, conditions, requestedAuthnContext, scoping, false)

		xml = slurpXml(authNRequest)
		//printXML(authNRequest)
		then:
		xml.Issuer == "SomeIssuer"
		xml.Signature.SignedInfo.size() == 0

		when:
		art = spmp.parseMessage(DEFAULT_CONTEXT,authNRequest, false)
		then:
		art.getIssuer().value == "SomeIssuer"

		when: "Verify that unsigned message throws exception if signature is required"
		spmp.parseMessage(DEFAULT_CONTEXT,authNRequest, true)
		then:
		thrown MessageContentException

	}


	def "Generate minimal AuthNRequest and verify that it is populated correctly"(){
		when:
		byte[] authNRequest = spmp.genAuthNRequest(DEFAULT_CONTEXT,"_1234512341234",null,null,null, null,null,null,null,null,null, null, null, null, null, null, null, null, true)

		def xml = slurpXml(authNRequest)
		//printXML(authNRequest)
		AuthnRequestType art = spmp.parseMessage(DEFAULT_CONTEXT,authNRequest, true)

		then:
		xml.@ID == "_1234512341234"
		xml.@IssueInstant.toString().startsWith("20")
		xml.@Version == "2.0"

		xml.Signature.SignedInfo.size() == 1

		art.getID().startsWith("_")

	}

	def "Generate a full Response and verify all fields are populated correctly"(){
		when:
		NameIDType issuer = of.createNameIDType()
		issuer.setValue("SomeIssuer")

		ExtensionsType extensions = samlpOf.createExtensionsType()
		extensions.any.add(dsignObj.createKeyName("SomeKeyName"))

		SubjectType subject = of.createSubjectType()
		NameIDType subjectNameId =of.createNameIDType()
		subjectNameId.setValue("SomeSubject");
		subject.getContent().add(of.createNameID(subjectNameId));

        StatusDetailType statusDetailType = samlpOf.createStatusDetailType()
		statusDetailType.any.add(dsignObj.createKeyName("SomeKeyName"))

		// TODO EncryptedAssertion

		JAXBElement<AssertionType> assertion1 = samp.generateSimpleAssertion("someIssuer", new Date(1436279212000), new Date(1436279412000), "SomeSubject1",null)
		JAXBElement<AssertionType> assertion2 = samp.generateSimpleAssertion("someIssuer2", new Date(1436279212000), new Date(1436279412000), "SomeSubject2",null)

		byte[] response = spmp.genResponse(DEFAULT_CONTEXT,"SomeResponseTo",issuer,"SomeDestination","SomeConsent", extensions,ResponseStatusCodes.RESPONDER,"SomeStatusMessage", statusDetailType,[assertion1,assertion2], true, true);

		//printXML(response)
		def xml = slurpXml(response)
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
		xml.Status.StatusMessage == "SomeStatusMessage"
		xml.Status.StatusDetail.KeyName == "SomeKeyName"

		xml.Assertion[0].Signature.SignedInfo.size() == 1
		xml.Assertion[1].Signature.SignedInfo.size() == 1

		when: "Verify that is is parsable"
        ResponseType r = spmp.parseMessage(DEFAULT_CONTEXT,response,true)

		then:
		r.signature != null


		when: "Verify that it is possible to generate SAMLP signed only messages"
		response = spmp.genResponse(DEFAULT_CONTEXT,"SomeResponseTo",issuer,"SomeDestination","SomeConsent", extensions,ResponseStatusCodes.RESPONDER,"SomeStatusMessage", statusDetailType,[assertion1,assertion2], false, true);

		//printXML(response)
		xml = slurpXml(response)
		then:
		xml.Issuer == "SomeIssuer"
		xml.Signature.SignedInfo.size() == 1

		xml.Assertion[0].Signature.size() == 0
		xml.Assertion[1].Signature.size() == 0

		when: "Verify that is is parsable"
		r = spmp.parseMessage(DEFAULT_CONTEXT,response,true)

		then:
		r.signature != null

		when: "Verify that it is possible to generate Assertion signed only messages"
		response = spmp.genResponse(DEFAULT_CONTEXT,"SomeResponseTo",issuer,"SomeDestination","SomeConsent", extensions,ResponseStatusCodes.RESPONDER,"SomeStatusMessage", statusDetailType,[assertion1,assertion2], true, false);

		//printXML(response)
		xml = slurpXml(response)
		then:
		xml.Issuer == "SomeIssuer"
		xml.Signature.SignedInfo.size() == 0

		xml.Assertion[0].Signature.size() == 1
		xml.Assertion[1].Signature.size() == 1

		when: "Verify that is is parsable"
		r = spmp.parseMessage(DEFAULT_CONTEXT,response,false)

		then:
		r.signature == null
		samp.verifyAssertionSignature(DEFAULT_CONTEXT,r.getAssertionOrEncryptedAssertion()[0])
		samp.verifyAssertionSignature(DEFAULT_CONTEXT,r.getAssertionOrEncryptedAssertion()[1])

		when:
		((AssertionType) r.getAssertionOrEncryptedAssertion()[0]).issuer.value = "SomeChanged"
		samp.verifyAssertionSignature(DEFAULT_CONTEXT,r.getAssertionOrEncryptedAssertion()[0])
		then:
		thrown MessageContentException

	}


	def "Verify that extractAssertionsFromSAMLP extracts found Assertions from SAMLP Responses"(){
		when:
		List ass = spmp.extractAssertionsFromSAMLP(spmp.unmarshallDoc(samlpResponse))
		then:
		ass.size() == 1
		ass[0].getDocumentElement().getAttribute("ID") == "_58470139e557126f32744518cfd3e9eb"
		samp.xmlSigner.verifyEnvelopedSignature(null,ass[0],false)

	}

	def "Generate AuthNRequest with Principal Selection and verify that it is populated as and extenstion"(){
		when:
		MatchValueType matchValueType1 = pcsOf.createMatchValueType()
		matchValueType1.name = "urn:oid:1.2.752.29.4.13"
		matchValueType1.value = "198906059483"
		MatchValueType matchValueType2 = pcsOf.createMatchValueType()
		matchValueType2.name = "urn:oid:1.2.752.201.3.4"
		matchValueType2.value = "NO:05068907693"

		ExtensionsType extensions = samlpOf.createExtensionsType()
		extensions.any.add( new PrincipalSelectionGenerator().genPrincipalSelectionElement([matchValueType1,matchValueType2]))
		byte[] authNRequest = spmp.genAuthNRequest(DEFAULT_CONTEXT,"_1234512341234",null,null,null, null,null,null,null,null,null, null, extensions, null, null, null, null, null, true)

		def xml = slurpXml(authNRequest)
		//printXML(authNRequest)
		AuthnRequestType art = spmp.parseMessage(DEFAULT_CONTEXT,authNRequest, true)

		then:
		xml.@ID == "_1234512341234"
		xml.@IssueInstant.toString().startsWith("20")
		xml.@Version == "2.0"

		xml.Signature.SignedInfo.size() == 1

		xml.Extensions.PrincipalSelection.MatchValue.size() == 2
		xml.Extensions.PrincipalSelection.MatchValue[0].@Name == "urn:oid:1.2.752.29.4.13"
		xml.Extensions.PrincipalSelection.MatchValue[0] == "198906059483"
		xml.Extensions.PrincipalSelection.MatchValue[1].@Name == "urn:oid:1.2.752.201.3.4"
		xml.Extensions.PrincipalSelection.MatchValue[1] == "NO:05068907693"
	}


	def samlpResponse = """<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_58470139e557126f32744518cfd3e9eb" IssueInstant="2017-12-22T11:04:47.636Z" Version="2.0" xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"><saml2:Issuer>https://idp.test.signatureservices.eu/samlv2/idp/metadata</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" /><ds:Reference URI="#_58470139e557126f32744518cfd3e9eb"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs" /></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" /><ds:DigestValue>8A5d4T1WxRQMTu8d8vQxMdpW9Zaaq8zvbMayfE5QVBU=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>j3lALPjHTGqGFOOI8hGQmdVFiyLLROJX37imDWHAKSWGtXBqjj95Lj62TCbOt19utmfK4WeBVHgABAVXrVHCkTUlnGtA3b9FeCmT9kyF/qOgq/sPAIzk0gXMfo6wKup8zP5y8AV4m0qlZRMnPp8Zob/N6pMlNny+rVWd6NDhVggl76YddWwccOI9avqnlknAncEE5sSoEZyGIG0+4kCjoByD7OReWr7WBafe428145TU/PSJkHFCxbd5KzsOwGJ1wiAcbrHsCC5LD3idNnlKW95uNC0nhEXxK/QBPzLZa21+5m9NslPicEu+75fP/mMxKaU3RXQ6Z/lD5si1kDqGkw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIFEjCCAvqgAwIBAgIIIHBQF4emxZ4wDQYJKoZIhvcNAQELBQAwRDEUMBIGA1UEAwwLU2VydmVy
Q0EgdjIxLDAqBgNVBAoMI0xvZ2ljYSBTRSBJTSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlIEFUMB4XDTE2
MDUzMDA4Mjk1MFoXDTE4MDUzMDA4Mjk1MFowUzEjMCEGA1UEAwwaU2lnbmF0dXJlIFNlcnZpY2Ug
SURQIFRlc3QxLDAqBgNVBAoMI0xvZ2ljYSBTRSBJTSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlIEFUMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxrRKbpZujmTSbw/F6gfKRIjt0o5YagHfF2UG
NgjOMtDHPOFcsCsy7wR8y9hTbvxaiK0rA+YCCoOCIIUkZKCP3tJ7UJ0XDIep2WYelFJ1VBqET7AR
pzq0Yeo1Pn92YfIVXngIKuFJ3qvx6aEjWkoAym2mN3w1hEwwaaVGA7ZLUcgD1C9jSySruWQ5SnqJ
gdMd5IR5cZ4HP9NGKpWhn/x3SdTSnfuHnUdw5ljCjfTOEePdybC6iGGmvnliqHmrm4YWteS9vt/J
yXrnmT1z0RKPF3/5maNBbN5vhyfZxvYtZzwJ0V+loxpLeuGcY5juMQGo1UUk0tHsNkUNAnGB8+wF
JQIDAQABo4H4MIH1MB0GA1UdDgQWBBT+bJU/F1Lh+d/JHAXXEdKyM/2qUTAMBgNVHRMBAf8EAjAA
MFkGA1UdHwRSMFAwTqBMoEqGSGh0dHA6Ly9wdWJsaWMubGNzaW0uYXQuY2VydGlmaWNhdGVzZXJ2
aWNlcy5zZS9jcmwvbGNzX2ltX3NlcnZlcmNhX3YyLmNybDAfBgNVHSMEGDAWgBTNBNHOUSo+bz/7
8KWQEpJqDn+gajATBgNVHSUEDDAKBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCBaAwJQYDVR0RBB4w
HIIaU2lnbmF0dXJlIFNlcnZpY2UgSURQIFRlc3QwDQYJKoZIhvcNAQELBQADggIBAL7bpIEbEcnS
nBF6Qzyru20OJw9UCaTPI3wxtD5L813TlbZMademcRaekv+++RXVDtck/IdCLKMs7vCrU62OD0za
in7mYQA2IwTldqSlU91UCkwv/9SlOc0tfo5Ba35O4JWH6X/NKe7QCQG3WoxalXB/ZYG9aa5km5AF
17BvEZBDfRymnYk6PEGWbNLej0Gg090gOcwBbIx7qhFZjUVPmm67zOvZJKI01eHxoioNCl1SDM+X
2peV8Vn0ipmR0IaD8fUxzgi6l+Le7ETt3HyY8PM+OIKNmOJjoVL2QnuiGP0k2YIygYwO7vHmoGjh
jUJ/YG+OVXMBlIEP+xH93W+xre4qwCWFZkWjSaG/KQAmK0c9dc3iEQBIaxE6+1xxpvEkYlwswJTf
nhaGwyOcJBqUEZ2tSheKkua/etFIXf5j+Okkfrf+IUor7JHQzjft3+KG7iCqZ7GIzL04e6V8peRC
yF38iCjL2BsuYh/cr1HftarCOJuVyeQIZ1sd10z+OML1ESforb8hJK2iBjkVdB8hH26wsbsG3A89
2djrXrsMoOuP9OxgYF4jyhyVQsRT8h8sW6g/TTBJjB4rDnpCWt5jIFvltGHqCHnW5w8GyNEROOJm
BlTN2IusqVtkRE13OhJaQ/dTLyeyW7uqd5+u3KXaN7hSNhsNxAImagCOqmWA8ZVL</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_e68be53b2ec8b44a39743d3184065753</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="_27eabe37-ffbe-4d3d-8250-b271a133ab47" NotOnOrAfter="2017-12-22T23:19:47.636Z" Recipient="https://st-esign.signatureservice.se/mission/acs/d5be57d3c93344c0" /></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2017-12-22T10:49:47.636Z" NotOnOrAfter="2017-12-22T23:19:47.636Z"><saml2:AudienceRestriction><saml2:Audience>https://st-esign.signatureservice.se/metadata/d5be57d3c93344c0</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2017-12-22T11:04:47.636Z"><saml2:SubjectLocality Address="174.170.133.150" /><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement><saml2:AttributeStatement><saml2:Attribute Name="Subject_CountryName"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">LU</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="Gender"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">F</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="dateOfBirth"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">19480722</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="age"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">67</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="Issuer_CommonName"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Testbank A Customer CA1 v1 for BankID Test</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="Issuer_OrganizationName"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Testbank A AB (publ)</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="SecurityLevelDescription"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">SoftwarePKI</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="SecurityLevel"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">3</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="ValidationOcspResponse"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">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</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="sn_id"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">4807229242</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="sn_type"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">19</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="CertificateSerialNumber"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">896570c35bb16bb9</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="Subject_OrganisationName"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Testbank A AB (publ)</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="urn:oid:1.2.752.29.4.13" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">194807229242</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Denise</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="urn:oid:2.5.4.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Lee</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="urn:oid:2.16.840.1.113730.3.1.241" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Denise Lee</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement></saml2:Assertion>""".getBytes()
}
