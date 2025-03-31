package se.signatureservice.messages.saml2.assertion

import se.signatureservice.messages.ContextMessageSecurityProvider
import se.signatureservice.messages.SimpleMessageSecurityProvider
import se.signatureservice.messages.saml2.BaseSAMLMessageParser
import se.signatureservice.messages.saml2.CommonSAMLMessageParserSpecification
import se.signatureservice.messages.saml2.assertion.jaxb.AssertionType
import se.signatureservice.messages.saml2.protocol.SAMLProtocolMessageParser
import se.signatureservice.messages.saml2.protocol.jaxb.ResponseType
import se.signatureservice.messages.utils.SystemTime
import org.w3c.dom.Document


class SAMLAssertionMessageParserSpec extends CommonSAMLMessageParserSpecification {

	
	def "Verify that JAXBPackages(), getNameSpace(), getSignatureLocationFinder(), getDefaultSchemaLocations(), getOrganisationLookup() returns the correct values"(){
		expect:
		samp.getJAXBPackages() == SAMLAssertionMessageParser.BASE_JAXB_CONTEXT
		samp.getNameSpace() == BaseSAMLMessageParser.ASSERTION_NAMESPACE
		samp.getSignatureLocationFinder() == samp.assertionSignatureLocationFinder
		samp.getDefaultSchemaLocations().length== 4
		samp.getOrganisationLookup() == null
	}


	def "Verify that decryptEncryptedAssertion decrypts encrypted assertion properly"(){
		setup:
		ContextMessageSecurityProvider.Context context = ContextMessageSecurityProvider.DEFAULT_CONTEXT
		AssertionType assertion1JaxB = samp.parseMessage(context,assertion1,true)

		when:
		def encryptedAssertion = samp.genEncryptedAssertion(context,assertion1, [secProv.getDecryptionCertificate(null)],false)

		then:
		encryptedAssertion.value.encryptedData != null
		when:
		def decryptedAssertion = samp.decryptEncryptedAssertion(context,encryptedAssertion.value, true)
		then:
		decryptedAssertion.value.getID() == assertion1JaxB.getID()

	}

	def "Verify that decryptEncryptedAssertionToDoc decrypts a document and retains the signature"(){
		setup:

		SystemTime mockedSystemTime = Mock(SystemTime)
		mockedSystemTime.systemTime >> { simpleDateFormat.parse("2017-01-01")}
		mockedSystemTime.systemTimeMS >> { simpleDateFormat.parse("2017-01-01").time}

		Properties p = new Properties()
		p.load(new StringReader(provprops))
		SimpleMessageSecurityProvider prov = new SimpleMessageSecurityProvider(p)
		SAMLAssertionMessageParser samp = new SAMLAssertionMessageParser()
		samp.init(prov)
		samp.systemTime = mockedSystemTime
		samp.xmlSigner.systemTime = mockedSystemTime

		SAMLProtocolMessageParser spmp = new SAMLProtocolMessageParser()
		spmp.init(prov)
		spmp.systemTime = mockedSystemTime
		spmp.xmlSigner.systemTime = mockedSystemTime

		when:
		ResponseType resp = spmp.parseMessage(null,assertionEnc, false)

		Document doc = samp.decryptEncryptedAssertionToDoc(null,resp.getAssertionOrEncryptedAssertion()[0])
		then:
		doc.getDocumentElement().getElementsByTagNameNS(BaseSAMLMessageParser.ASSERTION_NAMESPACE, "Issuer").length > 0

		byte[] assertionData = samp.marshallDoc(doc)

		samp.xmlSigner.verifyEnvelopedSignature(null,assertionData,false)
	}

	// TODO Verify

    // generateSimpleAssertion is tested by AssertionPayloadParserSpec

	static String provprops = """
simplesecurityprovider.signingkeystore.path=src/test/resources/test.backend.signatureservice.se.jks
simplesecurityprovider.signingkeystore.password=foo123
simplesecurityprovider.signingkeystore.alias=test.backend.signatureservice.se
simplesecurityprovider.trustkeystore.path=src/test/resources/test.backend.signatureservice.se.truststore.jks
simplesecurityprovider.trustkeystore.password=foo123
"""

	static byte[] assertion1 = """<?xml version="1.0" encoding="UTF-8"?>
<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_07f34316c5d43fae293c108ae890316194" IssueInstant="2017-02-10T09:49:53.168Z" Version="2.0"><saml2:Issuer>https://m00-mg-local.idpst.funktionstjanster.se/samlv2/idp/metadata/6/8</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#_07f34316c5d43fae293c108ae890316194"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>bC3Fg9v3nWUcbSt5jBQeco+RnpwGpeW6GhWvIteuCPA=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>VTP94Ukih4Y4ZhO8L3TVnCHJNq/1bYIqnvwrHHMYSliG+8zjZ5Mv8+zURx2fSJQXyOr8QgNO4QjQgvov9mv7KBtyKznYnXQ0amA7gdivrBgGaRKEqyDG+s3ow7A2L0Y3mjXVaXggel0CjbWI1BwtiAOi1b5RrmddJ5OY3g6+hEq5y6FJ31WpGp+eW5abbJr57KWN4kptzh+vj3PvdGsS3KbqoFws7lez1F89QdpoSWCwxB4eyfxlULWXtAdtrVDKAl7DI/yWS6/sS6ZQ3YyYtvIlFX2GOAX5HxE3XDl3inY6txSTKGn2iLoGEO9GuOAH7qer26fDZ8wZNZETgTA7TQ==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIFDDCCA/SgAwIBAgISESF1HlPpLVNc8FXl3XKQmw8TMA0GCSqGSIb3DQEBCwUAMEwxCzAJBgNV
                        BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSIwIAYDVQQDExlBbHBoYVNTTCBDQSAt
                        IFNIQTI1NiAtIEcyMB4XDTE2MDUxMTE1NTk0MloXDTE5MDUxMjE1NTk0MlowSjEhMB8GA1UECxMY
                        RG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMSUwIwYDVQQDDBwqLmlkcHN0LmZ1bmt0aW9uc3RqYW5z
                        dGVyLnNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwB0Re+LHfYNloxNMdTjIFgX6
                        KMklQt1ZTI0bpAg+4g5s+xctNaXiYtlu9qEB/TDkP8d/DWY4wB6+q1xQoyxIVrqttsfB9Am/FwNE
                        1QCzjMRgRzGE6W+zZ9yY2xKHon5orW/LHIRR0Td4rm6w2dbq7zFqLMZ6fCsVWIKrsnn4TrubdUOf
                        zi6nk39AoElSeOgATUavS/q64zM6gMnF/9xsXLkcvc3vjjy9D1SUHhxbnP0XHix1U7HIT2xO0yuo
                        xG6o38oHN79nxBt7zB9XQJgpKoJ1FXC0fFLaXG4XrXyfMn2b2q5ZfZ0Jme8bkOtM+83k1RqRxYHX
                        5sN2qh72T+s7dwIDAQABo4IB6DCCAeQwDgYDVR0PAQH/BAQDAgWgMFcGA1UdIARQME4wQgYKKwYB
                        BAGgMgEKCjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0
                        b3J5LzAIBgZngQwBAgEwQwYDVR0RBDwwOoIcKi5pZHBzdC5mdW5rdGlvbnN0amFuc3Rlci5zZYIa
                        aWRwc3QuZnVua3Rpb25zdGphbnN0ZXIuc2UwCQYDVR0TBAIwADAdBgNVHSUEFjAUBggrBgEFBQcD
                        AQYIKwYBBQUHAwIwPgYDVR0fBDcwNTAzoDGgL4YtaHR0cDovL2NybDIuYWxwaGFzc2wuY29tL2dz
                        L2dzYWxwaGFzaGEyZzIuY3JsMIGJBggrBgEFBQcBAQR9MHswQgYIKwYBBQUHMAKGNmh0dHA6Ly9z
                        ZWN1cmUyLmFscGhhc3NsLmNvbS9jYWNlcnQvZ3NhbHBoYXNoYTJnMnIxLmNydDA1BggrBgEFBQcw
                        AYYpaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL2dzYWxwaGFzaGEyZzIwHQYDVR0OBBYEFGbT
                        MGqoTeCNLPjKx0OWk7jkC8ypMB8GA1UdIwQYMBaAFPXN1TwIUPlqTzq3l9pWg+Zp0mj3MA0GCSqG
                        SIb3DQEBCwUAA4IBAQB3YQJjlxAXiHTlrHCRfOI7ZY7znwACvgKXVK4i+veUG6QOpQDrXX2LwRuZ
                        fC9p6s7UK+mivdk/vPVeBtLzDVk3laQVEG9YgKtBqg0ceZKLmurAn4XDEzblc/YGejJSbNwRTedQ
                        kuEtWPIA3A2NpNlsdFA1lFRg9q8k688bfY1gtHLirw9/AzxlSPxzr7SMZsMA/DPbAduaA/WjXQhw
                        kxRBNGphzcPYT4/Wmey5gK00aJKgF4V2Eq37eY3Rm1Fqh2zpN1gCAFgbeaSa0V6+jB0Padt+YVcF
                        mlGfiAZYFqMbKOE2VoVuxVknAiPLQXUr/PgnQLAjrnZzLYxNEEkhieA6</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_07f84d05d65d647391c67ed7355c530c29</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData Address="85.119.130.112" InResponseTo="_8482c6de-90be-4fa2-b9b9-fa09f9906462" NotOnOrAfter="2017-02-10T09:54:53.168Z" Recipient="https://st-esign.signatureservice.se/mission/acs/ea696372b9fc461b"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2017-02-10T09:44:53.168Z" NotOnOrAfter="2017-02-10T09:54:53.168Z"><saml2:AudienceRestriction><saml2:Audience>https://st-esign.signatureservice.se/metadata/ea696372b9fc461b</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2017-02-10T09:49:53.168Z" SessionIndex="_075e42b47fb05f588ba1ed9f7dceae0c79"><saml2:SubjectLocality Address="85.119.130.112"/><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement><saml2:AttributeStatement xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><saml2:Attribute Name="Subject_CountryName"><saml2:AttributeValue xsi:type="xs:string">SE</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="urn:oid:1.3.6.1.5.5.7.9.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xsi:type="xs:string">M</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="urn:oid:1.3.6.1.5.5.7.9.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xsi:type="xs:string">19790515</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="age"><saml2:AttributeValue xsi:type="xs:string">38</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="Issuer_CommonName"><saml2:AttributeValue xsi:type="xs:string">Testbank A Customer CA3 v1 for BankID Test</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="Issuer_OrganizationName"><saml2:AttributeValue xsi:type="xs:string">Testbank A AB (publ)</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="SecurityLevelDescription"><saml2:AttributeValue xsi:type="xs:string">MobileTwofactorContract</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="SecurityLevel"><saml2:AttributeValue xsi:type="xs:string">3</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="ValidationOcspResponse"><saml2:AttributeValue xsi:type="xs:string">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</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="sn_id"><saml2:AttributeValue xsi:type="xs:string">7905155573</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="sn_type"><saml2:AttributeValue xsi:type="xs:string">19</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="CertificateSerialNumber"><saml2:AttributeValue xsi:type="xs:string">6990815854c47312</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="Subject_OrganisationName"><saml2:AttributeValue xsi:type="xs:string">Testbank A AB (publ)</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="urn:oid:1.2.752.29.4.13" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xsi:type="xs:string">197905155573</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xsi:type="xs:string">DANIEL</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="urn:oid:2.5.4.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xsi:type="xs:string">ERIKSSON</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="urn:oid:2.16.840.1.113730.3.1.241" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xsi:type="xs:string">DANIEL ERIKSSON</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="urn:oid:1.2.752.201.3.2" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xsi:type="xs:string">Js1T-T98S</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement></saml2:Assertion>""".replaceAll("\n","").getBytes("UTF-8")


	def assertionEnc = """<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response Destination="https://esign.v2.st.signatureservice.se/signservice-frontend/consumeassertion" ID="_8ef6a672f2ae65ecb5af8790783fc3ea" InResponseTo="_E667011B-A342-479B-b92F-83AA9BA74852" IssueInstant="2017-12-18T16:20:04.891Z" Version="2.0" xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.svelegtest.se/idp</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<ds:Reference URI="#_8ef6a672f2ae65ecb5af8790783fc3ea">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<ds:DigestValue>d2QAwscedBMI0zr72gcTDSOLMS5gyvdED89E77vnm5s=</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue>
CvEL0yzN3i4DCd2gtsI5eVmfxvn8ZvCDqtkdLShvpFoPIY35FjVR2kUkbR89pE1uvbhVidPY01vf
GZvdgjUapVp05S3iKWVDO0VE/Yks0ukjnW/xdsN5KQZy5tR+pHrUWRuJNkGTl3HcXkig6jJjERYq
Wx3U/XdpyomxiJecMFWNPrFtMkecDFWxHrlePhrteuqHp3ieHXQjXjh+jc7shuh+wTLk8LBdKHZh
iZI5/Hex+Cwz8D5PRIy8fQLrgJEMW2Lg/DazK+FrqQuHxccwSJk7A2V5CVmHnK0wFpK/xxLm32eU
YQe8b4k2R1Gk6XhIb2qQfMZNWG2R5UmMQBJyrg==
</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDJTCCAg2gAwIBAgIVANRzptVQS0OC4yUngEfPkeVZwu3rMA0GCSqGSIb3DQEBCwUAMBwxGjAY
BgNVBAMMEWlkcC5zdmVsZWd0ZXN0LnNlMB4XDTE2MDkxMDEwMTcwNVoXDTM2MDkxMDEwMTcwNVow
HDEaMBgGA1UEAwwRaWRwLnN2ZWxlZ3Rlc3Quc2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCG8EktfnRi2LRB3UTwUXMni/eM2Dco4RA/RljvxP2Z9MdjrqO1FZJV2X2ACIKVvUVxQ7vR
JqSddzs5IO8bwJ5FORoH/zl/hxLXBnMkhPLbiXXTNgMvQBNJXVvMlwPvNKBP54zakEV1t7or+uUP
m4AHZV/g+18Y73rTz10prjmdlywm0rLKhsWcqT7vFVNOrf0b7TUw3DtjMz5fQVt9rLoQJV0RUak4
KQHSlJEnHaPWSMgtZ2fylVfBtMyIp1Q8WQ1D1j3BtW1u7lv017Ji35nSGRWWSDCL/t7aLxNvfTP9
nM4y7YHGA7nvpWzeruMc4Z24eEe717zf1syw43qvtLw7AgMBAAGjXjBcMB0GA1UdDgQWBBR9sg6F
+KfYjCaJx4mVHUvdbUbC+jA7BgNVHREENDAyghFpZHAuc3ZlbGVndGVzdC5zZYYdaHR0cHM6Ly9p
ZHAuc3ZlbGVndGVzdC5zZS9pZHAwDQYJKoZIhvcNAQELBQADggEBADh81fersDrGsoretj8NzRn7
Ff7/XE2h35ctMGDUFFttmvO1M2wO3iL412JFWVeXMrq4wHsvOnKFGVdnt1AkYRqFrUOkOA4YPduA
/dguhVzid4399+a5rwpo+zanEMGw56Z2qnHomwOtUldYFiqeQHnDtviQjPUObW1J0MWMg46lGOUf
M9z8blI7JWkwzcRsk8HkwqbMUgFVe4TH5Mftozo/hza6CZBqqRY+6yFx4ORIDoYZWPcSYKlO2Gcn
pBK5s0X2wv4UktpIs8GAUa36e9qN7H2Uno+/UH+c5J4Ng5VumMQmTVOm0fG+I0u33tjOY4S/UVX0
/ir/froXp1O3l/w=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status><saml2:EncryptedAssertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><xenc:EncryptedData Id="_7fd6ca24d483eae4de74bb163c15ffbc" Type="http://www.w3.org/2001/04/xmlenc#Element" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey Id="_072fdce76400abfae5469bad911fce72" Recipient="https://esign.v2.st.signatureservice.se/signservice-frontend/metadata/4321a583928" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/></xenc:EncryptionMethod><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDtTCCAp2gAwIBAgIIQIAaGoHvZG0wDQYJKoZIhvcNAQEFBQAwZTE1MDMGA1UEAwwsTG9naWNh
IFNFIElNIENlcnRpZmljYXRlIFNlcnZpY2UgU1QgU2VydmVyQ0ExLDAqBgNVBAoMI0xvZ2ljYSBT
RSBJTSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlIFNUMB4XDTE3MDcxMjExMDcwMloXDTE5MDcxMTExMDcw
MlowWTEpMCcGA1UEAwwgdGVzdC5iYWNrZW5kLnNpZ25hdHVyZXNlcnZpY2Uuc2UxLDAqBgNVBAoM
I0xvZ2ljYSBTRSBJTSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlIFNUMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAhLoCPpDifhnsbiR27W1tJ4SFrjHvhfe8GVlQC6F7pps5x7LsRj4XZvcpIQ+o
7qaFD7mMxMb4qPEH/n8sUsbPt12ByRgarXFOI9S6XyB0il6TGuODXvIXGeUhZHcRUdgB/nbGgZrb
oPIMXU5IXJAcm6/K4CJwr0s1Ix/vGy/QgjJ1Dl9obxSJ1Lh5tnUJxd5/2XQod+6up5XAtieLwfUR
JSj3gF6dKNp/cMhwVkPtDM2PA+zdayil+PUsvKiZQxBny/K7obmALCuTqDmQkE2WvLGdezooBQjp
CeWUSweq+8IVDgrkLkrIGFM2ERmGYnnFG/E0Iv4l+ye9SGMGGfnMRwIDAQABo3UwczAMBgNVHRMB
Af8EAjAAMB8GA1UdIwQYMBaAFOBD1HKL2rBlAoaehRcftgg2gElPMBMGA1UdJQQMMAoGCCsGAQUF
BwMBMB0GA1UdDgQWBBQ1p+7jFbgGWSTPUFU7TmukAROfDDAOBgNVHQ8BAf8EBAMCBaAwDQYJKoZI
hvcNAQEFBQADggEBAFVOWWhnXDGglSp5jxuhxEftfYp8ZK/qnpmY6Dkgix2qZL2KFpzxd3CF1HHA
IFyw+X9bVZHemIeEjtHttinkzsOPBkAYA2FYgWSBy4Wc8ucxoguxnNrVGRBv20CX6jIfOCeAZGi0
oTrj4OvBwbLvNgh35BwAHl99rPIJOnH7SogrGNGYYHaCxEjEDYB2uOZ/0z17MHdZ1aPpgR/6z+kZ
UQ0mjskkGAXtB+eV9XZWiEf4DcQWCNkpeYW9H3dI9nsxCbxUuH5dJMsWtpzADQYScIMh0dlFTxeQ
tXiZAHBV81NZPvVE8wUr2cX+V46RBvi9fqFV7ysx12Pzc6qjVU2C1Ok=</ds:X509Certificate></ds:X509Data></ds:KeyInfo><xenc:CipherData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"><xenc:CipherValue>AJJ9OuMYVLZ5T3n8h/cWQx/yw4D+nmn6hqpK72QSa/zfqMKSduOtFVrJqwIBOXBxV3mBhNXriw10
4xEmV5HfP36cjPetIAFjCuziD/IilZp6HZ6dHg875hfWb4YnKOwXNv/l1zSaFvIfmo1piCKxEYzU
kfRvHzvBZVxuS4jhzdc85fibUCiKz1fGXHbyZ1MbxRlqQePlf7QQId8/JV6Y432NjHgxfkm2Dizy
jiRUI5JVU77Yn3JeBWjWbJuSmAt3n8RJNZpf8fcwUwDwU/AdOKZqPLxRx6eKPy6j3ORoALZee1lS
Ludk0TNpopIMDWGOTlymzNReeYhABoykt3Jx0Q==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"><xenc:CipherValue>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
B/na6fp83eES</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml2:EncryptedAssertion></saml2p:Response>""".getBytes("UTF-8")

}
