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
package org.signatureservice.messages.utils

import org.apache.xml.security.Init
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Base64
import org.signatureservice.messages.ContextMessageSecurityProvider
import org.signatureservice.messages.DummyMessageSecurityProvider
import org.signatureservice.messages.HSMMessageSecurityProvider
import org.signatureservice.messages.MessageContentException
import org.signatureservice.messages.MessageProcessingException
import org.signatureservice.messages.MessageSecurityProvider
import org.signatureservice.messages.SigningAlgorithmScheme
import org.signatureservice.messages.TestUtils
import org.signatureservice.messages.assertion.AssertionPayloadParser
import org.signatureservice.messages.csmessages.CSMessageParser
import org.signatureservice.messages.csmessages.DefaultCSMessageParser
import org.signatureservice.messages.csmessages.jaxb.CSMessage
import org.signatureservice.messages.saml2.assertion.jaxb.ObjectFactory
import org.signatureservice.messages.csmessages.CSMessageParserManager
import org.signatureservice.messages.csmessages.PayloadParserRegistry
import org.w3c.dom.Document
import org.w3c.dom.Element
import spock.lang.Specification
import spock.lang.Unroll

import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec

import static org.signatureservice.messages.TestUtils.*

class XMLSignerSpec extends Specification {
	
	ObjectFactory of = new ObjectFactory()
	AssertionPayloadParser assertionPayloadParser
	XMLSigner xmlSigner
	XMLSigner csXMLSigner
	
	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Init.init()
	}


	def setup(){
		setupRegisteredPayloadParser();
		assertionPayloadParser = PayloadParserRegistry.getParser(AssertionPayloadParser.NAMESPACE);

		xmlSigner = assertionPayloadParser.xmlSigner
		csXMLSigner = new XMLSigner(
				CSMessageParserManager.getCSMessageParser().messageSecurityProvider,
				true,
				CSMessageParserManager.getCSMessageParser().cSMessageSignatureLocationFinder as XMLSigner.SignatureLocationFinder,
				new CSMessageOrganisationLookup()
		)
	}

	/*
	 * marshallAndSignAssertion() is tested through DefaultCSMessageParser and AssertionPayloadParser
	 */
	
	def "Verify that verifyEnvelopedSignature verifies a valid message"(){
		when:
		xmlSigner.verifyEnvelopedSignature(validSignatureSAMLP)
		then:
		true
	}

	def "Verify that verifyEnvelopedSignature verifies that no signure in signed element throws MessageContentException"(){
		when:
		xmlSigner.verifyEnvelopedSignature(sAMLPWithNoSignature)
		then:
		thrown MessageContentException
	}
	

	def "Verify that verifyEnvelopedSignature checks certificate auth authorization if flag set to true"(){
		when:
		csXMLSigner.verifyEnvelopedSignature(validCSMessage, true)
		then:
		true
	}
	
	def "Verify that certificate is found in CSMessage and SAMLP response"(){
		expect:
		csXMLSigner.findSignerCertificate(validCSMessage) instanceof X509Certificate
		xmlSigner.findSignerCertificate(validSignatureSAMLP) instanceof X509Certificate
		
		when: "Verify that message content exception is thrown if no signature could be found"
		xmlSigner.findSignerCertificate(sAMLPWithNoSignature)
		then:
		thrown MessageContentException
	}

	def "Check that checkValidTransform accepts enveloped transform"(){
		when:
		xmlSigner.checkValidTransform(findSignature(validSignatureSAMLP))
		then:
		true
	}
	
	def "Check that checkValidTransform throws MessageContentException if not enveloped"(){
		when:
		xmlSigner.checkValidTransform(findSignature(invalidTransformSAMLP))
		then:
		thrown MessageContentException
	}
	
	@Unroll
	def "Check that checkValidDigestURI only accepts supported algorithm: #signScheme"(){
		setup:
		String message = new String(validSignatureSAMLP,"UTF-8").replace("http://www.w3.org/2001/04/xmlenc#sha256", signScheme.getHashAlgorithmURI())
		when:
		xmlSigner.checkValidDigestURI(findSignature(message.getBytes("UTF-8")))
		then:
		true
		where:
		signScheme << SigningAlgorithmScheme.values()
	}
	
	def "Check that checkValidDigestURI throws MessageContentException for invalid URI"(){
		setup:
		String message = new String(validSignatureSAMLP,"UTF-8").replace("http://www.w3.org/2001/04/xmlenc#sha256", "invalid")
		when:
		xmlSigner.checkValidDigestURI(findSignature(message.getBytes("UTF-8")))
		then:
		thrown MessageContentException
	}
	
	@Unroll
	def "Check that checkValidSignatureURI only accepts supported algorithm: #signScheme"(){
		setup:
		String message = new String(validSignatureSAMLP,"UTF-8").replace("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", signScheme.getSignatureAlgorithmURI())
		when:
		xmlSigner.checkValidSignatureURI(findSignature(message.getBytes("UTF-8")))
		then:
		true
		where:
		signScheme << SigningAlgorithmScheme.values()
	}
	
	def "Check that checkValidSignatureURI throws MessageContentException for invalid URI"(){
		setup:
		String message = new String(validSignatureSAMLP,"UTF-8").replace("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "invalid")
		when:
		xmlSigner.checkValidSignatureURI(findSignature(message.getBytes("UTF-8")))
		then:
		thrown MessageContentException
	}
	
	def "Verify that checkValidReferenceURI checks that the correct URI is referenced and throws MessageContentException otherwise"(){
		setup:
		Document doc = xmlSigner.documentBuilder.parse(new ByteArrayInputStream(validSignatureSAMLP))
		Element assertion = doc.getElementsByTagNameNS(AssertionPayloadParser.NAMESPACE, "Assertion").item(0)
		Element signature = doc.getElementsByTagNameNS(XMLSigner.XMLDSIG_NAMESPACE, "Signature").item(0)
		when:
		xmlSigner.checkValidReferenceURI(assertion, signature, "ID")
		then:
		true
		when:
		assertion.setAttribute("ID","invalid")
		xmlSigner.checkValidReferenceURI(assertion, signature, "ID")
		then:
		thrown MessageContentException
	}
	
	
	def "Verify CSMessageOrgansiationLookup.findOrganisation() finds organisation value in a CSMessage"(){
		setup:
		Document doc = xmlSigner.documentBuilder.parse(new ByteArrayInputStream(validCSMessage))
		expect:
		xmlSigner.defaultOrganisationLookup.findOrganisation(doc) == "someorg"
	}
	
	def "Verify CSMessageOrgansiationLookup.findOrganisation() throws MessageContentException for messages that doesnt contain organisation element."(){
		setup:
		Document doc = xmlSigner.documentBuilder.parse(new ByteArrayInputStream(validSignatureSAMLP))
		when:
		xmlSigner.defaultOrganisationLookup.findOrganisation(doc)
		then:
		thrown MessageContentException	
	}

	def "Verify marshallDoc() converts a Doc to a string"(){
		setup:
		Document doc = xmlSigner.documentBuilder.parse(new ByteArrayInputStream(validSignatureSAMLP))
		when:
		def result = xmlSigner.marshallDoc(doc)
		then:
		new String(result,"UTF-8").replaceAll("\n","").replaceAll("\r","") == new String(validSignatureSAMLP,"UTF-8").replaceAll("\n","").replaceAll("\r","")
	}

	def "Verify that checkBasicCertificateValidation checks time validity of a certficate."(){
		setup:
		X509Certificate cert = xmlSigner.messageSecurityProvider.getSigningCertificate();
		when: "Verify that true is returned for valid certificate"
		XMLSigner.systemTime = TestUtils.mockSystemTime("2013-10-01")
		then:
		XMLSigner.checkBasicCertificateValidation(cert) == true
		when: "Verify that false is returned for expired certificate"
		XMLSigner.systemTime = TestUtils.mockSystemTime("2017-10-01")
		then:
		XMLSigner.checkBasicCertificateValidation(cert) == false
		when: "Verify that false is returned for yet valid certificate"
		XMLSigner.systemTime = TestUtils.mockSystemTime("2001-10-01")
		then:
		XMLSigner.checkBasicCertificateValidation(cert) == false

	}


	def "Verify that correct method is used if message security provider is ContextMessageSecurityProvider"(){
		setup:
		ContextMessageSecurityProvider.Context c = new ContextMessageSecurityProvider.Context("SomeUsage")
		ContextMessageSecurityProvider securityProvider = Mock(ContextMessageSecurityProvider)
		when:

		XMLSigner x = new XMLSigner(securityProvider, true,
				xmlSigner.defaultSignatureLocationFinder,
				xmlSigner.defaultOrganisationLookup)
		x.verifyEnvelopedSignature(c,validSignatureSAMLP)
		then:
		1 * securityProvider.isValidAndAuthorized(c,!null,_) >> true

		when:
		Document doc = xmlSigner.documentBuilder.parse(new ByteArrayInputStream(sAMLPWithNoSignature))
		x.sign(c,doc, xmlSigner.defaultSignatureLocationFinder)
		then:
		1 * securityProvider.getSigningAlgorithmScheme(c) >> SigningAlgorithmScheme.RSAWithSHA256
		1 * securityProvider.getSigningCertificate(c) >> xmlSigner.messageSecurityProvider.getSigningCertificate()
		1 * securityProvider.getSigningKey(c) >> xmlSigner.messageSecurityProvider.getSigningKey()
		1 * securityProvider.getProvider(_) >> "BC"

	}

	def "Verify that correct method is used if message security provider is MessageSecurityProvider"(){
		setup:
		MessageSecurityProvider securityProvider = Mock(MessageSecurityProvider)
		when:

		XMLSigner x = new XMLSigner(securityProvider, true,
				xmlSigner.defaultSignatureLocationFinder,
				xmlSigner.defaultOrganisationLookup)
		x.verifyEnvelopedSignature(validSignatureSAMLP)
		then:
		1 * securityProvider.isValidAndAuthorized(!null,_) >> true

		when:
		Document doc = xmlSigner.documentBuilder.parse(new ByteArrayInputStream(sAMLPWithNoSignature))
		x.sign(doc, xmlSigner.defaultSignatureLocationFinder)
		then:
		1 * securityProvider.getSigningAlgorithmScheme() >> SigningAlgorithmScheme.RSAWithSHA256
		1 * securityProvider.getSigningCertificate() >> xmlSigner.messageSecurityProvider.getSigningCertificate()
		1 * securityProvider.getSigningKey() >> xmlSigner.messageSecurityProvider.getSigningKey()
		1 * securityProvider.getProvider() >> "BC"

	}

	def "Verify that deprecated XMLSigner works for backward compatibility"(){
		setup:
		ContextMessageSecurityProvider.Context c = new ContextMessageSecurityProvider.Context("SomeUsage")
		ContextMessageSecurityProvider securityProvider = Mock(ContextMessageSecurityProvider)
		when:

		XMLSigner x = new XMLSigner(securityProvider, assertionPayloadParser.getDocumentBuilder(), true,
				xmlSigner.defaultSignatureLocationFinder,
				xmlSigner.defaultOrganisationLookup)
		x.verifyEnvelopedSignature(c,validSignatureSAMLP)
		then:
		1 * securityProvider.isValidAndAuthorized(c,!null,_) >> true

		when:
		Document doc = xmlSigner.documentBuilder.parse(new ByteArrayInputStream(sAMLPWithNoSignature))
		x.sign(c,doc, xmlSigner.defaultSignatureLocationFinder)
		then:
		1 * securityProvider.getSigningAlgorithmScheme(c) >> SigningAlgorithmScheme.RSAWithSHA256
		1 * securityProvider.getSigningCertificate(c) >> xmlSigner.messageSecurityProvider.getSigningCertificate()
		1 * securityProvider.getSigningKey(c) >> xmlSigner.messageSecurityProvider.getSigningKey()

	}

	def "Verify that getProvider is called if message security provider is HSMMessageSecurityProvider"(){
		setup:
		MessageSecurityProvider securityProvider = Mock(HSMMessageSecurityProvider)
		when:

		XMLSigner x = new XMLSigner(securityProvider, true,
				xmlSigner.defaultSignatureLocationFinder,
				xmlSigner.defaultOrganisationLookup)
		Document doc = xmlSigner.documentBuilder.parse(new ByteArrayInputStream(sAMLPWithNoSignature))
		x.sign(null, doc, xmlSigner.defaultSignatureLocationFinder)
		then:
		1 * securityProvider.getSigningAlgorithmScheme(_) >> SigningAlgorithmScheme.RSAWithSHA256
		1 * securityProvider.getSigningCertificate(_) >> xmlSigner.messageSecurityProvider.getSigningCertificate()
		1 * securityProvider.getSigningKey(_) >> xmlSigner.messageSecurityProvider.getSigningKey()
		1 * securityProvider.getProvider(_) >> "BC"
	}

	@Unroll
	def "Verify that signing and verification of sign algorithm #signAlg is supported"(){
		setup:
		useAlgorithm(signAlg)
		CSMessageParser p = CSMessageParserManager.getCSMessageParser()
		when:
		byte[] msgData = p.generateIsApprovedRequest(MessageGenerateUtils.generateRandomUUID(),"someDest","SomeOrg","SomeApprovalId", null,null)
		CSMessage msg = p.parseMessage(msgData)
		then:
		msg.signature.signedInfo.signatureMethod.algorithm == signAlg.signatureAlgorithmURI

		cleanup:
		resetAlgorithm()

		where:
		signAlg << SigningAlgorithmScheme.values()


	}

	def "Verify that parsing messages is thread safe"(){
		setup:
		Exception exception
		List<Thread> threads = []
		ContextMessageSecurityProvider.Context context = new ContextMessageSecurityProvider.Context("SomeUsage")

		when:
		for(int i=0;i<10;i++){
			threads.add(Thread.start {
				try {
					for (int j = 0; j < 1000; j++) {
						csXMLSigner.findSignerCertificate(validCSMessage)
						xmlSigner.verifyEnvelopedSignature(context, validSignatureSAMLP)
					}
				} catch(Exception e){
					exception = e
				}
			})
		}
		threads.each {
			it.join()
		}

		then:
		exception == null
	}

	private void useAlgorithm(SigningAlgorithmScheme algo){
		ContextMessageSecurityProvider secProv = new TestAlgoMessageSecurityProvider(algo)
		DefaultCSMessageParser parser = CSMessageParserManager.getCSMessageParser()
		parser.securityProvider = secProv
		parser.xmlSigner.messageSecurityProvider = secProv
		xmlSigner.messageSecurityProvider = secProv
	}

	private void resetAlgorithm(){
		ContextMessageSecurityProvider secProv = new DummyMessageSecurityProvider()
		DefaultCSMessageParser parser = CSMessageParserManager.getCSMessageParser()
		parser.securityProvider = secProv
		parser.xmlSigner.messageSecurityProvider = secProv
		xmlSigner.messageSecurityProvider = secProv
	}

	private class TestAlgoMessageSecurityProvider extends DummyMessageSecurityProvider{

		SigningAlgorithmScheme signAlg
		TestAlgoMessageSecurityProvider(SigningAlgorithmScheme signAlg){
			this.signAlg = signAlg
		}

		@Override
		PrivateKey getSigningKey(ContextMessageSecurityProvider.Context context) throws MessageProcessingException {
			if(signAlg.name().contains("ECDSA")) {
				PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.decode(ecKey))
				KeyFactory factory = KeyFactory.getInstance("ECDSA")
				PrivateKey privateKey = factory.generatePrivate(spec)
				return privateKey
			}
			super.getSigningKey(context)
		}

		@Override
		X509Certificate getSigningCertificate(ContextMessageSecurityProvider.Context context) throws MessageProcessingException {
			if(signAlg.name().contains("EC")) {
				CertificateFactory cf = CertificateFactory.getInstance("X509")
				return cf.generateCertificate(new ByteArrayInputStream(Base64.decode(ecCert)))
			}
			super.getSigningCertificate(context)
		}

		@Override
		SigningAlgorithmScheme getSigningAlgorithmScheme(ContextMessageSecurityProvider.Context context) throws MessageProcessingException {
			return signAlg
		}

		@Override
		boolean isValidAndAuthorized(ContextMessageSecurityProvider.Context context, X509Certificate signCertificate, String organisation) throws IllegalArgumentException, MessageProcessingException {
			return true
		}

	}

	private Element findSignature(byte[] message){
		return xmlSigner.documentBuilder.parse(new ByteArrayInputStream(message)).getElementsByTagNameNS(XMLSigner.XMLDSIG_NAMESPACE, "Signature").item(0)
	}
	
	def validSignatureSAMLP = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" ID="_34DCC381-5BD5-4035-b71B-B1552F8578CD" InResponseTo="_123456789" IssueInstant="2015-07-07T16:28:32.427+02:00" Version="2.0"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_CCA83D00-6FE6-4B80-8D20-9B3693068AB3" IssueInstant="2015-07-07T16:28:32.427+02:00" Version="2.0"><saml:Issuer>someIssuer</saml:Issuer><ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_CCA83D00-6FE6-4B80-8D20-9B3693068AB3"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>oMziNyNGdPLo6VLwp7OnGaAzFdvZBPiddubCJE7C/9c=</DigestValue></Reference></SignedInfo><SignatureValue>aRIwgOB7KPEhyiD4s+s340eM/XVFEfD38unhnaAWHspNzm7bCwW58XbU4nhtFH+DXQRiWVcUBqfC
rKHgu+mYAAuJGHZjgaEIa2ewv8xjQ44oc921ILItwIMBKgJnkkuU58FWlI/W1GXlHhXIe4ASZoct
qBWaNSI10ZhB6tzxQCiuQtFgfTt0SdOI5TUEjv30OkBZO5kg03s8iqc3by54p+2CqP3ExB4C2lf8
C28+WTb61Ytt8RylFW6xq71VuIHni9s9bJD7rivO9+YmL9N02/M8naWV28nvwt/OQlNWD/wYjujx
zbMCtIlDbFH6L+YdBk3KORicWwv1ZQ+/KrXK0A==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
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
ZLCP64EJEfE1mGxCJg==</X509Certificate></X509Data></KeyInfo></ds:Signature><saml:Subject><saml:NameID>SomeSubject</saml:NameID></saml:Subject><saml:Conditions NotBefore="2015-07-07T16:26:52.427+02:00" NotOnOrAfter="2015-07-07T16:28:32.427+02:00"/><saml:AttributeStatement><saml:EncryptedAttribute><xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/><ds:KeyInfo>
<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><ds:KeyInfo>
<ds:KeyName>A2a5JrfZL6oHCSexVqT9GyeV66QaYYY1YbqU+/eDkyc=</ds:KeyName>
</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>OsmJo/KXd/D/Tm4A8pTiqmsxPcdUkEZ0JwJAl5ITMzFy/hnghr9eX0wZYW7a+74iD9CJvZLQsmrvD61G4GLlu8iLYX+A57JKhxmLdhHEANHKFxh7/VkaHvH5bL/yfvD+1jPqaGmwYKr7eIf/wcWJeDWh/eqoGHNHrwdWWalkxyWJjImUt0tLuLKjKqmgqvC0ZG7D43bkZDbq+HPCKdfEzpAA1C/SH/d7wel32WlPI4cy6fO8wTLcA/FeIuw4ZYfhcLFwxurXm9N3ROAZgu7bMofm43/TkVtchAFbkU3Fj/Eqa0b5Yvoi50TuML/qgVwfkpce28dppzj4zujm4spSfA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><ds:KeyInfo>
<ds:KeyName>yrhA2ngreu9CwRBvbfKReRFRmZk/GB50/vT6IhgT8no=</ds:KeyName>
</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>g72vCUTVQB37dBwBavo+NvRklzRNkRh1H/d7lhKBhZJxbsFeMv2jZn0IAwNgkypfEDCcuQvNvIRzomAX3qeY+n+aX9Pis9vL1YXeLIUZSzOgJxkp94E1qTUiYo0IUg3ww3OgtTSE5zo6ZWjO0KHiv0LIL/KCT/LkjVMDw+c7oWV+/iA2CYnpq1EkpWrJcNOknxEYTKN0KVfg/2ntnp2GrDAZBXqpjK+iTt0qIHq0Dd7BUACPsgTgt9G6kmp87p9OTSqBb6llcalxOs+vbQ5NEvl7UbJF5q9saxu6ADy9oPJPIgrT5QEg37cD82FRjX2Ty8PBQJc2HriwI3loXn5taw==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>N/J+2evaoEXGQSEhR0P47FNSrBDYuoUI+Q3zrjhluEtxDWQGxTVI6CP7OBEGOCSbmQlUJ49QkCx418vXmoVjOY5Y3b3mJUO+86lSL8f+uZRmPs76JcFdf7uOme3tu6rhSsLh9JpklqnQSLBWqqydkbpHPM5LqkDOKDMXEmHpe6QfzpU1FXWUAqQuwXwZ8ceReJKNpp1RNxM1L/+EWDGeH+8pKLTG375f6UXCHy3u/sDYrDlXS7w6jeZ7LIs9NAWayDA1Aiqm0Y7h9jD8iC7ynPDapCwkd7u7psInpP2dqUz0Zxf3mJSZUvrsE+HblgdWw5RiaBlzsT7tIHpPA/3bnZuO9Oa4jGRnTFjOcTxW1/wN8UO2Lu96gtHCdgi/2+LJFCy3LS9uZUMTQDClAUrvfTWXzj3Xcrp3ph4FF6gzz+FufkMJbPmDv/fGK/6t4xVgRlZlV/+FSo6jFEexYaEch3KfZXLOyHSz/0WXONDlhINEr2zRmUZzCoQdey+v6tbXnVdrmyZxjM3i8tBpuEwkX6jDHWUekC8ljKDYs5zCW96YWLmpA9gt/Wa+VoETAlormkEK2+3dsXDsfu+mca4MhSDtCarzRoV0JtN02JK7FJm+oZhWLXsfy0R6XmmVwHgktnGQ1/Km+3y426WKANTEuczqZ/ZgXWBxGMj5g8kGzVHyCpJYR+3dGdSyErUvHvyvlXGuEuVyKAv9/AZVz3QFVHjvD71TH1le+eFvkRjXcjJuMAHyEJ8p3AT6HyPxRPOLQERd+shfkvYG3bA/VYk34Q==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAttribute></saml:AttributeStatement></saml:Assertion></samlp:Response>""".getBytes("UTF-8")

def invalidTransformSAMLP = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" ID="_34DCC381-5BD5-4035-b71B-B1552F8578CD" InResponseTo="_123456789" IssueInstant="2015-07-07T16:28:32.427+02:00" Version="2.0"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_CCA83D00-6FE6-4B80-8D20-9B3693068AB3" IssueInstant="2015-07-07T16:28:32.427+02:00" Version="2.0"><saml:Issuer>someIssuer</saml:Issuer><ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_CCA83D00-6FE6-4B80-8D20-9B3693068AB3"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#other-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>oMziNyNGdPLo6VLwp7OnGaAzFdvZBPiddubCJE7C/9c=</DigestValue></Reference></SignedInfo><SignatureValue>aRIwgOB7KPEhyiD4s+s340eM/XVFEfD38unhnaAWHspNzm7bCwW58XbU4nhtFH+DXQRiWVcUBqfC
rKHgu+mYAAuJGHZjgaEIa2ewv8xjQ44oc921ILItwIMBKgJnkkuU58FWlI/W1GXlHhXIe4ASZoct
qBWaNSI10ZhB6tzxQCiuQtFgfTt0SdOI5TUEjv30OkBZO5kg03s8iqc3by54p+2CqP3ExB4C2lf8
C28+WTb61Ytt8RylFW6xq71VuIHni9s9bJD7rivO9+YmL9N02/M8naWV28nvwt/OQlNWD/wYjujx
zbMCtIlDbFH6L+YdBk3KORicWwv1ZQ+/KrXK0A==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
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
ZLCP64EJEfE1mGxCJg==</X509Certificate></X509Data></KeyInfo></ds:Signature><saml:Subject><saml:NameID>SomeSubject</saml:NameID></saml:Subject><saml:Conditions NotBefore="2015-07-07T16:26:52.427+02:00" NotOnOrAfter="2015-07-07T16:28:32.427+02:00"/><saml:AttributeStatement><saml:EncryptedAttribute><xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/><ds:KeyInfo>
<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><ds:KeyInfo>
<ds:KeyName>A2a5JrfZL6oHCSexVqT9GyeV66QaYYY1YbqU+/eDkyc=</ds:KeyName>
</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>OsmJo/KXd/D/Tm4A8pTiqmsxPcdUkEZ0JwJAl5ITMzFy/hnghr9eX0wZYW7a+74iD9CJvZLQsmrvD61G4GLlu8iLYX+A57JKhxmLdhHEANHKFxh7/VkaHvH5bL/yfvD+1jPqaGmwYKr7eIf/wcWJeDWh/eqoGHNHrwdWWalkxyWJjImUt0tLuLKjKqmgqvC0ZG7D43bkZDbq+HPCKdfEzpAA1C/SH/d7wel32WlPI4cy6fO8wTLcA/FeIuw4ZYfhcLFwxurXm9N3ROAZgu7bMofm43/TkVtchAFbkU3Fj/Eqa0b5Yvoi50TuML/qgVwfkpce28dppzj4zujm4spSfA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><ds:KeyInfo>
<ds:KeyName>yrhA2ngreu9CwRBvbfKReRFRmZk/GB50/vT6IhgT8no=</ds:KeyName>
</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>g72vCUTVQB37dBwBavo+NvRklzRNkRh1H/d7lhKBhZJxbsFeMv2jZn0IAwNgkypfEDCcuQvNvIRzomAX3qeY+n+aX9Pis9vL1YXeLIUZSzOgJxkp94E1qTUiYo0IUg3ww3OgtTSE5zo6ZWjO0KHiv0LIL/KCT/LkjVMDw+c7oWV+/iA2CYnpq1EkpWrJcNOknxEYTKN0KVfg/2ntnp2GrDAZBXqpjK+iTt0qIHq0Dd7BUACPsgTgt9G6kmp87p9OTSqBb6llcalxOs+vbQ5NEvl7UbJF5q9saxu6ADy9oPJPIgrT5QEg37cD82FRjX2Ty8PBQJc2HriwI3loXn5taw==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>N/J+2evaoEXGQSEhR0P47FNSrBDYuoUI+Q3zrjhluEtxDWQGxTVI6CP7OBEGOCSbmQlUJ49QkCx418vXmoVjOY5Y3b3mJUO+86lSL8f+uZRmPs76JcFdf7uOme3tu6rhSsLh9JpklqnQSLBWqqydkbpHPM5LqkDOKDMXEmHpe6QfzpU1FXWUAqQuwXwZ8ceReJKNpp1RNxM1L/+EWDGeH+8pKLTG375f6UXCHy3u/sDYrDlXS7w6jeZ7LIs9NAWayDA1Aiqm0Y7h9jD8iC7ynPDapCwkd7u7psInpP2dqUz0Zxf3mJSZUvrsE+HblgdWw5RiaBlzsT7tIHpPA/3bnZuO9Oa4jGRnTFjOcTxW1/wN8UO2Lu96gtHCdgi/2+LJFCy3LS9uZUMTQDClAUrvfTWXzj3Xcrp3ph4FF6gzz+FufkMJbPmDv/fGK/6t4xVgRlZlV/+FSo6jFEexYaEch3KfZXLOyHSz/0WXONDlhINEr2zRmUZzCoQdey+v6tbXnVdrmyZxjM3i8tBpuEwkX6jDHWUekC8ljKDYs5zCW96YWLmpA9gt/Wa+VoETAlormkEK2+3dsXDsfu+mca4MhSDtCarzRoV0JtN02JK7FJm+oZhWLXsfy0R6XmmVwHgktnGQ1/Km+3y426WKANTEuczqZ/ZgXWBxGMj5g8kGzVHyCpJYR+3dGdSyErUvHvyvlXGuEuVyKAv9/AZVz3QFVHjvD71TH1le+eFvkRjXcjJuMAHyEJ8p3AT6HyPxRPOLQERd+shfkvYG3bA/VYk34Q==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAttribute></saml:AttributeStatement></saml:Assertion></samlp:Response>""".getBytes("UTF-8")

def sAMLPWithNoSignature = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" ID="_34DCC381-5BD5-4035-b71B-B1552F8578CD" InResponseTo="_123456789" IssueInstant="2015-07-07T16:28:32.427+02:00" Version="2.0"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_CCA83D00-6FE6-4B80-8D20-9B3693068AB3" IssueInstant="2015-07-07T16:28:32.427+02:00" Version="2.0"><saml:Issuer>someIssuer</saml:Issuer><saml:Subject><saml:NameID>SomeSubject</saml:NameID></saml:Subject><saml:Conditions NotBefore="2015-07-07T16:26:52.427+02:00" NotOnOrAfter="2015-07-07T16:28:32.427+02:00"/><saml:AttributeStatement><saml:EncryptedAttribute><xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/><ds:KeyInfo>
<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><ds:KeyInfo>
<ds:KeyName>A2a5JrfZL6oHCSexVqT9GyeV66QaYYY1YbqU+/eDkyc=</ds:KeyName>
</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>OsmJo/KXd/D/Tm4A8pTiqmsxPcdUkEZ0JwJAl5ITMzFy/hnghr9eX0wZYW7a+74iD9CJvZLQsmrvD61G4GLlu8iLYX+A57JKhxmLdhHEANHKFxh7/VkaHvH5bL/yfvD+1jPqaGmwYKr7eIf/wcWJeDWh/eqoGHNHrwdWWalkxyWJjImUt0tLuLKjKqmgqvC0ZG7D43bkZDbq+HPCKdfEzpAA1C/SH/d7wel32WlPI4cy6fO8wTLcA/FeIuw4ZYfhcLFwxurXm9N3ROAZgu7bMofm43/TkVtchAFbkU3Fj/Eqa0b5Yvoi50TuML/qgVwfkpce28dppzj4zujm4spSfA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><ds:KeyInfo>
<ds:KeyName>yrhA2ngreu9CwRBvbfKReRFRmZk/GB50/vT6IhgT8no=</ds:KeyName>
</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>g72vCUTVQB37dBwBavo+NvRklzRNkRh1H/d7lhKBhZJxbsFeMv2jZn0IAwNgkypfEDCcuQvNvIRzomAX3qeY+n+aX9Pis9vL1YXeLIUZSzOgJxkp94E1qTUiYo0IUg3ww3OgtTSE5zo6ZWjO0KHiv0LIL/KCT/LkjVMDw+c7oWV+/iA2CYnpq1EkpWrJcNOknxEYTKN0KVfg/2ntnp2GrDAZBXqpjK+iTt0qIHq0Dd7BUACPsgTgt9G6kmp87p9OTSqBb6llcalxOs+vbQ5NEvl7UbJF5q9saxu6ADy9oPJPIgrT5QEg37cD82FRjX2Ty8PBQJc2HriwI3loXn5taw==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>N/J+2evaoEXGQSEhR0P47FNSrBDYuoUI+Q3zrjhluEtxDWQGxTVI6CP7OBEGOCSbmQlUJ49QkCx418vXmoVjOY5Y3b3mJUO+86lSL8f+uZRmPs76JcFdf7uOme3tu6rhSsLh9JpklqnQSLBWqqydkbpHPM5LqkDOKDMXEmHpe6QfzpU1FXWUAqQuwXwZ8ceReJKNpp1RNxM1L/+EWDGeH+8pKLTG375f6UXCHy3u/sDYrDlXS7w6jeZ7LIs9NAWayDA1Aiqm0Y7h9jD8iC7ynPDapCwkd7u7psInpP2dqUz0Zxf3mJSZUvrsE+HblgdWw5RiaBlzsT7tIHpPA/3bnZuO9Oa4jGRnTFjOcTxW1/wN8UO2Lu96gtHCdgi/2+LJFCy3LS9uZUMTQDClAUrvfTWXzj3Xcrp3ph4FF6gzz+FufkMJbPmDv/fGK/6t4xVgRlZlV/+FSo6jFEexYaEch3KfZXLOyHSz/0WXONDlhINEr2zRmUZzCoQdey+v6tbXnVdrmyZxjM3i8tBpuEwkX6jDHWUekC8ljKDYs5zCW96YWLmpA9gt/Wa+VoETAlormkEK2+3dsXDsfu+mca4MhSDtCarzRoV0JtN02JK7FJm+oZhWLXsfy0R6XmmVwHgktnGQ1/Km+3y426WKANTEuczqZ/ZgXWBxGMj5g8kGzVHyCpJYR+3dGdSyErUvHvyvlXGuEuVyKAv9/AZVz3QFVHjvD71TH1le+eFvkRjXcjJuMAHyEJ8p3AT6HyPxRPOLQERd+shfkvYG3bA/VYk34Q==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAttribute></saml:AttributeStatement></saml:Assertion></samlp:Response>""".getBytes("UTF-8")

def dualSignatureSAMLP = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" ID="_34DCC381-5BD5-4035-b71B-B1552F8578CD" InResponseTo="_123456789" IssueInstant="2015-07-07T16:28:32.427+02:00" Version="2.0"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_CCA83D00-6FE6-4B80-8D20-9B3693068AB3" IssueInstant="2015-07-07T16:28:32.427+02:00" Version="2.0"><saml:Issuer>someIssuer</saml:Issuer><ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_CCA83D00-6FE6-4B80-8D20-9B3693068AB3"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>oMziNyNGdPLo6VLwp7OnGaAzFdvZBPiddubCJE7C/9c=</DigestValue></Reference></SignedInfo><SignatureValue>aRIwgOB7KPEhyiD4s+s340eM/XVFEfD38unhnaAWHspNzm7bCwW58XbU4nhtFH+DXQRiWVcUBqfC
rKHgu+mYAAuJGHZjgaEIa2ewv8xjQ44oc921ILItwIMBKgJnkkuU58FWlI/W1GXlHhXIe4ASZoct
qBWaNSI10ZhB6tzxQCiuQtFgfTt0SdOI5TUEjv30OkBZO5kg03s8iqc3by54p+2CqP3ExB4C2lf8
C28+WTb61Ytt8RylFW6xq71VuIHni9s9bJD7rivO9+YmL9N02/M8naWV28nvwt/OQlNWD/wYjujx
zbMCtIlDbFH6L+YdBk3KORicWwv1ZQ+/KrXK0A==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
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
ZLCP64EJEfE1mGxCJg==</X509Certificate></X509Data></KeyInfo></ds:Signature><saml:Subject><saml:NameID>SomeSubject</saml:NameID></saml:Subject><saml:Conditions NotBefore="2015-07-07T16:26:52.427+02:00" NotOnOrAfter="2015-07-07T16:28:32.427+02:00"/><saml:AttributeStatement><saml:EncryptedAttribute><xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/><ds:KeyInfo>
<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><ds:KeyInfo>
<ds:KeyName>A2a5JrfZL6oHCSexVqT9GyeV66QaYYY1YbqU+/eDkyc=</ds:KeyName>
</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>OsmJo/KXd/D/Tm4A8pTiqmsxPcdUkEZ0JwJAl5ITMzFy/hnghr9eX0wZYW7a+74iD9CJvZLQsmrvD61G4GLlu8iLYX+A57JKhxmLdhHEANHKFxh7/VkaHvH5bL/yfvD+1jPqaGmwYKr7eIf/wcWJeDWh/eqoGHNHrwdWWalkxyWJjImUt0tLuLKjKqmgqvC0ZG7D43bkZDbq+HPCKdfEzpAA1C/SH/d7wel32WlPI4cy6fO8wTLcA/FeIuw4ZYfhcLFwxurXm9N3ROAZgu7bMofm43/TkVtchAFbkU3Fj/Eqa0b5Yvoi50TuML/qgVwfkpce28dppzj4zujm4spSfA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><ds:KeyInfo>
<ds:KeyName>yrhA2ngreu9CwRBvbfKReRFRmZk/GB50/vT6IhgT8no=</ds:KeyName>
</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>g72vCUTVQB37dBwBavo+NvRklzRNkRh1H/d7lhKBhZJxbsFeMv2jZn0IAwNgkypfEDCcuQvNvIRzomAX3qeY+n+aX9Pis9vL1YXeLIUZSzOgJxkp94E1qTUiYo0IUg3ww3OgtTSE5zo6ZWjO0KHiv0LIL/KCT/LkjVMDw+c7oWV+/iA2CYnpq1EkpWrJcNOknxEYTKN0KVfg/2ntnp2GrDAZBXqpjK+iTt0qIHq0Dd7BUACPsgTgt9G6kmp87p9OTSqBb6llcalxOs+vbQ5NEvl7UbJF5q9saxu6ADy9oPJPIgrT5QEg37cD82FRjX2Ty8PBQJc2HriwI3loXn5taw==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>N/J+2evaoEXGQSEhR0P47FNSrBDYuoUI+Q3zrjhluEtxDWQGxTVI6CP7OBEGOCSbmQlUJ49QkCx418vXmoVjOY5Y3b3mJUO+86lSL8f+uZRmPs76JcFdf7uOme3tu6rhSsLh9JpklqnQSLBWqqydkbpHPM5LqkDOKDMXEmHpe6QfzpU1FXWUAqQuwXwZ8ceReJKNpp1RNxM1L/+EWDGeH+8pKLTG375f6UXCHy3u/sDYrDlXS7w6jeZ7LIs9NAWayDA1Aiqm0Y7h9jD8iC7ynPDapCwkd7u7psInpP2dqUz0Zxf3mJSZUvrsE+HblgdWw5RiaBlzsT7tIHpPA/3bnZuO9Oa4jGRnTFjOcTxW1/wN8UO2Lu96gtHCdgi/2+LJFCy3LS9uZUMTQDClAUrvfTWXzj3Xcrp3ph4FF6gzz+FufkMJbPmDv/fGK/6t4xVgRlZlV/+FSo6jFEexYaEch3KfZXLOyHSz/0WXONDlhINEr2zRmUZzCoQdey+v6tbXnVdrmyZxjM3i8tBpuEwkX6jDHWUekC8ljKDYs5zCW96YWLmpA9gt/Wa+VoETAlormkEK2+3dsXDsfu+mca4MhSDtCarzRoV0JtN02JK7FJm+oZhWLXsfy0R6XmmVwHgktnGQ1/Km+3y426WKANTEuczqZ/ZgXWBxGMj5g8kGzVHyCpJYR+3dGdSyErUvHvyvlXGuEuVyKAv9/AZVz3QFVHjvD71TH1le+eFvkRjXcjJuMAHyEJ8p3AT6HyPxRPOLQERd+shfkvYG3bA/VYk34Q==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAttribute></saml:AttributeStatement></saml:Assertion><saml:Assertion ID="_CCA83D00-6FE6-4B80-8D20-9B3693068AB3" IssueInstant="2015-07-07T16:28:32.427+02:00" Version="2.0"><saml:Issuer>someIssuer</saml:Issuer><ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_CCA83D00-6FE6-4B80-8D20-9B3693068AB3"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>oMziNyNGdPLo6VLwp7OnGaAzFdvZBPiddubCJE7C/9c=</DigestValue></Reference></SignedInfo><SignatureValue>aRIwgOB7KPEhyiD4s+s340eM/XVFEfD38unhnaAWHspNzm7bCwW58XbU4nhtFH+DXQRiWVcUBqfC
rKHgu+mYAAuJGHZjgaEIa2ewv8xjQ44oc921ILItwIMBKgJnkkuU58FWlI/W1GXlHhXIe4ASZoct
qBWaNSI10ZhB6tzxQCiuQtFgfTt0SdOI5TUEjv30OkBZO5kg03s8iqc3by54p+2CqP3ExB4C2lf8
C28+WTb61Ytt8RylFW6xq71VuIHni9s9bJD7rivO9+YmL9N02/M8naWV28nvwt/OQlNWD/wYjujx
zbMCtIlDbFH6L+YdBk3KORicWwv1ZQ+/KrXK0A==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
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
ZLCP64EJEfE1mGxCJg==</X509Certificate></X509Data></KeyInfo></ds:Signature><saml:Subject><saml:NameID>SomeSubject</saml:NameID></saml:Subject><saml:Conditions NotBefore="2015-07-07T16:26:52.427+02:00" NotOnOrAfter="2015-07-07T16:28:32.427+02:00"/><saml:AttributeStatement><saml:EncryptedAttribute><xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/><ds:KeyInfo>
<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><ds:KeyInfo>
<ds:KeyName>A2a5JrfZL6oHCSexVqT9GyeV66QaYYY1YbqU+/eDkyc=</ds:KeyName>
</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>OsmJo/KXd/D/Tm4A8pTiqmsxPcdUkEZ0JwJAl5ITMzFy/hnghr9eX0wZYW7a+74iD9CJvZLQsmrvD61G4GLlu8iLYX+A57JKhxmLdhHEANHKFxh7/VkaHvH5bL/yfvD+1jPqaGmwYKr7eIf/wcWJeDWh/eqoGHNHrwdWWalkxyWJjImUt0tLuLKjKqmgqvC0ZG7D43bkZDbq+HPCKdfEzpAA1C/SH/d7wel32WlPI4cy6fO8wTLcA/FeIuw4ZYfhcLFwxurXm9N3ROAZgu7bMofm43/TkVtchAFbkU3Fj/Eqa0b5Yvoi50TuML/qgVwfkpce28dppzj4zujm4spSfA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><ds:KeyInfo>
<ds:KeyName>yrhA2ngreu9CwRBvbfKReRFRmZk/GB50/vT6IhgT8no=</ds:KeyName>
</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>g72vCUTVQB37dBwBavo+NvRklzRNkRh1H/d7lhKBhZJxbsFeMv2jZn0IAwNgkypfEDCcuQvNvIRzomAX3qeY+n+aX9Pis9vL1YXeLIUZSzOgJxkp94E1qTUiYo0IUg3ww3OgtTSE5zo6ZWjO0KHiv0LIL/KCT/LkjVMDw+c7oWV+/iA2CYnpq1EkpWrJcNOknxEYTKN0KVfg/2ntnp2GrDAZBXqpjK+iTt0qIHq0Dd7BUACPsgTgt9G6kmp87p9OTSqBb6llcalxOs+vbQ5NEvl7UbJF5q9saxu6ADy9oPJPIgrT5QEg37cD82FRjX2Ty8PBQJc2HriwI3loXn5taw==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>N/J+2evaoEXGQSEhR0P47FNSrBDYuoUI+Q3zrjhluEtxDWQGxTVI6CP7OBEGOCSbmQlUJ49QkCx418vXmoVjOY5Y3b3mJUO+86lSL8f+uZRmPs76JcFdf7uOme3tu6rhSsLh9JpklqnQSLBWqqydkbpHPM5LqkDOKDMXEmHpe6QfzpU1FXWUAqQuwXwZ8ceReJKNpp1RNxM1L/+EWDGeH+8pKLTG375f6UXCHy3u/sDYrDlXS7w6jeZ7LIs9NAWayDA1Aiqm0Y7h9jD8iC7ynPDapCwkd7u7psInpP2dqUz0Zxf3mJSZUvrsE+HblgdWw5RiaBlzsT7tIHpPA/3bnZuO9Oa4jGRnTFjOcTxW1/wN8UO2Lu96gtHCdgi/2+LJFCy3LS9uZUMTQDClAUrvfTWXzj3Xcrp3ph4FF6gzz+FufkMJbPmDv/fGK/6t4xVgRlZlV/+FSo6jFEexYaEch3KfZXLOyHSz/0WXONDlhINEr2zRmUZzCoQdey+v6tbXnVdrmyZxjM3i8tBpuEwkX6jDHWUekC8ljKDYs5zCW96YWLmpA9gt/Wa+VoETAlormkEK2+3dsXDsfu+mca4MhSDtCarzRoV0JtN02JK7FJm+oZhWLXsfy0R6XmmVwHgktnGQ1/Km+3y426WKANTEuczqZ/ZgXWBxGMj5g8kGzVHyCpJYR+3dGdSyErUvHvyvlXGuEuVyKAv9/AZVz3QFVHjvD71TH1le+eFvkRjXcjJuMAHyEJ8p3AT6HyPxRPOLQERd+shfkvYG3bA/VYk34Q==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAttribute></saml:AttributeStatement></saml:Assertion></samlp:Response>""".getBytes("UTF-8")


def validCSMessage = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:credmanagement="http://certificateservices.org/xsd/credmanagement2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:keystoremgmt="http://certificateservices.org/xsd/keystoremgmt2_0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="2.0" timeStamp="2015-07-15T17:11:54.467+02:00" version="2.0" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd"><cs:name>ChangeCredentialStatusRequest</cs:name><cs:sourceId>SOMEREQUESTER</cs:sourceId><cs:destinationId>somedst</cs:destinationId><cs:organisation>someorg</cs:organisation><cs:assertions><saml:Assertion ID="_FD3F463B-9B6B-4C83-bD73-3FE38308F876" IssueInstant="2015-07-07T16:26:53.000+02:00" Version="2.0"><saml:Issuer>someIssuer</saml:Issuer><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#_FD3F463B-9B6B-4C83-bD73-3FE38308F876"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>32DJ27TaWSwJugskXXCu1IYeHr8Zl50vzzMwBsbR2sU=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Jv352IodydZEaXHHm6jbr5/s7S7gNQ8daN1zCkctsEz3VEKVhALr8dTWg8/1z4kg0gDKMu+nBFPigxar6gotWksF0qIrfibHPelo1/qnR0mMEdYBUymnLNkr73m+Mdtq2jiJ5LGNRyNRx3rJMi1npdWgJo3V11Ziuyz9S3aOhBBR3We5HzXyhBAPtAstRTjsGe72EBKB8sTpbCtfz2H1k7Zw5dzK/RhQ8GiHbFsHWSvFRhIkwWRco2gvlrBki/SMcxA+8kPcD9nx6niKvFVPnwGv7OJ9QYMALxshPLxdXYUU7umnzG/hUGDSKAF58huzepKSOnCfYCL+++rxmia0Cw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBDdXN0b21lcjEgQVQgU2VydmVyQ0ExGjAYBgNVBAoMEURlbW8gQ3VzdG9tZXIxIEFUMB4XDTEyMTAxMDE0NDQwNFoXDTE0MTAxMDE0NDQwNFowKzENMAsGA1UEAwwEdGVzdDEaMBgGA1UECgwRRGVtbyBDdXN0b21lcjEgQVQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCbDqmR4e8sgxw2Afi/y3i/mT7WwtpW18/QfyUGpYPPxQ4bvPPn61y3jJg/dAbGHvnyQSHfIvrIJUN83q6evvk0bNZNVSENUEP29isE4D+KjD3PFtAzQq18P8m/8mSXMva5VTooEUSDX+VJ/6el6tnyZdc85AlIJkkkvyiDKcjhf10yllaiVCHLunGMDXAec4DapPi5GdmSMMXyPOhRx5e+oy6b5q9XmT3C29VNVFf+tkAt3ew3BoQbd+VrlBI4oRYq+mfbgkXU6dSKr9DRqhsbu5rU4Jdst2KClXsxaxvC0rVeKQ8iXCDKFH5glzhSYoeWl7CI15CdQM6/so7EisSvAgMBAAGjgeMwgeAwHQYDVR0OBBYEFLpidyp0Pc46cUpJf1neFnq/rLJBMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUgEn+Hp9+Yxe4lOhaIPmf++Wu7SYwGAYDVR0gBBEwDzANBgsrBgEEAYH1fgMDCTBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vYXQtY3JsLndtLm5ldC9kZW1vY3VzdG9tZXIxX3NlcnZlcmNhLmNybDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0RBAgwBoIEdGVzdDANBgkqhkiG9w0BAQUFAAOCAQEAZxGls/mNT4GyAf9u9lg78sSA27sc3xFvHNogrT4yUCbYAOhLXO4HJ9XuKaFyz4bKz6JGdLaQDknDI1GUvpJLpiPTXk4cq1ppHVt5/2QVeDCGtite4CH/YrAe4gufBqWo9q7XQeQbjil0mOUsSp1ErrcSadyT+KZoD4GXJBIVFcOIWKL7aCHzSLpw/+DY1sEiAbStmhz0K+UrFK+FVdZn1RIWGeVClhJklLb2vNjQgPYGdd5nKyLrlA4zekPDDWdmmxwv4A3MG8KSnl8VBU5CmAZLR1YRaioK6xL1QaH0a16FTkn3y6GVeYUGsTeyLvLlfhgAZLCP64EJEfE1mGxCJg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID>SomeSubject</saml:NameID></saml:Subject><saml:Conditions NotBefore="2015-07-07T16:26:52.427+02:00" NotOnOrAfter="2015-07-07T16:28:32.427+02:00"/><saml:AttributeStatement><saml:Attribute Name="AssertionType"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">APPROVAL_TICKET</saml:AttributeValue></saml:Attribute><saml:Attribute Name="ApprovalId"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">1234</saml:AttributeValue></saml:Attribute><saml:Attribute Name="ApprovedRequests"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">abcdef</saml:AttributeValue><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">defcva</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion><saml:Assertion ID="_62FFBB6F-D450-4693-93BC-6E561398C425" IssueInstant="2015-07-07T16:26:53.000+02:00" Version="2.0"><saml:Issuer>someIssuer</saml:Issuer><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#_62FFBB6F-D450-4693-93BC-6E561398C425"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>kH2pQbZaTC/YpCKM7/5XxjMLSvd5RdU5b8nMRi9bd5k=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>HPwY8YTSTmYGqEYCXmXnqfL4XrlwI7kiOSctC42+6iND/OXo38uo48EoizzE4geZq8Bve/OLESMd8As6GUzZMlwCK0qXdLwKJgho7TObIkI613zq6zrLrq3t3TuGvDsPRjKRVEYA6ofpl3SVnMdUcG1ZJIEMhP7lbN98cxteeY+MvOPl7Kdif1xnBZQCeVmkE+x1x/a5nhTqCQ+PvzL1FRUFkLz+nb85dqdzDgjVpeyY9Da8fgeVjgKGulOHFUvuL20bE8mbXI/d+Nr9rpeQ1WMvGfv7dJnbpeo8C0JIxUqyC/huoXxGWEYwAvq95/TwQJ5wLLwAgMki7FWqV9KuIA==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBDdXN0b21lcjEgQVQgU2VydmVyQ0ExGjAYBgNVBAoMEURlbW8gQ3VzdG9tZXIxIEFUMB4XDTEyMTAxMDE0NDQwNFoXDTE0MTAxMDE0NDQwNFowKzENMAsGA1UEAwwEdGVzdDEaMBgGA1UECgwRRGVtbyBDdXN0b21lcjEgQVQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCbDqmR4e8sgxw2Afi/y3i/mT7WwtpW18/QfyUGpYPPxQ4bvPPn61y3jJg/dAbGHvnyQSHfIvrIJUN83q6evvk0bNZNVSENUEP29isE4D+KjD3PFtAzQq18P8m/8mSXMva5VTooEUSDX+VJ/6el6tnyZdc85AlIJkkkvyiDKcjhf10yllaiVCHLunGMDXAec4DapPi5GdmSMMXyPOhRx5e+oy6b5q9XmT3C29VNVFf+tkAt3ew3BoQbd+VrlBI4oRYq+mfbgkXU6dSKr9DRqhsbu5rU4Jdst2KClXsxaxvC0rVeKQ8iXCDKFH5glzhSYoeWl7CI15CdQM6/so7EisSvAgMBAAGjgeMwgeAwHQYDVR0OBBYEFLpidyp0Pc46cUpJf1neFnq/rLJBMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUgEn+Hp9+Yxe4lOhaIPmf++Wu7SYwGAYDVR0gBBEwDzANBgsrBgEEAYH1fgMDCTBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vYXQtY3JsLndtLm5ldC9kZW1vY3VzdG9tZXIxX3NlcnZlcmNhLmNybDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0RBAgwBoIEdGVzdDANBgkqhkiG9w0BAQUFAAOCAQEAZxGls/mNT4GyAf9u9lg78sSA27sc3xFvHNogrT4yUCbYAOhLXO4HJ9XuKaFyz4bKz6JGdLaQDknDI1GUvpJLpiPTXk4cq1ppHVt5/2QVeDCGtite4CH/YrAe4gufBqWo9q7XQeQbjil0mOUsSp1ErrcSadyT+KZoD4GXJBIVFcOIWKL7aCHzSLpw/+DY1sEiAbStmhz0K+UrFK+FVdZn1RIWGeVClhJklLb2vNjQgPYGdd5nKyLrlA4zekPDDWdmmxwv4A3MG8KSnl8VBU5CmAZLR1YRaioK6xL1QaH0a16FTkn3y6GVeYUGsTeyLvLlfhgAZLCP64EJEfE1mGxCJg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID>SomeSubject</saml:NameID></saml:Subject><saml:Conditions NotBefore="2015-07-07T16:26:52.427+02:00" NotOnOrAfter="2015-07-07T16:28:32.427+02:00"/><saml:AttributeStatement><saml:Attribute Name="AssertionType"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">AUTHORIZATION_TICKET</saml:AttributeValue></saml:Attribute><saml:EncryptedAttribute><xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/><ds:KeyInfo>
<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><ds:KeyInfo>
<ds:KeyName>A2a5JrfZL6oHCSexVqT9GyeV66QaYYY1YbqU+/eDkyc=</ds:KeyName>
</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>K5GfR+ntss/kDMLrXEZSH2Twc7fLV478lVqou1ASJQBce8BpPEPddv9njkSQsJp4yY33isj0QCY0JaoIIr+sHX5e1jqkes6ir0JnksCq1iXM9UrpZCtlwl/6PtuATGjObVMj6tJXOlj6Q2n3atOJzsFJD1syc88w6DZH9vnLK92k2puvGJNJLTrD+iO23PoPr0w2lgZU/mfarTF0Yv/6t6xAqw1W0WCbIvz5QqTn5Up0skB4Mxz5QcNgMnKP6SFWV/RPfSQcyAMDST5KbmAsAV1ySu4Y9TMvYWdCGa3XifYt60VG+bBf/rn2yc0zdYuoE+jfi3YuTe29jgZLDNhcBw==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>vJzGoOstOSTHNzE1hzDDrKdjCDKfNu8+V34DxYMUeEI73ZeSJsZInAFPx5WHEvIfG2OyVPew8tZRHGMX/FVYwNSwgwt7qG99G5lhysvTXGIFU+GhUauwC3GcdmV9dVgFZqN0btI7+TnhsSsj14ExVO/0+7ammxG+n1GW61+Sr3hDzPfuQbrNQDETVliCkvTC6ckwl8gG/RzEFsGquSPGuTnDqyEL+7HEUpNroEnO6/PaaYRMPjswGgRKtUl2IRVYU+VtAvWAGn+l/v2+06TxEH8rp0WY2IDWAe2IXGD7RHHuazKkIknEhMdKLTVp9a4SUamZR/NI9ziepOkL0WBm4/XXsJrKczl/l/WYCJbxscT7Ts7PF58udZYAjfwL5HCND7J75geF5fiG5VgPJ9MFyAFnTblQFS64VQqhsNEpKyGRVBBF3+m/0fHROYbtxN5ODTlqdggTaP6NFFD7ndEqc9hu1VtA0YjwhcB35NHCk4BzpsOscPQ2ypVrEZRjCjtnT483TDiRK0WLSN1J/DVBIMjE9CQcUhN1Emy0zFa2GMyi9B1cMJ9MpS8bEUR/Nltwhw0qrPrYqFimzcGXO4Vc0qpz1cktJM4dEWCvdvg1tZF4O+vcwFbXfNg02WhDJD7skmbkok0HGsHwAdgLLWqBVCFpnor9E38w6WdWQdFpaqwtC9xZLmYYzGNlyxq1Uq/tJDVGn/t1C5zU2Z1jK/6Qt+npOe+HHCJAkbN0RQlUbL/QgZZw7LNTpPx2+G6cqXj3EtydtpO9UFIErB+tk8NqUQ==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAttribute></saml:AttributeStatement></saml:Assertion></cs:assertions><cs:payload><credmanagement:ChangeCredentialStatusRequest><credmanagement:issuerId>someissuer</credmanagement:issuerId><credmanagement:serialNumber>123</credmanagement:serialNumber><credmanagement:newCredentialStatus>100</credmanagement:newCredentialStatus></credmanagement:ChangeCredentialStatusRequest></cs:payload><ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#12345678-1234-4444-8000-123456789012"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>qh0f6v3xdyBkMd0H9d7C8uyQ523dStORjqFXVQuGsoQ=</DigestValue></Reference></SignedInfo><SignatureValue>dmLQsSMrA9kL11HFAfGGacxyx7FAron9AwAMobH42PrSFdvEt9HmaObfQaIG3O1++ZLkVHA+JDX5
UO+V1t2g302T7nbrTSXFkm4WBa/W5RMp3Lt1l1DCCU/rx+yreUhQwv2uuHsxq2Ozb8XOqFIOKvlD
sJH2J7hXt4JRCcj+j67QlRrTdFHfIvbThjciN2tZ8koCtNXbvwVgyNjy+ofGfMQFO6JAYCKxR/Af
YvG3lp06WY9rSFOTYEQ5m2bsWpvWHWJLa6zpHnhFsgbOnCsz0E/CYLc7DYgRogM2A2tgyvpdmQCe
1kX7qI15Pp/HZ3LTpilw8FaPkoq4eECBA3wGCg==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
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
ZLCP64EJEfE1mGxCJg==</X509Certificate></X509Data></KeyInfo></ds:Signature></cs:CSMessage>""".getBytes("UTF-8")

	def ecCert = """MIIBDTCBtAIJALqOTIKfSF+iMAoGCCqGSM49BAMCMA8xDTALBgNVBAMMBFRlc3Qw
HhcNMTgwNjEyMTIzMTA4WhcNMzgwNjA3MTIzMTA4WjAPMQ0wCwYDVQQDDARUZXN0
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEf+oCECV53U2580NTExF2/QlEoL+p
3/mOnGC0qb3UhUowlo+f94Y5WH8HcuY9U+cv44udHM0jlJZwMo/QoTsEVjAKBggq
hkjOPQQDAgNIADBFAiEA2Y2viDHBsNbA+5slq24M2kcc190lgBTvcmfQhZgZKccC
IBGY9uX1A4fDvb1/ygBj7X+Mh5jU2CTkUWnkH6xjtYGK"""

	def ecKey = """MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgw6qZY9/fbuup4bZQ
U/LfB7N9/NKeMEz0cBYPW57veEGhRANCAAR/6gIQJXndTbnzQ1MTEXb9CUSgv6nf
+Y6cYLSpvdSFSjCWj5/3hjlYfwdy5j1T5y/ji50czSOUlnAyj9ChOwRW"""

}
