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
package org.certificateservices.messages.utils

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Base64
import org.certificateservices.messages.ContextMessageSecurityProvider
import org.certificateservices.messages.HSMMessageSecurityProvider
import org.certificateservices.messages.MessageSecurityProvider
import org.certificateservices.messages.csmessages.CSMessageParserManager
import org.w3c.dom.NodeList

import javax.crypto.KeyGenerator
import java.security.MessageDigest
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.xml.bind.JAXBElement
import javax.xml.transform.OutputKeys
import javax.xml.transform.Transformer
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult

import org.apache.xml.security.Init
import org.apache.xml.security.encryption.XMLCipher
import org.apache.xml.security.utils.EncryptionConstants
import org.certificateservices.messages.EncryptionAlgorithmScheme
import org.certificateservices.messages.MessageContentException
import org.certificateservices.messages.MessageProcessingException
import org.certificateservices.messages.NoDecryptionKeyFoundException
import org.certificateservices.messages.assertion.AssertionPayloadParser
import org.certificateservices.messages.saml2.BaseSAMLMessageParser.EncryptedAttributeXMLConverter
import org.certificateservices.messages.saml2.assertion.jaxb.AssertionType
import org.certificateservices.messages.saml2.assertion.jaxb.AttributeStatementType
import org.certificateservices.messages.saml2.assertion.jaxb.AttributeType
import org.certificateservices.messages.saml2.assertion.jaxb.EncryptedElementType
import org.certificateservices.messages.saml2.assertion.jaxb.NameIDType
import org.certificateservices.messages.saml2.assertion.jaxb.ObjectFactory
import org.certificateservices.messages.csmessages.PayloadParserRegistry
import org.certificateservices.messages.xenc.jaxb.EncryptedDataType
import org.w3c.dom.Document
import org.w3c.dom.Element
import spock.lang.Specification
import spock.lang.Unroll
import static org.certificateservices.messages.TestUtils.*
import static org.certificateservices.messages.ContextMessageSecurityProvider.DEFAULT_CONTEXT
import static org.certificateservices.messages.utils.XMLSigner.XMLDSIG_NAMESPACE

class XMLEncrypterSpec extends Specification {
	
	ObjectFactory of = new ObjectFactory()
	X509Certificate testCert
	AssertionPayloadParser assertionPayloadParser
	XMLEncrypter xmlEncrypter
	List<X509Certificate> threeReceipients
	List<X509Certificate> twoReceiptiensValidFirst
	List<X509Certificate> twoReceiptiensValidLast
	List<X509Certificate> noValidReceiptients
	
	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Init.init()
	}


	def setup(){
		setupRegisteredPayloadParser()
		assertionPayloadParser = PayloadParserRegistry.getParser(AssertionPayloadParser.NAMESPACE)


		MessageSecurityProvider messageSecurityProvider = CSMessageParserManager.getCSMessageParser().messageSecurityProvider
		assertionPayloadParser.systemTime = new DefaultSystemTime()
		CertificateFactory cf = CertificateFactory.getInstance("X.509")
		testCert = cf.generateCertificate(new ByteArrayInputStream(Base64.decode(base64Cert)))
		
		xmlEncrypter = new XMLEncrypter(messageSecurityProvider, assertionPayloadParser.getDocumentBuilder(),
			 assertionPayloadParser.getAssertionMarshaller(),
			 assertionPayloadParser.getAssertionUnmarshaller())
		
		threeReceipients = new ArrayList<X509Certificate>()
		for(String keyId : messageSecurityProvider.decryptionKeyIds){
			threeReceipients.add(messageSecurityProvider.getDecryptionCertificate(keyId))
		}
		
		X509Certificate validCert = messageSecurityProvider.getDecryptionCertificate(messageSecurityProvider.decryptionKeyIds.iterator().next())
		
		twoReceiptiensValidFirst = new ArrayList<X509Certificate>()
		twoReceiptiensValidFirst.add(validCert)
		twoReceiptiensValidFirst.add(testCert)
		
		twoReceiptiensValidLast = new ArrayList<X509Certificate>()
		twoReceiptiensValidLast.add(testCert)
		twoReceiptiensValidLast.add(validCert)
		
		noValidReceiptients = new ArrayList<X509Certificate>()
		noValidReceiptients.add(testCert)
		
	}
	
	@Unroll
	def "Verify that encryptElement generates encrypted XML document with included certificate using encryption scheme: #encScheme"(){
		setup:
		xmlEncrypter.encKeyXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(encScheme.getKeyEncryptionAlgorithmURI())
		xmlEncrypter.encDataXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(encScheme.getDataEncryptionAlgorithmURI())

		AttributeType attributeType1 = of.createAttributeType()
		attributeType1.getAttributeValue().add("Hej Svejs")
		attributeType1.setName("SomeAttribute")
		def attribute1 = of.createAttribute(attributeType1)
		
		
		when:
		Document encDoc = xmlEncrypter.encryptElement(attribute1, threeReceipients, false)
		String encXML = docToString(encDoc)
		//println encXML
		
		def xml = new XmlSlurper().parse(new StringReader(encXML))
		then:
		xml.@Type == "http://www.w3.org/2001/04/xmlenc#Element"
		xml.EncryptionMethod.@Algorithm == encScheme.getDataEncryptionAlgorithmURI()
		xml.KeyInfo.EncryptedKey.size() == 3
		xml.KeyInfo.EncryptedKey[0].EncryptionMethod.@Algorithm == encScheme.getKeyEncryptionAlgorithmURI()

	    Base64.decode(xml.KeyInfo.EncryptedKey[0].KeyInfo.X509Data.X509Certificate.toString()) == testcertdata1
		xml.KeyInfo.EncryptedKey[0].CipherData.toString().length() > 0
		xml.CipherData.toString().length() > 0
		true
		where:
		encScheme << EncryptionAlgorithmScheme.values()
	}
	
	
	@Unroll
	def "Verify that encryptElement generates encrypted XML document with included keyid using encryption scheme: #encScheme"(){
		setup:
		xmlEncrypter.encKeyXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(encScheme.getKeyEncryptionAlgorithmURI())
		xmlEncrypter.encDataXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(encScheme.getDataEncryptionAlgorithmURI())

		when:
		Document encDoc = xmlEncrypter.encryptElement(genSAMLAttribute("SomeAttribute","Hej Svejs" ), threeReceipients, true)
		String encXML = docToString(encDoc)
//		println encXML
		
		def xml = new XmlSlurper().parse(new StringReader(encXML))
		then:
		xml.@Type == "http://www.w3.org/2001/04/xmlenc#Element"
		xml.EncryptionMethod.@Algorithm == encScheme.getDataEncryptionAlgorithmURI()
		xml.KeyInfo.EncryptedKey.size() == 3
		xml.KeyInfo.EncryptedKey[0].EncryptionMethod.@Algorithm == encScheme.getKeyEncryptionAlgorithmURI()
		xml.KeyInfo.EncryptedKey[0].KeyInfo.KeyName == "A2a5JrfZL6oHCSexVqT9GyeV66QaYYY1YbqU+/eDkyc="
		xml.KeyInfo.EncryptedKey[0].CipherData.toString().length() > 0
		xml.CipherData.toString().length() > 0
		true
		where:
		encScheme << EncryptionAlgorithmScheme.values()
	}

	@Unroll
	def "Verify that encryptElement generates encrypted XML document with included KeyValue using encryption scheme: #encScheme"(){
		setup:
		xmlEncrypter.encKeyXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(encScheme.getKeyEncryptionAlgorithmURI())
		xmlEncrypter.encDataXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(encScheme.getDataEncryptionAlgorithmURI())

		when:
		Document encDoc = xmlEncrypter.encryptElement(DEFAULT_CONTEXT,genSAMLAttribute("SomeAttribute","Hej Svejs" ), threeReceipients, XMLEncrypter.KeyInfoType.KEYVALUE)
		String encXML = docToString(encDoc)
		//println encXML

		def xml = new XmlSlurper().parse(new StringReader(encXML))
		then:
		xml.@Type == "http://www.w3.org/2001/04/xmlenc#Element"
		xml.EncryptionMethod.@Algorithm == encScheme.getDataEncryptionAlgorithmURI()
		xml.KeyInfo.EncryptedKey.size() == 3
		xml.KeyInfo.EncryptedKey[0].EncryptionMethod.@Algorithm == encScheme.getKeyEncryptionAlgorithmURI()
		xml.KeyInfo.EncryptedKey[0].KeyInfo.KeyValue.RSAKeyValue.Modulus.toString().length() > 0
		xml.KeyInfo.EncryptedKey[0].KeyInfo.KeyValue.RSAKeyValue.Exponent.toString() == "AQAB"
				xml.KeyInfo.EncryptedKey[0].CipherData.toString().length() > 0
		xml.CipherData.toString().length() > 0
		true
		where:
		encScheme << EncryptionAlgorithmScheme.values()
	}
	

	@Unroll
	def "Verify that decryptDocument decrypts document encrypted with certificate as keyinfo using encryption scheme: #encScheme"(){
		setup:
		xmlEncrypter.encKeyXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(encScheme.getKeyEncryptionAlgorithmURI())
		xmlEncrypter.encDataXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(encScheme.getDataEncryptionAlgorithmURI())
		def encDoc = docToStringToDoc(xmlEncrypter.encryptElement(genSAMLAttribute("SomeAttribute","Hej Svejs" ), twoReceiptiensValidFirst, false))
		when:
        JAXBElement<AttributeType> decryptedAttribute = xmlEncrypter.decryptDocument(DEFAULT_CONTEXT,encDoc)
		AttributeType attributeType = decryptedAttribute.getValue()
		then:
		attributeType.getName() == "SomeAttribute"
		attributeType.getAttributeValue().get(0) == "Hej Svejs"
		where:
		encScheme << EncryptionAlgorithmScheme.values()
	}

	@Unroll
	def "Verify that decryptDocument decrypts document encrypted with rsa key value as keyinfo using encryption scheme: #encScheme"() {
		setup:
		xmlEncrypter.encKeyXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(encScheme.getKeyEncryptionAlgorithmURI())
		xmlEncrypter.encDataXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(encScheme.getDataEncryptionAlgorithmURI())
		def encDoc = docToStringToDoc(xmlEncrypter.encryptElement(DEFAULT_CONTEXT, genSAMLAttribute("SomeAttribute","Hej Svejs" ), twoReceiptiensValidFirst, XMLEncrypter.KeyInfoType.KEYVALUE))
		when:
		JAXBElement<AttributeType> decryptedAttribute = xmlEncrypter.decryptDocument(DEFAULT_CONTEXT,encDoc)
		AttributeType attributeType = decryptedAttribute.getValue()
		then:
		attributeType.getName() == "SomeAttribute"
		attributeType.getAttributeValue().get(0) == "Hej Svejs"
		where:
		encScheme << EncryptionAlgorithmScheme.values()

	}
	
	@Unroll
	def "Verify that decryptDocument decrypts document encrypted with keyname as keyinfo using encryption scheme: #encScheme"(){
		setup:
		xmlEncrypter.encKeyXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(encScheme.getKeyEncryptionAlgorithmURI())
		xmlEncrypter.encDataXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(encScheme.getDataEncryptionAlgorithmURI())
		def encDoc = docToStringToDoc(xmlEncrypter.encryptElement(genSAMLAttribute("SomeAttribute","Hej Svejs" ), twoReceiptiensValidFirst, true))
		when:
		JAXBElement<AttributeType> decryptedAttribute = xmlEncrypter.decryptDocument(DEFAULT_CONTEXT, encDoc)
		AttributeType attributeType = decryptedAttribute.getValue()
		then:
		attributeType.getName() == "SomeAttribute"
		attributeType.getAttributeValue().get(0) == "Hej Svejs"
		where:
		encScheme << EncryptionAlgorithmScheme.values()
	}
	
	@Unroll
	def "Verify that decryptDocument decrypts document even if valid key info isn't the first one using : #encScheme"(){
		setup:
		xmlEncrypter.encKeyXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(encScheme.getKeyEncryptionAlgorithmURI())
		xmlEncrypter.encDataXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(encScheme.getDataEncryptionAlgorithmURI())
		def encDoc = docToStringToDoc(xmlEncrypter.encryptElement(genSAMLAttribute("SomeAttribute","Hej Svejs" ), twoReceiptiensValidLast, true))
		when:
		JAXBElement<AttributeType> decryptedAttribute = xmlEncrypter.decryptDocument(DEFAULT_CONTEXT,encDoc)
		AttributeType attributeType = decryptedAttribute.getValue()
		then:
		attributeType.getName() == "SomeAttribute"
		attributeType.getAttributeValue().get(0) == "Hej Svejs"


		where:
		encScheme << EncryptionAlgorithmScheme.values()
	}


	@Unroll
	def "Verify that decryptDocument decrypts document with keyinfo using keyvalue and scheme: #encScheme"(){
		setup:
		xmlEncrypter.encKeyXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(encScheme.getKeyEncryptionAlgorithmURI())
		xmlEncrypter.encDataXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(encScheme.getDataEncryptionAlgorithmURI())
		Document encDoc = docToStringToDoc(xmlEncrypter.encryptElement(DEFAULT_CONTEXT, genSAMLAttribute("SomeAttribute","Hej Svejs" ), twoReceiptiensValidLast, XMLEncrypter.KeyInfoType.KEYVALUE))
		expect:
		encDoc.getElementsByTagNameNS(XMLSigner.XMLDSIG_NAMESPACE,"RSAKeyValue").length > 0
		when:
		JAXBElement<AttributeType> decryptedAttribute = xmlEncrypter.decryptDocument(DEFAULT_CONTEXT,encDoc)
		AttributeType attributeType = decryptedAttribute.getValue()
		then:
		attributeType.getName() == "SomeAttribute"
		attributeType.getAttributeValue().get(0) == "Hej Svejs"


		where:
		encScheme << EncryptionAlgorithmScheme.values()
	}



	def "Verify that decryptDocument throws NoDecryptionKeyFoundException if no valid key info could be found"(){
		setup:
		xmlEncrypter.encKeyXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT] = XMLCipher.getInstance(EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256.getKeyEncryptionAlgorithmURI())
		xmlEncrypter.encDataXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT] = XMLCipher.getInstance(EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256.getDataEncryptionAlgorithmURI())
		def encDoc = docToStringToDoc(xmlEncrypter.encryptElement(genSAMLAttribute("SomeAttribute","Hej Svejs" ), noValidReceiptients, true))
		when:
		xmlEncrypter.decryptDocument(DEFAULT_CONTEXT,encDoc)
		
		then:
		thrown NoDecryptionKeyFoundException
		
		when:
		def encDoc2 = docToStringToDoc(xmlEncrypter.encryptElement(genSAMLAttribute("SomeAttribute","Hej Svejs" ), new ArrayList(), true))
		xmlEncrypter.decryptDocument(DEFAULT_CONTEXT,encDoc2)
		then:
		thrown NoDecryptionKeyFoundException
		
	}

	def "Verify that decryptDocument can decrypt Assertion containing multiple encrypted SAMLAttributes with the same reciepients"(){
		setup:
		xmlEncrypter.encKeyXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256.getKeyEncryptionAlgorithmURI())
		xmlEncrypter.encDataXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256.getDataEncryptionAlgorithmURI())
		def encDoc = genComplexSAMLWithToEncryptedData(XMLEncrypter.KeyInfoType.KEYVALUE)
		when:
		JAXBElement<AttributeType> assertion = xmlEncrypter.decryptDocument(DEFAULT_CONTEXT, encDoc, new EncryptedAttributeXMLConverter())
		AssertionType assertionType = assertion.getValue()
		AttributeStatementType attributeStatement = assertionType.getStatementOrAuthnStatementOrAuthzDecisionStatement().get(0)
		AttributeType attr1 = attributeStatement.getAttributeOrEncryptedAttribute().get(0)
		AttributeType attr2 = attributeStatement.getAttributeOrEncryptedAttribute().get(1)
		then:
		attributeStatement.getAttributeOrEncryptedAttribute().size() == 2
		attr1.getName() == "SomeAttribute1"
		attr2.getName() == "SomeAttribute2"
	}

	def "Verify that decryptDocument can decrypt Assertion with KeyInfo containing RetrievalMethod"() {
		setup:
		xmlEncrypter.encKeyXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256.getKeyEncryptionAlgorithmURI())
		xmlEncrypter.encDataXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256.getDataEncryptionAlgorithmURI())
		def encDoc = updateKeyInfoWithRetrievalMethod(genComplexSAMLWithToEncryptedData(XMLEncrypter.KeyInfoType.KEYVALUE))
		when:
		JAXBElement<AttributeType> assertion = xmlEncrypter.decryptDocument(DEFAULT_CONTEXT, encDoc, new EncryptedAttributeXMLConverter())
		AssertionType assertionType = assertion.getValue()
		AttributeStatementType attributeStatement = assertionType.getStatementOrAuthnStatementOrAuthzDecisionStatement().get(0)
		AttributeType attr1 = attributeStatement.getAttributeOrEncryptedAttribute().get(0)
		AttributeType attr2 = attributeStatement.getAttributeOrEncryptedAttribute().get(1)
		then:
		attributeStatement.getAttributeOrEncryptedAttribute().size() == 2
		attr1.getName() == "SomeAttribute1"
		attr2.getName() == "SomeAttribute2"	}

	def "Verify that decryptDocument doesn't break signature of encrypted element"(){
		setup:
		byte[] signedAssertionData = createSimpleSignedAssertion()
		when:
		def signedAssertionJaxb = assertionPayloadParser.parseApprovalTicket(signedAssertionData)
		then: // verify that signature works
		signedAssertionJaxb != null
		when:
		Document doc = xmlEncrypter.documentBuilder.parse(new ByteArrayInputStream(signedAssertionData))
		assertionPayloadParser.xmlSigner.verifyEnvelopedSignature(DEFAULT_CONTEXT,doc,false)
		then: // verify that Document parse didn't break signature
		true

		when:
		Document encryptedDoc = xmlEncrypter.encryptElement(doc,twoReceiptiensValidLast, false)
		Document decryptedDoc = xmlEncrypter.decryptDoc(DEFAULT_CONTEXT,encryptedDoc,null)
		then: // Verify that decrypted element still verifies
		assertionPayloadParser.xmlSigner.verifyEnvelopedSignature(DEFAULT_CONTEXT,decryptedDoc,false)
	}
	
	def "Verify encryption and decryption of properties"() {
		setup:
		Properties properties = new Properties()
		properties.setProperty("prop1", "somevalue11")
		properties.setProperty("prop2", "somevalue22")
		properties.setProperty("prop3", "somevalue33")
		properties.setProperty("prop4", "somevalue44")
		when:
		Document encDocument = xmlEncrypter.encryptProperties(properties, threeReceipients, true)
		Properties decProperties = xmlEncrypter.decryptProperties(encDocument)
		then:
		decProperties.getProperty("prop1") == "somevalue11"
		decProperties.getProperty("prop2") == "somevalue22"
		decProperties.getProperty("prop3") == "somevalue33"
		decProperties.getProperty("prop4") == "somevalue44"
	}
	
	def "Verify that generateKeyId generates a valid id as Base64 encoded SHA-256 hash or throws MessageProcessingException if generation fails"(){
		expect:
		XMLEncrypter.generateKeyId(testCert.getPublicKey()) == "yrhA2ngreu9CwRBvbfKReRFRmZk/GB50/vT6IhgT8no="
		when:
		XMLEncrypter.generateKeyId(null)
		then:
		thrown MessageProcessingException
	}
	
	def "Verify verifyCiphers accepts supported chiphers and thrown MessageContentException for unsupported chiphers"(){
		setup:
		Document encryptedDoc = xmlEncrypter.encryptElement(genSAMLAttribute("SomeAttribute1","Hej Svejs1" ), twoReceiptiensValidLast, true)
		Element encryptedElement = encryptedDoc.getDocumentElement()
		when:
		xmlEncrypter.verifyCiphers(encryptedElement)
		then:
		true
		
		when:
		Element encryptionMethod = encryptedElement.getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS, EncryptionConstants._TAG_ENCRYPTIONMETHOD).item(0)
		encryptionMethod.setAttribute(EncryptionConstants._ATT_ALGORITHM, "INVALID")
		
		xmlEncrypter.verifyCiphers(encryptedElement)
		then:
		thrown MessageContentException
	}

	def "Verify that correct method is used if message security provider is ContextMessageSecurityProvider"(){
		setup:
		ContextMessageSecurityProvider.Context c = new ContextMessageSecurityProvider.Context("SomeUsage")
		ContextMessageSecurityProvider securityProvider = Mock(ContextMessageSecurityProvider)

		xmlEncrypter.encKeyXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256.getKeyEncryptionAlgorithmURI())
		xmlEncrypter.encDataXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256.getDataEncryptionAlgorithmURI())
		def encDoc = genComplexSAMLWithToEncryptedData()

		when:
		XMLEncrypter x = new XMLEncrypter(securityProvider, assertionPayloadParser.getDocumentBuilder(),
				assertionPayloadParser.getAssertionMarshaller(),
				assertionPayloadParser.getAssertionUnmarshaller())
		x.decryptDoc(c, encDoc,new EncryptedAttributeXMLConverter())
		then:
		2 * securityProvider.getDecryptionKeyIds(c) >> xmlEncrypter.securityProvider.getDecryptionKeyIds()
		2 * securityProvider.getDecryptionKey(c,!null) >> xmlEncrypter.securityProvider.getDecryptionKey(null)

	}

	def "Verify that correct method is used if message security provider is ContextMessageSecurityProvider with default context"(){
		setup:
		ContextMessageSecurityProvider.Context c = ContextMessageSecurityProvider.DEFAULT_CONTEXT
		ContextMessageSecurityProvider securityProvider = Mock(ContextMessageSecurityProvider)

		xmlEncrypter.encKeyXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256.getKeyEncryptionAlgorithmURI())
		xmlEncrypter.encDataXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256.getDataEncryptionAlgorithmURI())
		def encDoc = genComplexSAMLWithToEncryptedData()

		when:
		XMLEncrypter x = new XMLEncrypter(securityProvider, assertionPayloadParser.getDocumentBuilder(),
				assertionPayloadParser.getAssertionMarshaller(),
				assertionPayloadParser.getAssertionUnmarshaller())
		x.decryptDoc(c, encDoc,new EncryptedAttributeXMLConverter())
		then:
		2 * securityProvider.getDecryptionKeyIds(c) >> xmlEncrypter.securityProvider.getDecryptionKeyIds()
		2 * securityProvider.getDecryptionKey(c,!null) >> xmlEncrypter.securityProvider.getDecryptionKey(null)

	}

	def "Verify that correct method is used if message security provider is MessageSecurityProvider"(){
		setup:
		MessageSecurityProvider	 securityProvider = Mock(MessageSecurityProvider)

		xmlEncrypter.encKeyXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256.getKeyEncryptionAlgorithmURI())
		xmlEncrypter.encDataXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256.getDataEncryptionAlgorithmURI())
		def encDoc = genComplexSAMLWithToEncryptedData()

		when:
		XMLEncrypter x = new XMLEncrypter(securityProvider, assertionPayloadParser.getDocumentBuilder(),
				assertionPayloadParser.getAssertionMarshaller(),
				assertionPayloadParser.getAssertionUnmarshaller())

		x.decryptDoc(encDoc,new EncryptedAttributeXMLConverter())
		then:
		2 * securityProvider.getDecryptionKeyIds() >> xmlEncrypter.securityProvider.getDecryptionKeyIds()
		2 * securityProvider.getDecryptionKey(!null) >> xmlEncrypter.securityProvider.getDecryptionKey(null)

	}

	def "Verify that getHSMProvider is called if message security provider is HSMMessageSecurityProvider"() {
		setup:
		MessageSecurityProvider	 securityProvider = Mock(HSMMessageSecurityProvider)

		xmlEncrypter.encKeyXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256.getKeyEncryptionAlgorithmURI())
		xmlEncrypter.encDataXMLCipherMap[ContextMessageSecurityProvider.DEFAULT_CONTEXT]  = XMLCipher.getInstance(EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256.getDataEncryptionAlgorithmURI())
		def encDoc = genComplexSAMLWithToEncryptedData()

		when:
		XMLEncrypter x = new XMLEncrypter(securityProvider, assertionPayloadParser.getDocumentBuilder(),
				assertionPayloadParser.getAssertionMarshaller(),
				assertionPayloadParser.getAssertionUnmarshaller())

		x.decryptDoc(encDoc,new EncryptedAttributeXMLConverter())
		then:
		2 * securityProvider.getDecryptionKeyIds(_) >> xmlEncrypter.securityProvider.getDecryptionKeyIds()
		2 * securityProvider.getDecryptionKey(_,!null) >> xmlEncrypter.securityProvider.getDecryptionKey(null)
		2 * securityProvider.getHSMProvider() >> "BC"
	}

	def "Verify getScheme() calls correct method in message security provider"(){
		setup:
		ContextMessageSecurityProvider.Context c = new ContextMessageSecurityProvider.Context("SomeUsage")
		MessageSecurityProvider	securityProvider = Mock(MessageSecurityProvider)
		when:
		XMLEncrypter x = new XMLEncrypter(securityProvider, assertionPayloadParser.getDocumentBuilder(),
				assertionPayloadParser.getAssertionMarshaller(),
				assertionPayloadParser.getAssertionUnmarshaller())
		x.getScheme(c)
		then:
		1 * securityProvider.getEncryptionAlgorithmScheme()

	}

	def "Verify getScheme() calls correct method in context message security provider"(){
		setup:
		ContextMessageSecurityProvider.Context c = new ContextMessageSecurityProvider.Context("SomeUsage")
		MessageSecurityProvider	securityProvider = Mock(ContextMessageSecurityProvider)
		when:
		XMLEncrypter x = new XMLEncrypter(securityProvider, assertionPayloadParser.getDocumentBuilder(),
				assertionPayloadParser.getAssertionMarshaller(),
				assertionPayloadParser.getAssertionUnmarshaller())
		x.getScheme(c)
		then:
		1 * securityProvider.getEncryptionAlgorithmScheme(c)
	}

	def "Verify that getEncDataXMLCipher generates correct XMLChipher and stores it in cache"(){
		setup:
		ContextMessageSecurityProvider.Context c = new ContextMessageSecurityProvider.Context("SomeUsage")
		MessageSecurityProvider	securityProvider = Mock(ContextMessageSecurityProvider)
		XMLEncrypter x = new XMLEncrypter(securityProvider, assertionPayloadParser.getDocumentBuilder(),
				assertionPayloadParser.getAssertionMarshaller(),
				assertionPayloadParser.getAssertionUnmarshaller())
		expect:
		x.encDataXMLCipherMap[c] == null
		when:
		XMLCipher xc= x.getEncDataXMLCipher(c)
		then:
		xc != null
		1 * securityProvider.getEncryptionAlgorithmScheme(c) >> EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256
		x.encDataXMLCipherMap[c] != null
	}

	def "Verify that getEncKeyXMLCipher generates correct key generator and stores it in cache"(){
		setup:
		ContextMessageSecurityProvider.Context c = new ContextMessageSecurityProvider.Context("SomeUsage")
		MessageSecurityProvider	securityProvider = Mock(ContextMessageSecurityProvider)
		XMLEncrypter x = new XMLEncrypter(securityProvider, assertionPayloadParser.getDocumentBuilder(),
				assertionPayloadParser.getAssertionMarshaller(),
				assertionPayloadParser.getAssertionUnmarshaller())
		expect:
		x.encKeyXMLCipherMap[c] == null
		when:
		XMLCipher xc= x.getEncKeyXMLCipher(c)
		then:
		xc != null
		1 * securityProvider.getEncryptionAlgorithmScheme(c) >> EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256
		x.encKeyXMLCipherMap[c] != null
	}

	def "Verify that getDataKeyGenerator generates correct key generator and stores it in cache"(){
		setup:
		ContextMessageSecurityProvider.Context c = new ContextMessageSecurityProvider.Context("SomeUsage")
		MessageSecurityProvider	securityProvider = Mock(ContextMessageSecurityProvider)
		XMLEncrypter x = new XMLEncrypter(securityProvider, assertionPayloadParser.getDocumentBuilder(),
				assertionPayloadParser.getAssertionMarshaller(),
				assertionPayloadParser.getAssertionUnmarshaller())
		expect:
		x.dataKeyGeneratorMap[c] == null
		when:
		KeyGenerator kg = x.getDataKeyGenerator(c)
		then:
		kg != null
		1 * securityProvider.getEncryptionAlgorithmScheme(c) >> EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256
		x.dataKeyGeneratorMap[c] != null
	}
	
	private def genSAMLAttribute(String name, String value){
		AttributeType attributeType1 = of.createAttributeType()
		attributeType1.getAttributeValue().add(value)
		attributeType1.setName(name)
		return of.createAttribute(attributeType1)
		
	}
	
	private String docToString(Document doc) throws Exception {

		ByteArrayOutputStream bo = new ByteArrayOutputStream()

		TransformerFactory factory = TransformerFactory.newInstance()
		Transformer transformer = factory.newTransformer()
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes")
		transformer.setOutputProperty(OutputKeys.INDENT, "yes")
		DOMSource source = new DOMSource(doc)
		StreamResult result = new StreamResult(bo)
		transformer.transform(source, result)

		bo.close()
		return new String(bo.toByteArray(),"UTF-8")
				
	}
	
	private Document docToStringToDoc(Document doc) throws Exception{
		return xmlEncrypter.documentBuilder.parse(new ByteArrayInputStream(docToString(doc).getBytes("UTF-8")))
	}

    private Document updateKeyInfoWithRetrievalMethod(Document document){
		NodeList keyInfoList = document.getElementsByTagNameNS(XMLDSIG_NAMESPACE, "KeyInfo")
		if (keyInfoList.getLength() == 0) {
			throw new MessageContentException("No KeyInfo found in encrypted element")
		}

		for(int i=0;i<keyInfoList.length;i++){
			Element keyInfoElement = keyInfoList.item(i)
			NodeList encryptedKeyList = keyInfoElement.getElementsByTagNameNS(XMLEncrypter.XMLENC_NAMESPACE, "EncryptedKey")
			int listsize = encryptedKeyList.getLength()
			List elementsToBeMoved = []
			for (int j=0; j < encryptedKeyList.getLength(); j++) {
				String keyId = genRandomId()

				// Mark EncryptedKey to be moved.
				Element encryptedKeyElement = (Element)encryptedKeyList.item(j)
				encryptedKeyElement.setAttribute("Id", "${keyId}")
				elementsToBeMoved.add(encryptedKeyElement)

				// Add RetrievalMethod to KeyInfo with reference to the EncryptedKey.
				Element retrievalMethodElement = document.createElementNS(XMLDSIG_NAMESPACE, "ds:RetrievalMethod")
				retrievalMethodElement.setAttribute("Type", "http://www.w3.org/2001/04/xmlenc#EncryptedKey")
				retrievalMethodElement.setAttribute("URI", "#${keyId}")
				keyInfoElement.appendChild(retrievalMethodElement)
			}

			// Move all EncryptedKey elements from KeyInfo and make them
			// siblings of EncryptedData.
			elementsToBeMoved.each {
				Element encryptedDataElement = keyInfoElement.parentNode
				Element sharedParentElement = encryptedDataElement.parentNode
				sharedParentElement.appendChild(it)
			}
		}

		return document
    }

	private String genRandomId() {
		return "_${MessageDigest.getInstance("MD5").digest(UUID.randomUUID().toString().bytes).encodeHex()}"
	}

    private Document genComplexSAMLWithToEncryptedData(){
        return genComplexSAMLWithToEncryptedData(XMLEncrypter.KeyInfoType.KEYNAME)
    }

	private Document genComplexSAMLWithToEncryptedData(XMLEncrypter.KeyInfoType keyInfoType){
		NameIDType nameIdType = of.createNameIDType()
		nameIdType.setValue("SomeIssuer")
		
		JAXBElement<EncryptedDataType> encDataElement1 = xmlEncrypter.unmarshaller.unmarshal(xmlEncrypter.encryptElement(DEFAULT_CONTEXT, genSAMLAttribute("SomeAttribute1","Hej Svejs1" ), twoReceiptiensValidLast, keyInfoType))
		JAXBElement<EncryptedDataType> encDataElement2 = xmlEncrypter.unmarshaller.unmarshal(xmlEncrypter.encryptElement(DEFAULT_CONTEXT, genSAMLAttribute("SomeAttribute2","Hej Svejs2" ), twoReceiptiensValidLast, keyInfoType))
		
		EncryptedElementType encryptedElementType1 = of.createEncryptedElementType()
		encryptedElementType1.setEncryptedData(encDataElement1.getValue())

		EncryptedElementType encryptedElementType2 = of.createEncryptedElementType()
		encryptedElementType2.setEncryptedData(encDataElement2.getValue())

		AttributeStatementType attributeStatementType = of.createAttributeStatementType()
		attributeStatementType.attributeOrEncryptedAttribute.add(encryptedElementType1)
		attributeStatementType.attributeOrEncryptedAttribute.add(encryptedElementType2)
			
		AssertionType assertionType = of.createAssertionType()
		assertionType.setID("_" +MessageGenerateUtils.generateRandomUUID())
		assertionType.setIssueInstant(MessageGenerateUtils.dateToXMLGregorianCalendar(new Date()))
		assertionType.setIssuer(nameIdType)
		assertionType.setVersion("2.0")
		assertionType.getStatementOrAuthnStatementOrAuthzDecisionStatement().add(attributeStatementType)
	
		def assertion = of.createAssertion(assertionType)
		
		byte[] signedAssertion = assertionPayloadParser.marshallAndSignAssertion(assertion)
		
		//println new String(signedAssertion,"UTF-8")
		return xmlEncrypter.documentBuilder.parse(new ByteArrayInputStream(signedAssertion))
	}

	byte[] createSimpleSignedAssertion(){
		NameIDType nameIdType = of.createNameIDType()
		nameIdType.setValue("SomeIssuer")

		AttributeStatementType attributeStatementType = of.createAttributeStatementType()
		attributeStatementType.attributeOrEncryptedAttribute.add(genSAMLAttribute("SomeAttribute1","Hej Svejs1" ).value)

		AssertionType assertionType = of.createAssertionType()
		assertionType.setID("_" +MessageGenerateUtils.generateRandomUUID())
		assertionType.setIssueInstant(MessageGenerateUtils.dateToXMLGregorianCalendar(new Date()))
		assertionType.setIssuer(nameIdType)
		assertionType.setVersion("2.0")
		assertionType.getStatementOrAuthnStatementOrAuthzDecisionStatement().add(attributeStatementType)

		def assertion = of.createAssertion(assertionType)

		return assertionPayloadParser.marshallAndSignAssertion(assertion)
	}

	def testcertdata1 = Base64.decode("""MIIDcTCCAlmgAwIBAgIEZf08dzANBgkqhkiG9w0BAQsFADBpMRAwDgYDVQQGEwdVbmtub3duMRAw
DgYDVQQIEwdVbmtub3duMRAwDgYDVQQHEwdVbmtub3duMRAwDgYDVQQKEwd0ZXN0b3JnMRAwDgYD
VQQLEwdVbmtub3duMQ0wCwYDVQQDEwRrZXkxMB4XDTE1MDcwNjEwNDYwMloXDTM1MDMyMzEwNDYw
MlowaTEQMA4GA1UEBhMHVW5rbm93bjEQMA4GA1UECBMHVW5rbm93bjEQMA4GA1UEBxMHVW5rbm93
bjEQMA4GA1UEChMHdGVzdG9yZzEQMA4GA1UECxMHVW5rbm93bjENMAsGA1UEAxMEa2V5MTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKEFZfEUkqVw3fe9YfPuK+X/GdAJgw2zvZ8QNY3J
X/dJjMjefjDlZIkAM1zaVzjxiu94UhrS/CEL+ouLWgRi3dvtOYCsilkTjl6NPKwPFkU1EfRVOVnP
aJoaqeLLvDck+iN/f+0xtOd1YY6vZZivPeXAOIonMWprxzaFUi///1tL5QSQ09FUR6EHNPtFk8Aj
CGF7j7Y1DCwayfYYe5auyPvRNbJ2IkmEemrWina8uV6v2gqIhjj3HPe8idUkQfsbd7Cn5036ETLb
NIHCF9MhAQO4VvScmucaZZcbJAsc6uJ/djCX5Omfqm2E7DWpDQDHKLG1fln65txJpPa23WTa5fEC
AwEAAaMhMB8wHQYDVR0OBBYEFM1cn0IBTznpUe1AXJKrOrvsoofRMA0GCSqGSIb3DQEBCwUAA4IB
AQCPuSHK/1NX+nWby67SRC/xYpYenLqyjh6vdrxA8AfqOuZq0HNoGPmAQc6HQn3aX1FJ+6sViohl
1SqI38F9raB8Opqg8e0zONEZV1FNtS2V7Sx/IA0WcxnsoMuWReYKqVR+yffqsgn89q3MUWwuD9Yx
sSRjPxCeBd7arAgZv72PriiqxvvFCGoXrX5Prng8euS/gIeDQZBNEWC3MzbLty8QwMqKFd0+V2fz
LaRMArYLp0nS3TwF24KdgaKuSyA0nq1j/ZNyi/TowrNPA4FLE2f/1akjn3mvgpn62XQoPO1BfZCq
utkUJrOx5P7ZIr91erXUfsQbPDsQkcjAi3IPJFAr""")
	
	def testchipherdata1 = """DOFOukwwk3Xj0J0LJ3op/MLQh/HeeGj4KkKKUchLOKc6LJvGfLIpN1QqT9DAY1rmpMQYu0H7JOPu
        JRAX63XUD5XV5KXfSXS2G23/oQcVelRbUjtdDa9RivbkNZo2SjkgsNxyhj2kVkUDok7yT5Qxrg85
        eHRIWoTVzjuwzS4duHzkje0wS7oc/Iuq7Rb1W1D2/l1YWOSKmThBh1GafmHaDLzxcgFdmn3dfVp7
        wfnYQU96dseWUgBUHfZKLewQCZOwz2IywrHuHdxjGEc4dOgHw4mV/ePLxiJAeCPjxkg4+ZgBaiZH
        JhkQQOYbPIcTvePsleUVfc2hq2RWCd9rpsHjZA=="""
	
	static byte[] base64Cert =("MIIDLTCCAhWgAwIBAgIIYmVP6xQ/t3QwDQYJKoZIhvcNAQEFBQAwJDETMBEGA1UE" +
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
		"Vw==").getBytes()




}
