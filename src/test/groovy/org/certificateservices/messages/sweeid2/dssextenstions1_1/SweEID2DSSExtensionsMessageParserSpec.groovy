package org.certificateservices.messages.sweeid2.dssextenstions1_1

import org.bouncycastle.util.encoders.Base64
import org.certificateservices.messages.ContextMessageSecurityProvider
import org.certificateservices.messages.csmessages.DefaultCSMessageParser
import org.certificateservices.messages.dss1.core.DSS1CoreMessageParser
import org.certificateservices.messages.dss1.core.ResultMajorValues
import org.certificateservices.messages.dss1.core.jaxb.SignRequest
import org.certificateservices.messages.dss1.core.jaxb.SignResponse
import org.certificateservices.messages.saml2.BaseSAMLMessageParser
import org.certificateservices.messages.saml2.CommonSAMLMessageParserSpecification
import org.certificateservices.messages.saml2.assertion.jaxb.AttributeStatementType
import org.certificateservices.messages.saml2.assertion.jaxb.AttributeType
import org.certificateservices.messages.saml2.assertion.jaxb.ConditionsType
import org.certificateservices.messages.saml2.assertion.jaxb.NameIDType
import org.certificateservices.messages.sweeid2.dssextenstions1_1.jaxb.*
import org.w3c.dom.Document
import org.w3c.dom.Element

import javax.xml.bind.JAXBElement
import javax.xml.namespace.QName

import static org.certificateservices.messages.TestUtils.printXML
import static org.certificateservices.messages.TestUtils.slurpXml
import static org.certificateservices.messages.ContextMessageSecurityProvider.DEFAULT_CONTEXT

class SweEID2DSSExtensionsMessageParserSpec extends CommonSAMLMessageParserSpecification {

	SweEID2DSSExtensionsMessageParser emp = new SweEID2DSSExtensionsMessageParser()

	def dssOf = new org.certificateservices.messages.dss1.core.jaxb.ObjectFactory();
	def eidOf = new org.certificateservices.messages.sweeid2.dssextenstions1_1.jaxb.ObjectFactory();

	def currentDate

	def setup() {
		emp.init(secProv);
		emp.systemTime = mockedSystemTime

		currentDate = emp.systemTime.systemTime

	}
	def "Verify that JAXBPackages(), getNameSpace(), getSignatureLocationFinder(), getDefaultSchemaLocations(), getOrganisationLookup() returns the correct values"(){
		expect:
		emp.getJAXBPackages() == SweEID2DSSExtensionsMessageParser.BASE_JAXB_CONTEXT + ":" + DSS1CoreMessageParser.BASE_JAXB_CONTEXT
		emp.getNameSpace() == SweEID2DSSExtensionsMessageParser.NAMESPACE
		emp.getSignatureLocationFinder() != null
		emp.getDefaultSchemaLocations().length== 6
		emp.getOrganisationLookup() == null
		emp.lookupSchemaForElement(null, DSS1CoreMessageParser.NAMESPACE, null, null, null) == DSS1CoreMessageParser.DSS_XSD_SCHEMA_1_0_RESOURCE_LOCATION
		emp.lookupSchemaForElement(null, DefaultCSMessageParser.XMLDSIG_NAMESPACE, null, null, null) == DefaultCSMessageParser.XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION
		emp.lookupSchemaForElement(null, DSS1CoreMessageParser.SAML_1_1_NAMESPACE, null, null, null) == DSS1CoreMessageParser.ASSERTION_XSD_SCHEMA_1_1_RESOURCE_LOCATION
		emp.lookupSchemaForElement(null, SweEID2DSSExtensionsMessageParser.NAMESPACE, null, null, null) == SweEID2DSSExtensionsMessageParser.SWEEID_DSS_EXTENSTIONS_XSD_SCHEMA_1_1_RESOURCE_LOCATION
		emp.lookupSchemaForElement(null, SweEID2DSSExtensionsMessageParser.ASSERTION_NAMESPACE, null, null, null) == BaseSAMLMessageParser.ASSERTION_XSD_SCHEMA_2_0_RESOURCE_LOCATION
		emp.lookupSchemaForElement(null, DefaultCSMessageParser.XMLENC_NAMESPACE, null, null, null) == DefaultCSMessageParser.XMLENC_XSD_SCHEMA_RESOURCE_LOCATION
	}

	def "Generate SignRequestExtension and populate it to a SignRequest and verify that saml1 and saml2 prefix namespacing is correct."(){
		setup:
		JAXBElement<SignRequestExtensionType> signRequestExtension = emp.genSignRequestExtension("1.5", currentDate, createConditions(), createAttributeStatement(),
				"SomeIdentityProvider", "SomeSignRequest", "SomeSignService",
				"SomeRequestedSignatureAlgorithm", createSignMessage(), createCertRequestProperties(),
				createOtherRequestInfo())
		JAXBElement<SignTasksType> signTasks = emp.genSignTasks([emp.genSignTaskData(null,SigType.ASiC, null,null,
				"tobesigned1".bytes, null, null,null, null),emp.genSignTaskData(null,SigType.CMS, null,null,
				"tobesigned2".bytes, null, null,null, null)])
		when:
		byte[] data = emp.genSignRequest(DEFAULT_CONTEXT,"SomeRequestId","SomeProfile", signRequestExtension,signTasks, true);
		Document xmlDoc = emp.getDocumentBuilder().parse(new ByteArrayInputStream(data))
		Element signRequestElement = xmlDoc.getDocumentElement()
		Element signRequestExtensionElement = xmlDoc.getElementsByTagNameNS(SweEID2DSSExtensionsMessageParser.NAMESPACE,"SignRequestExtension").item(0)
		Element signTasksElement = xmlDoc.getElementsByTagNameNS(SweEID2DSSExtensionsMessageParser.NAMESPACE,"SignTasks").item(0)
		//printXML(data)
		def xml = slurpXml(data)
		then:
		// Check namespacing is correct.
		signRequestElement.getAttributeNode("xmlns:saml").value == "urn:oasis:names:tc:SAML:1.0:assertion"
		signRequestElement.getAttributeNode("xmlns:dss").value == "urn:oasis:names:tc:dss:1.0:core:schema"
		signRequestElement.getAttributeNode("xmlns:ds").value == "http://www.w3.org/2000/09/xmldsig#"

		signRequestExtensionElement.getAttributeNode("xmlns:csig").value == "http://id.elegnamnden.se/csig/1.1/dss-ext/ns"
		signRequestExtensionElement.getAttributeNode("xmlns:saml").value == "urn:oasis:names:tc:SAML:2.0:assertion"
		signRequestExtensionElement.getAttributeNode("xmlns:xenc").value == "http://www.w3.org/2001/04/xmlenc#"

		signTasksElement.getAttributeNode("xmlns:csig").value == "http://id.elegnamnden.se/csig/1.1/dss-ext/ns"
		signTasksElement.getAttributeNode("xmlns:saml").value == "urn:oasis:names:tc:SAML:2.0:assertion"
		signTasksElement.getAttributeNode("xmlns:xenc").value == "http://www.w3.org/2001/04/xmlenc#"

		xml.@Profile == "SomeProfile"
		xml.@RequestID == "SomeRequestId"
		xml.OptionalInputs.SignRequestExtension.size() == 1
		xml.OptionalInputs.Signature.size() == 1
		xml.InputDocuments.Other.SignTasks.SignTaskData.size() == 2

		when:
		SignRequest sr = emp.parseMessage(DEFAULT_CONTEXT,data, true)
		then:
		sr.requestID == "SomeRequestId"
		sr.optionalInputs.any.get(0) instanceof JAXBElement<SignRequestExtensionType>

		when: "Try unsigned"
		data = emp.genSignRequest(DEFAULT_CONTEXT,"SomeRequestId","SomeProfile", signRequestExtension,signTasks, false);
		//printXML(data)
		xml = slurpXml(data)
		then:
		xml.@Profile == "SomeProfile"
		xml.@RequestID == "SomeRequestId"
		xml.OptionalInputs.SignRequestExtension.size() == 1
		xml.OptionalInputs.Signature.size() == 0
		xml.InputDocuments.Other.SignTasks.SignTaskData.size() == 2

		when:
		sr = emp.parseMessage(DEFAULT_CONTEXT,data, false)
		then:
		sr.requestID == "SomeRequestId"
	}

	def "Generate SignResponseExtension and populate it to a SignResponse and verify that saml1 and saml2 prefix namespacing is correct."(){
		setup:
		JAXBElement<SignRequestExtensionType> signRequestExtension = emp.genSignRequestExtension("1.5", currentDate, createConditions(), createAttributeStatement(),
				"SomeIdentityProvider", "SomeSignRequest", "SomeSignService",
				"SomeRequestedSignatureAlgorithm", createSignMessage(), createCertRequestProperties(),
				createOtherRequestInfo())
		JAXBElement<SignTasksType> signTasks = emp.genSignTasks([emp.genSignTaskData(null,SigType.ASiC, null,null,
				"tobesigned1".bytes, null, null,null, null),emp.genSignTaskData(null,SigType.CMS, null,null,
				"tobesigned2".bytes, null, null,null, null)])
		byte[] signRequestData = emp.genSignRequest(DEFAULT_CONTEXT,"SomeRequestId","SomeProfile", signRequestExtension,signTasks, true);

		JAXBElement<SignTasksType> responseSignTasks = emp.genSignTasks([emp.genSignTaskData(null,SigType.ASiC, null,null,
				"tobesigned3".bytes, null, null,null, null),emp.genSignTaskData(null,SigType.CMS, null,null,
				"tobesigned4".bytes, null, null,null, null)])

		when:
		JAXBElement<SignResponseExtensionType> resp = emp.genSignResponseExtension("1.5",currentDate,signRequestData,emp.genSignerAssertionInfo(createContextInfo(), createAttributeStatement(), null),
				twoReceiptiensValidFirst, createOtherResponseInfo());
		byte[] data = emp.genSignResponse(DEFAULT_CONTEXT,"SomeRequestId","SomeProfile", emp.genResult(ResultMajorValues.Success,null,null,null),resp,responseSignTasks,true)
		Document xmlDoc = emp.getDocumentBuilder().parse(new ByteArrayInputStream(data))
		Element signRequestElement = xmlDoc.getDocumentElement()
		Element signResponseExtensionElement = xmlDoc.getElementsByTagNameNS(SweEID2DSSExtensionsMessageParser.NAMESPACE,"SignResponseExtension").item(0)
		Element signTasksElement = xmlDoc.getElementsByTagNameNS(SweEID2DSSExtensionsMessageParser.NAMESPACE,"SignTasks").item(0)
		//printXML(data);
		def xml = slurpXml(data)
		then:
		// Check namespacing is correct.
		signRequestElement.getAttributeNode("xmlns:saml").value == "urn:oasis:names:tc:SAML:1.0:assertion"
		signRequestElement.getAttributeNode("xmlns:dss").value == "urn:oasis:names:tc:dss:1.0:core:schema"
		signRequestElement.getAttributeNode("xmlns:ds").value == "http://www.w3.org/2000/09/xmldsig#"

		signResponseExtensionElement.getAttributeNode("xmlns:csig").value == "http://id.elegnamnden.se/csig/1.1/dss-ext/ns"
		signResponseExtensionElement.getAttributeNode("xmlns:saml").value == "urn:oasis:names:tc:SAML:2.0:assertion"
		signResponseExtensionElement.getAttributeNode("xmlns:xenc").value == "http://www.w3.org/2001/04/xmlenc#"

		signTasksElement.getAttributeNode("xmlns:csig").value == "http://id.elegnamnden.se/csig/1.1/dss-ext/ns"
		signTasksElement.getAttributeNode("xmlns:saml").value == "urn:oasis:names:tc:SAML:2.0:assertion"
		signTasksElement.getAttributeNode("xmlns:xenc").value == "http://www.w3.org/2001/04/xmlenc#"

		xml.@Profile == "SomeProfile"
		xml.@RequestID == "SomeRequestId"
		xml.Result.ResultMajor == "urn:oasis:names:tc:dss:1.0:resultmajor:Success"
		xml.OptionalOutputs.SignResponseExtension.size() == 1
		xml.OptionalOutputs.Signature.size() == 1
		xml.SignatureObject.Other.SignTasks.SignTaskData.size() == 2

		when:
		SignResponse sr = emp.parseMessage(DEFAULT_CONTEXT,data, true)
		then:
		sr.requestID == "SomeRequestId"
		sr.optionalOutputs.any.get(0) instanceof JAXBElement<SignResponseExtensionType>

		when: "Try unsigned"
		data = emp.genSignResponse(DEFAULT_CONTEXT,"SomeRequestId","SomeProfile", emp.genResult(ResultMajorValues.Success,null,null,null),resp,responseSignTasks,false)
		//printXML(data)
		xml = slurpXml(data)
		then:
		xml.@Profile == "SomeProfile"
		xml.@RequestID == "SomeRequestId"
		xml.OptionalOutputs.SignResponseExtension.size() == 1
		xml.OptionalOutputs.Signature.size() == 0
		xml.SignatureObject.Other.SignTasks.SignTaskData.size() == 2

		when:
		sr = emp.parseMessage(DEFAULT_CONTEXT,data, false)
		then:
		sr.requestID == "SomeRequestId"
	}

	def "Verify that genSignRequestExtension populates data structure correctly"() {
		when:  "Generate full data structure"
		JAXBElement<SignRequestExtensionType> t = emp.genSignRequestExtension("1.5", currentDate, createConditions(), createAttributeStatement(),
				"SomeIdentityProvider", "SomeSignRequest", "SomeSignService",
				"SomeRequestedSignatureAlgorithm", createSignMessage(), createCertRequestProperties(),
				createOtherRequestInfo())
		byte[] d = emp.marshall(t)
		//printXML(d);
		def xml = slurpXml(d)
		then:
		xml.@Version == "1.5"
		xml.RequestTime == "2015-07-07T16:26:53.000+02:00"
		xml.Conditions.size() == 1
		xml.Signer.Attribute.size() == 2
		xml.IdentityProvider == "SomeIdentityProvider"
		xml.IdentityProvider.@Format == "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
		xml.SignRequester == "SomeSignRequest"
		xml.SignService == "SomeSignService"
		xml.RequestedSignatureAlgorithm == "SomeRequestedSignatureAlgorithm"
		xml.CertRequestProperties.size() == 1
		xml.OtherRequestInfo.KeyName.size() == 2
		xml.OtherRequestInfo.KeyName[0] == "SomeKeyName7"

		when:
		SignRequestExtensionType t2 = emp.parseMessage(DEFAULT_CONTEXT,d, false)
		then:
		t2.version == "1.5"

		when:  "Generate minimal data structure"
		t = emp.genSignRequestExtension(null, currentDate, createConditions(), null,
				"SomeIdentityProvider", "SomeSignRequest", "SomeSignService",
				null, null, null,
				null)
		d = emp.marshall(t)
		//printXML(d);
		xml = slurpXml(d)
		then:
		xml.@Version != "1.5"


		when:
		t2 = emp.parseMessage(DEFAULT_CONTEXT,d, false)
		then:
		t2.version == "1.1"
	}



	def "Verify that genBasicConditions populates data structure correctly"(){
		when:
		ConditionsType t = emp.genBasicConditions(currentDate, new Date(currentDate.time + 1000), "SomeAudience")
		byte[] d = emp.marshall(of.createConditions(t))
		//printXML(d);
		def xml = slurpXml(d)
		then:
		xml.@NotBefore == "2015-07-07T16:26:53.000+02:00"
		xml.@NotOnOrAfter == "2015-07-07T16:26:54.000+02:00"
		xml.AudienceRestriction.Audience == "SomeAudience"
	}

	def "Verify that genCertRequestProperties populates data structure correctly"(){
		when:
		CertRequestPropertiesType t = emp.genCertRequestProperties(CertType.QC,"SomeAuthnContextClassRef", createRequestedCertAttributes(), createOtherProperties())
		byte[] d = emp.marshall(eidOf.createCertRequestProperties(t))
		//printXML(d);
		def xml = slurpXml(d)
		then:
		xml.@CertType == "QC"
		xml.AuthnContextClassRef == "SomeAuthnContextClassRef"
		xml.RequestedCertAttributes.RequestedCertAttribute.size() == 2
		xml.OtherProperties.KeyName.size() == 2

		when:
		t = emp.parseMessage(DEFAULT_CONTEXT,d, false)
		then:
		t.certType ==  "QC"

		when: "Try to generate minimal data structure"
		t = emp.genCertRequestProperties(null,null,null,null)
		d = emp.marshall(eidOf.createCertRequestProperties(t))
		//printXML(d);
		xml = slurpXml(d)
		then:
		xml.@CertType.size() == 0

		when:
		t = emp.parseMessage(DEFAULT_CONTEXT,d, false)
		then:
		t.certType ==  "PKC"

	}

	def "Verify that genMappedAttribute populates data structure correctly"(){
		when: "Generate full data structure"
		MappedAttributeType t = emp.genMappedAttribute("SomeCertAttributeRef",CertNameType.rdn, "SomeFriendlyName","SomeDefaultValue",
		true, createAttributeAuthorities(), createSamlAttributeNames())
		then:
		t.certAttributeRef == "SomeCertAttributeRef"
		t.certNameType == CertNameType.rdn.name()
		t.friendlyName == "SomeFriendlyName"
		t.defaultValue == "SomeDefaultValue"
		t.required == true
		t.attributeAuthority.size() == 2
		t.samlAttributeName.size() == 2
	}

	def "Verify that genPreferredSAMLAttributeName populates data structure correctly"() {
		when: "Generate full data structure"
		PreferredSAMLAttributeNameType t = emp.genPreferredSAMLAttributeName(1, "SomeValue")
		then:
		t.order == 1
		t.value == "SomeValue"

	}

	def "Verify that genSignMessage populates data structure correctly"() {
		when: "Generate full data structure"
		SignMessageType t = emp.genSignMessage(true, "SomeDisplayEntity", SignMessageMimeType.HTML, "SomeMessage".getBytes("UTF-8"),
				createOtherAttributes());
		byte[] d = emp.marshall(eidOf.createSignMessage(t))
		//printXML(d);
		def xml = slurpXml(d)
		then:
		xml.@MustShow == true
		xml.@DisplayEntity == "SomeDisplayEntity"
		xml.@MimeType == "text/html"
		xml.@"ds:Algorithm" == "http://somealg"
		xml.Message == "U29tZU1lc3NhZ2U="

		when:
		t = emp.parseMessage(DEFAULT_CONTEXT,d, false)
		then:
		t.mustShow == true

		when: "Generate minimal data structure"
		t = emp.genSignMessage(null, null, null, "SomeMessage".getBytes("UTF-8"),
				null);
		d = emp.marshall(eidOf.createSignMessage(t))
		//printXML(d);
		xml = slurpXml(d)
		then:

		xml.Message == "U29tZU1lc3NhZ2U="

		when:
		t = emp.parseMessage(DEFAULT_CONTEXT,d, false)
		then:
		t.mustShow == false

		when: "Test with encrypted message"
		t = emp.genSignEncryptedMessage(ContextMessageSecurityProvider.DEFAULT_CONTEXT,true, "SomeDisplayEntity", SignMessageMimeType.HTML, "SomeMessage".getBytes("UTF-8"),
				createOtherAttributes(), twoReceiptiensValidFirst);
		d = emp.marshall(eidOf.createSignMessage(t))
		//printXML(d);
		xml = slurpXml(d)
		then:
		xml.@MustShow == true
		xml.@DisplayEntity == "SomeDisplayEntity"
		xml.@MimeType == "text/html"
		xml.@"ds:Algorithm" == "http://somealg"
		xml.EncryptedMessage.size() == 1

		when:
		t = emp.parseMessage(DEFAULT_CONTEXT,d, false)
		then:
		t.encryptedMessage != null

		when: "Test to decrypt the message"
		t = emp.decryptSignMessageData(DEFAULT_CONTEXT,t)

		then:
		new String(t.message,"UTF-8") == "SomeMessage"

	}

	def "Verify that genSignResponseExtension populates data structure correctly"() {
		when: "Generate full data structure"
		JAXBElement<SignResponseExtensionType> t = emp.genSignResponseExtension("1.5", currentDate, createSignRequest(),
				emp.genSignerAssertionInfo(createContextInfo(), createAttributeStatement(), null),
				twoReceiptiensValidFirst, createOtherResponseInfo());
		byte[] d = emp.marshall(t)
		//printXML(d);
		def xml = slurpXml(d)
		then:
		xml.@Version == "1.5"
		xml.ResponseTime == "2015-07-07T16:26:53.000+02:00"
		xml.Request.size() == 1
		xml.SignerAssertionInfo.size() == 1
		xml.SignatureCertificateChain.X509Certificate.size() == 2
		xml.OtherResponseInfo.KeyName.size() == 2
		xml.OtherResponseInfo.KeyName[0] == "SomeKeyName3"

		when:
		SignResponseExtensionType t2 = emp.parseMessage(DEFAULT_CONTEXT,d, false)
		then:
		t2.version == "1.5"

		when: "Generate minimal data structure"
		t = emp.genSignResponseExtension(null, currentDate, null,
				null, null, null);
		d = emp.marshall(t)
		//printXML(d);
		xml = slurpXml(d)
		then:
		xml.ResponseTime == "2015-07-07T16:26:53.000+02:00"

		when:
		t2 = emp.parseMessage(DEFAULT_CONTEXT,d, false)
		then:
		t2.version == "1.1"
	}

	def "Verify that genSignerAssertionInfo populates data structure correctly"() {
		when: "Generate full data structure"
		SignerAssertionInfoType t = emp.genSignerAssertionInfo(createContextInfo(), createAttributeStatement(), createAssertions());
		byte[] d = emp.marshall(eidOf.createSignerAssertionInfo(t))
		//printXML(d);
		def xml = slurpXml(d)
		then:
		xml.ContextInfo.size() == 1
		xml.AttributeStatement.size() == 1
		xml.SamlAssertions.size() == 1

		when:
		t = emp.parseMessage(DEFAULT_CONTEXT,d, false)
		then:
		t.contextInfo != null

		when: "Generate minimal data structure"
		t = emp.genSignerAssertionInfo(createContextInfo(), createAttributeStatement(), null);
		d = emp.marshall(eidOf.createSignerAssertionInfo(t))
		//printXML(d);
		xml = slurpXml(d)

		then:
		xml.ContextInfo.size() == 1
		xml.AttributeStatement.size() == 1
		xml.SamlAssertions.size() == 0

		when:
		t = emp.parseMessage(DEFAULT_CONTEXT,d, false)
		then:
		t.contextInfo != null
	}

	def "Verify that genContextInfo populates data structure correctly"(){
		when: "Generate full data structure"

		ContextInfoType t = emp.genContextInfo(createIdentifyProvider(), currentDate, "SomeAuthnContextClassRef", "SomeServiceID", "SomeAuthType", "SomeAssertionRef")
		byte[] d = emp.marshall(eidOf.createContextInfo(t))
		//printXML(d);
		def xml = slurpXml(d)
		then:
		xml.IdentityProvider == "SomeIdentifyProvider"
		xml.AuthenticationInstant == "2015-07-07T16:26:53.000+02:00"
		xml.AuthnContextClassRef == "SomeAuthnContextClassRef"
		xml.ServiceID == "SomeServiceID"
		xml.AuthType == "SomeAuthType"
		xml.AssertionRef == "SomeAssertionRef"

		when:
		t = emp.parseMessage(DEFAULT_CONTEXT,d,false)
		then:
		t.serviceID == "SomeServiceID"

		when: "Generate minimal data structure"
		t = emp.genContextInfo(createIdentifyProvider(), currentDate, "SomeAuthnContextClassRef", null,null,null)
		d = emp.marshall(eidOf.createContextInfo(t))
		//printXML(d);
		xml = slurpXml(d)
		then:
		xml.IdentityProvider == "SomeIdentifyProvider"
		xml.AuthenticationInstant == "2015-07-07T16:26:53.000+02:00"
		xml.AuthnContextClassRef == "SomeAuthnContextClassRef"

		when:
		t = emp.parseMessage(DEFAULT_CONTEXT,d,false)
		then:
		t.authnContextClassRef == "SomeAuthnContextClassRef"

	}

	def "Verify that genSignTaskData populates data structure correctly"(){
		when: "Generate full data structure"
		SignTaskDataType t = emp.genSignTaskData("SomeSignTaskId",SigType.ASiC, AdESType.BES, "SomeProcessingRules",
		"tobesigned".bytes, createADESObject(), "signeddata".bytes, "CMS", createOtherSignTaskData())
		byte[] d = emp.marshall(eidOf.createSignTaskData(t))
		//printXML(d);
		def xml = slurpXml(d)
		then:
		xml.@SignTaskId == "SomeSignTaskId"
		xml.@SigType == "ASiC"
		xml.@AdESType == "BES"
		xml.@ProcessingRules == "SomeProcessingRules"
		xml.ToBeSignedBytes == new String(Base64.encode("tobesigned".bytes))
		xml.AdESObject.SignatureId == "SomeAdesSignatureID"
		xml.Base64Signature == new String(Base64.encode("signeddata".bytes))
		xml.Base64Signature.@Type == "CMS"
		xml.OtherSignTaskData.KeyName.size() == 2

		when: "try to parse"
		t = emp.parseMessage(DEFAULT_CONTEXT,d,false)
		then:
		t.signTaskId == "SomeSignTaskId"

		when: "Generate minimal data structure"
		t = emp.genSignTaskData(null,SigType.ASiC, null,null,
				"tobesigned".bytes, null, null,null, null)
		d = emp.marshall(eidOf.createSignTaskData(t))
		//printXML(d);
		xml = slurpXml(d)
		then:
		xml.@SigType == "ASiC"
		xml.ToBeSignedBytes == new String(Base64.encode("tobesigned".bytes))

		when: "try to parse"
		t = emp.parseMessage(DEFAULT_CONTEXT,d,false)
		then:
		t.sigType == "ASiC"

	}

	def "Verify that genSignTasks populates data structure correctly"(){
		when: "Generate data structure"
		JAXBElement<SignTasksType> t = emp.genSignTasks([emp.genSignTaskData(null,SigType.ASiC, null,null,
				"tobesigned1".bytes, null, null,null, null),emp.genSignTaskData(null,SigType.CMS, null,null,
				"tobesigned2".bytes, null, null,null, null)])
		byte[] d = emp.marshall(t)
		//printXML(d);
		def xml = slurpXml(d)
		then:
		xml.SignTaskData.size() == 2
		xml.SignTaskData[0].@SigType == "ASiC"
		xml.SignTaskData[1].@SigType == "CMS"

		when: "try to parse"
		SignTasksType t2 = emp.parseMessage(DEFAULT_CONTEXT,d,false)
		then:
		t2.signTaskData.size() == 2

	}

	private AdESObjectType createADESObject(){
		AdESObjectType t = eidOf.createAdESObjectType();
		t.signatureId = "SomeAdesSignatureID"
		return t
	}

	private List<Object> createOtherSignTaskData(){
		return [dsignObj.createKeyName("SomeKeyName1"),dsignObj.createKeyName("SomeKeyName2")]
	}

	private List<Object> createOtherResponseInfo(){
		return [dsignObj.createKeyName("SomeKeyName3"),dsignObj.createKeyName("SomeKeyName4")]
	}

	private NameIDType createIdentifyProvider(){
		NameIDType t = of.createNameIDType();
		t.setValue("SomeIdentifyProvider");
		return t;
	}

	private ContextInfoType createContextInfo(){
		return emp.genContextInfo(createIdentifyProvider(), currentDate, "SomeAuthnContextClassRef", null,null,null);
	}

	private AttributeStatementType createAttributeStatement(){
		AttributeType attr1 = of.createAttributeType();
		attr1.setName("SomeSAMLAttribute1")
		attr1.getAttributeValue().add("SomeValue1")
		AttributeType attr2 = of.createAttributeType();
		attr2.setName("SomeSAMLAttribute2")
		attr2.getAttributeValue().add("SomeValue2")
		AttributeStatementType t = of.createAttributeStatementType()
		t.attributeOrEncryptedAttribute.addAll([attr1,attr2])
		return t;
	}

	private List<Object> createAssertions(){
		return [samp.generateSimpleAssertion("SomeIssuer1", currentDate,currentDate,"SomeSubjectID", null),
				samp.generateSimpleAssertion("SomeIssuer2", currentDate,currentDate,"SomeSubjectID", null)]

	}

	private SignRequest createSignRequest(){
		return emp.genSignRequest(null,null, null,null)
	}

	private Map<QName,String> createOtherAttributes(){
		Map retval = [:]
		retval.put(new QName("http://www.w3.org/2000/09/xmldsig#","Algorithm"), "http://somealg")
		return retval
	}

	private List<NameIDType> createAttributeAuthorities(){
		NameIDType a1 = of.createNameIDType();
		a1.setValue("AttributeAuthority1");
		NameIDType a2 = of.createNameIDType();
		a2.setValue("AttributeAuthority2");
		return [a1,a2]
	}

	private List<PreferredSAMLAttributeNameType> createSamlAttributeNames(){
		return [emp.genPreferredSAMLAttributeName(1, "SomeValue1"),
				emp.genPreferredSAMLAttributeName(null, "SomeValue2")]
	}

	private createRequestedCertAttributes(){

		MappedAttributeType t1 = emp.genMappedAttribute("SomeCertAttributeRef",CertNameType.rdn, "SomeFriendlyName","SomeDefaultValue",
				true, createAttributeAuthorities(), createSamlAttributeNames())
		MappedAttributeType t2 = emp.genMappedAttribute(null,null, null,null,
				null, null, null)
		return [t1,t2]
	}

	private List<Object> createOtherProperties(){
		return [dsignObj.createKeyName("SomeKeyName5"),dsignObj.createKeyName("SomeKeyName6")]
	}

	private ConditionsType createConditions(){
		return emp.genBasicConditions(currentDate, new Date(currentDate.time + 1000), "SomeAudience")
	}

	private SignMessageType createSignMessage(){
		return emp.genSignMessage(true, "SomeDisplayEntity", SignMessageMimeType.HTML, "SomeMessage".getBytes("UTF-8"),
				createOtherAttributes());
	}

	private CertRequestPropertiesType createCertRequestProperties(){
		return emp.genCertRequestProperties(CertType.QC,"SomeAuthnContextClassRef", createRequestedCertAttributes(), createOtherProperties())
	}

	private List<Object> createOtherRequestInfo(){
		return [dsignObj.createKeyName("SomeKeyName7"),dsignObj.createKeyName("SomeKeyName8")]
	}
}
