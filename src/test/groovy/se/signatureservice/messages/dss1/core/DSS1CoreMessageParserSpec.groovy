package se.signatureservice.messages.dss1.core


import se.signatureservice.messages.MessageContentException
import se.signatureservice.messages.csmessages.DefaultCSMessageParser
import se.signatureservice.messages.dss1.core.jaxb.AnyType
import se.signatureservice.messages.dss1.core.jaxb.InputDocuments
import se.signatureservice.messages.dss1.core.jaxb.ObjectFactory
import se.signatureservice.messages.dss1.core.jaxb.ResponseBaseType
import se.signatureservice.messages.dss1.core.jaxb.SignRequest
import se.signatureservice.messages.dss1.core.jaxb.SignResponse
import se.signatureservice.messages.dss1.core.jaxb.SignatureObject
import se.signatureservice.messages.dss1.core.jaxb.VerifyRequest
import se.signatureservice.messages.saml2.CommonSAMLMessageParserSpecification

import jakarta.xml.bind.JAXBElement

import static se.signatureservice.messages.TestUtils.*
import static se.signatureservice.messages.ContextMessageSecurityProvider.DEFAULT_CONTEXT

class DSS1CoreMessageParserSpec extends CommonSAMLMessageParserSpecification {

	DSS1CoreMessageParser dmp = new DSS1CoreMessageParser()

	protected ObjectFactory dssOf = new ObjectFactory();

	def setup() {
		dmp.init(secProv);
		dmp.systemTime = mockedSystemTime

	}
	def "Verify that JAXBPackages(), getNameSpace(), getSignatureLocationFinder(), getDefaultSchemaLocations(), getOrganisationLookup() returns the correct values"(){
		expect:
		dmp.getJAXBPackages() == DSS1CoreMessageParser.BASE_JAXB_CONTEXT
		dmp.getNameSpace() == DSS1CoreMessageParser.NAMESPACE
		dmp.getSignatureLocationFinder() != null
		dmp.getDefaultSchemaLocations().length== 3
		dmp.getOrganisationLookup() == null
		dmp.lookupSchemaForElement(null, DSS1CoreMessageParser.NAMESPACE, null, null, null) == DSS1CoreMessageParser.DSS_XSD_SCHEMA_1_0_RESOURCE_LOCATION
		dmp.lookupSchemaForElement(null, DefaultCSMessageParser.XMLDSIG_NAMESPACE, null, null, null) == DefaultCSMessageParser.XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION
		dmp.lookupSchemaForElement(null, DSS1CoreMessageParser.SAML_1_1_NAMESPACE, null, null, null) == DSS1CoreMessageParser.ASSERTION_XSD_SCHEMA_1_1_RESOURCE_LOCATION
	}

	def "Verify that genSignRequest generates a valid data structure"(){
		when: "Generate full message"
		byte[] srd  = dmp.genSignRequest(DEFAULT_CONTEXT,"SomeRequestId","SomeProfile", createOptionalData(),createInputDocuments(), false)
		//printXML(srd)
		def xml = slurpXml(srd)
		then:
		xml.@RequestID == "SomeRequestId"
		xml.@Profile == "SomeProfile"
		xml.OptionalInputs.KeyName.size() == 2
		xml.OptionalInputs.KeyName[0] == "SomeKeyName1"
		xml.InputDocuments.Other.size() == 2
		xml.InputDocuments.Other[0].KeyName == "SomeKeyName3"

		when: "Try to parse"
        SignRequest sr = dmp.parseMessage(DEFAULT_CONTEXT,srd,false)
		then:
		sr.requestID == "SomeRequestId"

		when: "Generate minimal message"
		sr  = dmp.genSignRequest(null,null, null,null)
		srd = dmp.marshall(sr)
		//printXML(srd)
		then:
		srd != null

		when: "Try to parse"
		sr = dmp.parseMessage(DEFAULT_CONTEXT,srd,false)
		then:
		sr.requestID == null
	}

	def "Verify that genSignResponse generates a valid data structure"() {
		when: "Generate full message"
		byte[] srd = dmp.genSignResponse(DEFAULT_CONTEXT,"SomeRequestId", "SomeProfile",
				dmp.genResult(ResultMajorValues.Success,ResultMajorValues.SuccessResultMinorValues.OnAllDocuments,"SomeDetail","en"),
				createOptionalData(), createSignatureObject(), false)
		//printXML(srd)
		def xml = slurpXml(srd)
		then:
		xml.@RequestID == "SomeRequestId"
		xml.@Profile == "SomeProfile"
		xml.Result.ResultMajor == "urn:oasis:names:tc:dss:1.0:resultmajor:Success"
		xml.Result.ResultMinor == "urn:oasis:names:tc:dss:1.0:resultminor:valid:signature:OnAllDocuments"
		xml.Result.ResultMessage.@"xml:lang" == "en"
		xml.Result.ResultMessage == "SomeDetail"
		xml.OptionalOutputs.KeyName.size() == 2
		xml.OptionalOutputs.KeyName[0] == "SomeKeyName1"
		xml.SignatureObject.Other.KeyName.size() == 2
		xml.SignatureObject.Other.KeyName[0] == "SomeKeyName5"

		when: "Try to parse"
        SignResponse sr = dmp.parseMessage(DEFAULT_CONTEXT,srd, false)
		then:
		sr.requestID == "SomeRequestId"

		when: "Generate minimal message"
		sr  = dmp.genSignResponse(null,"SomeProfile",
		               dmp.genResult(ResultMajorValues.Success,null,null,null), null,null)
		srd = dmp.marshall(sr)
		//printXML(srd)
		then:
		xml.@Profile == "SomeProfile"
		xml.Result.ResultMajor == "urn:oasis:names:tc:dss:1.0:resultmajor:Success"

		when: "Try to parse"
		sr = dmp.parseMessage(DEFAULT_CONTEXT,srd,false)
		then:
		sr.requestID == null
	}

	def "Verify that genVerifyRequest generates a valid data structure"(){
		when: "Generate full message"
		byte[] vrd   = dmp.genVerifyRequest(DEFAULT_CONTEXT,"SomeRequestId","SomeProfile", createOptionalData(),createInputDocuments(), createSignatureObject(), false)
		//printXML(vrd)
		def xml = slurpXml(vrd)
		then:
		xml.@RequestID == "SomeRequestId"
		xml.@Profile == "SomeProfile"
		xml.OptionalInputs.KeyName.size() == 2
		xml.OptionalInputs.KeyName[0] == "SomeKeyName1"
		xml.InputDocuments.Other.size() == 2
		xml.InputDocuments.Other[0].KeyName == "SomeKeyName3"
		xml.SignatureObject.Other.KeyName.size() == 2
		xml.SignatureObject.Other.KeyName[0] == "SomeKeyName5"

		when: "Try to parse"
        VerifyRequest vr = dmp.parseMessage(DEFAULT_CONTEXT,vrd,false)
		then:
		vr.requestID == "SomeRequestId"

		when: "Generate minimal message"
		vr  = dmp.genVerifyRequest(null,null, null,null, null)
		vrd = dmp.marshall(vr)
		//printXML(vrd)
		then:
		vrd != null

		when: "Try to parse"
		vr = dmp.parseMessage(DEFAULT_CONTEXT,vrd,false)
		then:
		vr.requestID == null
	}

	def "Verify that genVerifyResponse generates a valid data structure"() {
		when: "Generate full message"
		byte[] vrd = dmp.genVerifyResponse(DEFAULT_CONTEXT,"SomeRequestId", "SomeProfile",
				dmp.genResult(ResultMajorValues.Success,ResultMajorValues.SuccessResultMinorValues.OnAllDocuments,"SomeDetail","en"),
				createOptionalData(), false)
		//printXML(vrd)
		def xml = slurpXml(vrd)
		then:
		xml.@RequestID == "SomeRequestId"
		xml.@Profile == "SomeProfile"
		xml.Result.ResultMajor == "urn:oasis:names:tc:dss:1.0:resultmajor:Success"
		xml.Result.ResultMinor == "urn:oasis:names:tc:dss:1.0:resultminor:valid:signature:OnAllDocuments"
		xml.Result.ResultMessage.@"xml:lang" == "en"
		xml.Result.ResultMessage == "SomeDetail"
		xml.OptionalOutputs.KeyName.size() == 2
		xml.OptionalOutputs.KeyName[0] == "SomeKeyName1"

		when: "Try to parse"
        ResponseBaseType rbt = dmp.parseMessage(DEFAULT_CONTEXT,vrd, false)
		then:
		rbt.requestID == "SomeRequestId"

		when: "Generate minimal message"
		JAXBElement<ResponseBaseType> vr  = dmp.genVerifyResponse(null,"SomeProfile",
				dmp.genResult(ResultMajorValues.Success,null,null,null), null)
		vrd = dmp.marshall(vr)
		//printXML(vrd)
		then:
		xml.@Profile == "SomeProfile"
		xml.Result.ResultMajor == "urn:oasis:names:tc:dss:1.0:resultmajor:Success"

		when: "Try to parse"
		rbt = dmp.parseMessage(DEFAULT_CONTEXT,vrd,false)
		then:
		rbt.requestID == null
	}

	def "Verify Signed SignRequest places the signature under OptionalInput and is targeted for the entire document"(){
		when:
		byte[] data = dmp.genSignRequest(DEFAULT_CONTEXT,"SomeRequestId","SomeProfile", createOptionalData(),createInputDocuments(), true)
		//printXML(data)
		def xml = slurpXml(data)
		then:
		xml.OptionalInputs.Signature.size() == 1
		dmp.parseMessage(DEFAULT_CONTEXT,data,true) != null

		when: "Verify the signature applies for the entire document"
		data = new String(data,"UTF-8").replace("SomeKeyName4","SomeKeyName5").getBytes("UTF-8")
		dmp.parseMessage(DEFAULT_CONTEXT,data,true)
		then:
		thrown MessageContentException

		when: "Verify that message content exception is thrown if no OptionalInputs element exists"
		dmp.genSignRequest(DEFAULT_CONTEXT,"SomeRequestId","SomeProfile", null,createInputDocuments(), true)
		then:
		thrown MessageContentException
	}

	def "Verify Signed SignResponse places the signature under OptionalInput and is targeted for the entire document"(){
		when:
		byte[] data = dmp.genSignResponse(DEFAULT_CONTEXT,"SomeRequestId","SomeProfile",  dmp.genResult(ResultMajorValues.Success,null,null,null),createOptionalData(),createSignatureObject(), true)
		//printXML(data)
		def xml = slurpXml(data)
		then:
		xml.OptionalOutputs.Signature.size() == 1
		dmp.parseMessage(DEFAULT_CONTEXT,data,true) != null

		when: "Verify the signature applies for the entire document"
		data = new String(data,"UTF-8").replace("SomeKeyName5","SomeKeyName6").getBytes("UTF-8")
		dmp.parseMessage(DEFAULT_CONTEXT,data,true)
		then:
		thrown MessageContentException

		when: "Verify that message content exception is thrown if no OptionalOutputs element exists"
		dmp.genSignResponse(DEFAULT_CONTEXT,"SomeRequestId","SomeProfile",  dmp.genResult(ResultMajorValues.Success,null,null,null),null,createSignatureObject(), true)
		then:
		thrown MessageContentException
	}

	def "Verify Signed VerifyRequest places the signature under OptionalInput and is targeted for the entire document"(){
		when:
		byte[] data = dmp.genVerifyRequest(DEFAULT_CONTEXT,"SomeRequestId","SomeProfile", createOptionalData(),createInputDocuments(), createSignatureObject(),true)
		//printXML(data)
		def xml = slurpXml(data)
		then:
		xml.OptionalInputs.Signature.size() == 1
		dmp.parseMessage(DEFAULT_CONTEXT,data,true) != null

		when: "Verify the signature applies for the entire document"
		data = new String(data,"UTF-8").replace("SomeKeyName4","SomeKeyName5").getBytes("UTF-8")
		dmp.parseMessage(DEFAULT_CONTEXT,data,true)
		then:
		thrown MessageContentException

	}

	def "Verify Signed VerifyResponse places the signature under OptionalInput and is targeted for the entire document"(){
		when:
		byte[] data = dmp.genVerifyResponse(DEFAULT_CONTEXT,"SomeRequestId","SomeProfile",  dmp.genResult(ResultMajorValues.Success,null,null,null),createOptionalData(), true)
		//printXML(data)
		def xml = slurpXml(data)
		then:
		xml.OptionalOutputs.Signature.size() == 1
		dmp.parseMessage(DEFAULT_CONTEXT,data,true) != null

		when: "Verify the signature applies for the entire document"
		data = new String(data,"UTF-8").replace("SomeKeyName1","SomeKeyName2").getBytes("UTF-8")
		dmp.parseMessage(DEFAULT_CONTEXT,data,true)
		then:
		thrown MessageContentException

	}


	private List<Object> createOptionalData(){
		return [dsignObj.createKeyName("SomeKeyName1"),dsignObj.createKeyName("SomeKeyName2")]
	}


	private InputDocuments createInputDocuments(){
		InputDocuments id = dssOf.createInputDocuments()
        AnyType at3 = dssOf.createAnyType()
		at3.any.add(dsignObj.createKeyName("SomeKeyName3"))
		AnyType at4 = dssOf.createAnyType()
		at4.any.add(dsignObj.createKeyName("SomeKeyName4"))
		id.getDocumentOrTransformedDataOrDocumentHash().add(at3)
		id.getDocumentOrTransformedDataOrDocumentHash().add(at4)
		return id;
	}

	private SignatureObject createSignatureObject(){
		SignatureObject so = dssOf.createSignatureObject()
		AnyType at1 = dssOf.createAnyType()
		at1.any.addAll([dsignObj.createKeyName("SomeKeyName5"),dsignObj.createKeyName("SomeKeyName6")])
		so.setOther(at1)
		return so;
	}

}
