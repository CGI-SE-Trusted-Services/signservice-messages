package org.signatureservice.messages.saml2.metadata


import org.signatureservice.messages.MessageContentException
import org.signatureservice.messages.csmessages.DefaultCSMessageParser
import org.signatureservice.messages.saml2.BaseSAMLMessageParser
import org.signatureservice.messages.saml2.CommonSAMLMessageParserSpecification
import org.signatureservice.messages.saml2.assertion.jaxb.AssertionType
import org.signatureservice.messages.saml2.assertion.jaxb.AttributeType
import org.signatureservice.messages.saml2.metadata.jaxb.AdditionalMetadataLocationType
import org.signatureservice.messages.saml2.metadata.jaxb.AffiliationDescriptorType
import org.signatureservice.messages.saml2.metadata.jaxb.AttributeConsumingServiceType
import org.signatureservice.messages.saml2.metadata.jaxb.ContactType
import org.signatureservice.messages.saml2.metadata.jaxb.ContactTypeType
import org.signatureservice.messages.saml2.metadata.jaxb.EndpointType
import org.signatureservice.messages.saml2.metadata.jaxb.EntitiesDescriptorType
import org.signatureservice.messages.saml2.metadata.jaxb.EntityDescriptorType
import org.signatureservice.messages.saml2.metadata.jaxb.ExtensionsType
import org.signatureservice.messages.saml2.metadata.jaxb.IDPSSODescriptorType
import org.signatureservice.messages.saml2.metadata.jaxb.IndexedEndpointType
import org.signatureservice.messages.saml2.metadata.jaxb.KeyDescriptorType
import org.signatureservice.messages.saml2.metadata.jaxb.KeyTypes
import org.signatureservice.messages.saml2.metadata.jaxb.LocalizedNameType
import org.signatureservice.messages.saml2.metadata.jaxb.LocalizedURIType
import org.signatureservice.messages.saml2.metadata.jaxb.OrganizationType
import org.signatureservice.messages.saml2.metadata.jaxb.RequestedAttributeType
import org.signatureservice.messages.saml2.metadata.jaxb.SPSSODescriptorType
import org.signatureservice.messages.saml2.metadata.ui.jaxb.DiscoHintsType
import org.signatureservice.messages.saml2.metadata.ui.jaxb.KeywordsType
import org.signatureservice.messages.saml2.metadata.ui.jaxb.LogoType
import org.signatureservice.messages.saml2.metadata.ui.jaxb.ObjectFactory
import org.signatureservice.messages.saml2.metadata.ui.jaxb.UIInfoType
import org.signatureservice.messages.sweeid2.pricipalselection1_0.PrincipalSelectionGenerator
import org.signatureservice.messages.sweeid2.pricipalselection1_0.jaxb.MatchValueType
import org.signatureservice.messages.sweeid2.pricipalselection1_0.jaxb.RequestedPrincipalSelectionType
import org.signatureservice.messages.utils.MessageGenerateUtils
import org.signatureservice.messages.xenc.jaxb.EncryptionMethodType

import jakarta.xml.bind.JAXBElement
import javax.xml.datatype.DatatypeFactory
import javax.xml.datatype.Duration
import javax.xml.namespace.QName

import static org.signatureservice.messages.TestUtils.printXML
import static org.signatureservice.messages.TestUtils.*
import static org.signatureservice.messages.ContextMessageSecurityProvider.DEFAULT_CONTEXT

class SAMLMetaDataMessageParserSpec extends CommonSAMLMessageParserSpecification {

	SAMLMetaDataMessageParser smdmp = new SAMLMetaDataMessageParser();

	org.signatureservice.messages.saml2.metadata.jaxb.ObjectFactory mdOf = new org.signatureservice.messages.saml2.metadata.jaxb.ObjectFactory()
    ObjectFactory uiOf = new ObjectFactory()


	Date validUntil
	Duration cacheDuration

	def setup() {
		smdmp.init(secProv);
		smdmp.systemTime = mockedSystemTime

		validUntil = simpleDateFormat.parse("2016-02-1")
		cacheDuration = DatatypeFactory.newInstance().newDuration(true,(int) 1,(int) 1,(int) 1,(int) 1,(int) 1,(int) 1)
	}

	def "Verify that JAXBPackages(), getNameSpace(), getSignatureLocationFinder(), getDefaultSchemaLocations(), getOrganisationLookup() returns the correct values"(){
		expect:
		smdmp.getJAXBPackages() == SAMLMetaDataMessageParser.BASE_JAXB_CONTEXT
		smdmp.getNameSpace() == SAMLMetaDataMessageParser.NAMESPACE
		smdmp.getSignatureLocationFinder() instanceof SAMLMetaDataMessageParser.SAML2MetaDataSignatureLocationFinder
		smdmp.getDefaultSchemaLocations().length== 4
		smdmp.getDefaultSchemaLocations()[0] == DefaultCSMessageParser.XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION;
		smdmp.getDefaultSchemaLocations()[1] == DefaultCSMessageParser.XMLENC_XSD_SCHEMA_RESOURCE_LOCATION;
		smdmp.getDefaultSchemaLocations()[2] == BaseSAMLMessageParser.ASSERTION_XSD_SCHEMA_2_0_RESOURCE_LOCATION;
		smdmp.getDefaultSchemaLocations()[3] == SAMLMetaDataMessageParser.METADATA_XSD_SCHEMA_2_0_RESOURCE_LOCATION;
		smdmp.getOrganisationLookup() == null
	}

	def "Verify that generateEntityDescriptor populates the datastructure correctly"(){
		when: "generate full data structure"
        EntityDescriptorType dt = smdmp.genEntityDescriptor("SomeEntityId", validUntil,cacheDuration, createExtensions(),
		                                   [createIDP(), createSP()], createOrganisation(),
		                                   createContactPersons(), createMetadataLocations(), createOtherAttributes());
		byte[] dtd = smdmp.marshall(mdOf.createEntityDescriptor(dt))
		//printXML(dtd)
		def xml = slurpXml(dtd)
		then:
		xml.@ID.toString().startsWith("_")
		xml.@entityID == "SomeEntityId"
		xml.@validUntil == MessageGenerateUtils.dateToXMLGregorianCalendarNoTimeZone(validUntil)
		xml.@cacheDuration == "P1Y1M1DT1H1M1S"
		xml.@"ds:Algorithm" == "http://somealg"
		xml.Extensions.size() == 1
		xml.IDPSSODescriptor.size() == 1
		xml.SPSSODescriptor.size() == 1
		xml.Organization.size() == 1
		xml.ContactPerson.size() == 2
		xml.AdditionalMetadataLocation.size() == 1

		when: "try to parse"
		dt = smdmp.parseMessage(null,dtd,false)
		then:
		dt != null

		when: "Generate minimal data structure"
		dt = smdmp.genEntityDescriptor("SomeEntityId", null,null, null,
				[createIDP()], null,
				null, null, null);
		dtd = smdmp.marshall(mdOf.createEntityDescriptor(dt))
		//printXML(dtd)
		xml = slurpXml(dtd)

		then:
		xml.@ID.toString().startsWith("_")
		xml.@entityID == "SomeEntityId"
		xml.IDPSSODescriptor.size() == 1

		when: "try to parse"
		dt = smdmp.parseMessage(DEFAULT_CONTEXT,dtd,false)
		then:
		dt != null

		when: "Try to generate with one affiliation descriptor"
		dt = smdmp.genEntityDescriptor("SomeEntityId", null,null, null,
				[createAffiliationDescriptor()], null,
				null, null, null);
		dtd = smdmp.marshall(mdOf.createEntityDescriptor(dt))
		//printXML(dtd)
		xml = slurpXml(dtd)
		then:
		xml.@ID.toString().startsWith("_")
		xml.@entityID == "SomeEntityId"
		xml.AffiliationDescriptor.size() == 1

		when: "Verify that adding two affiliation descriptors throws MessageContentException"
		smdmp.genEntityDescriptor("SomeEntityId", null,null, null,
				[createAffiliationDescriptor(),createAffiliationDescriptor()], null,
				null, null, null);
		then:
		thrown MessageContentException

		when: "Verify that mixing affiliation descriptor with other types throws MessageContentException"
		smdmp.genEntityDescriptor("SomeEntityId", null,null, null,
				[createAffiliationDescriptor(),createIDP()], null,
				null, null, null);
		then:
		thrown MessageContentException

		when: "Verify that no descriptors throws MessageContentException"
		smdmp.genEntityDescriptor("SomeEntityId", null,null, null,
				[], null,
				null, null, null);
		then:
		thrown MessageContentException
	}

	def "Verify that genEntitiesDescriptor generates valid data structure"(){
		setup:
		EntityDescriptorType edt1 = smdmp.genEntityDescriptor("SomeEntityId", null,null, null,
				[createIDP()], null,
				null, null, null);
		EntityDescriptorType edt2 = smdmp.genEntityDescriptor("SomeEntityId", null,null, null,
				[createSP()], null,
				null, null, null);
		when: "Generate full data structure"
        EntitiesDescriptorType dt = smdmp.genEntitiesDescriptor(validUntil,cacheDuration,"SomeName",createExtensions(),[edt1, edt2]);

		byte[] dtd = smdmp.marshall(mdOf.createEntitiesDescriptor(dt))
		//printXML(dtd)
		def xml = slurpXml(dtd)
		then:
		xml.@ID.toString().startsWith("_")
		xml.@Name == "SomeName"
		xml.@validUntil == MessageGenerateUtils.dateToXMLGregorianCalendarNoTimeZone(validUntil)
		xml.@cacheDuration == "P1Y1M1DT1H1M1S"
		xml.Extensions.size() == 1
		xml.EntityDescriptor.size() == 2

		when: "Generate minimal data structure"
		dt = smdmp.genEntitiesDescriptor(null,null,null,null,[edt1]);
		dtd = smdmp.marshall(mdOf.createEntitiesDescriptor(dt))
		//printXML(dtd)
		xml = slurpXml(dtd)
		then:
		xml.@ID.toString().startsWith("_")
		xml.EntityDescriptor.size() == 1

	}

	def "Verify that genIDPSSODescriptor populates correctly"(){
		when: "Generate a full IDPSSODescriptor"

        IDPSSODescriptorType dt = smdmp.genIDPSSODescriptor(validUntil,cacheDuration,["urn:oasis:names:tc:SAML:2.0:protocol", "urn:oasis:names:tc:SAML:profiles:query:attributes:X509-basic"],
		                                   "http://someerrorURL", createExtensions(), createKeyDescriptor(),createOrganisation(),
				                           createContactPersons(),createOtherAttributes(), createArtifactResolutionServices(),
		                                   createSingleLogoutServices(), createManageNameIDServices(), ["nameid1","nameid2"],
		                                   true, createSingleSignOnServices(),createNameIDMappingServices(),createAssertionIDRequestServices(),
		                                   ["attrprofile1","attrprofile2"], createSAMLAttributes())
		byte[] dtd = smdmp.marshall(mdOf.createIDPSSODescriptor(dt));
		//printXML(dtd)
		def xml = slurpXml(dtd)
		then:
		xml.@ID.toString().startsWith("_")
		xml.@validUntil == MessageGenerateUtils.dateToXMLGregorianCalendarNoTimeZone(validUntil)
		xml.@cacheDuration == "P1Y1M1DT1H1M1S"
		xml.@protocolSupportEnumeration == "urn:oasis:names:tc:SAML:2.0:protocol urn:oasis:names:tc:SAML:profiles:query:attributes:X509-basic"
		xml.@errorURL == "http://someerrorURL"
		xml.@"ds:Algorithm" == "http://somealg"
		xml.@WantAuthnRequestsSigned == true
		xml.Extensions.size() == 1
		xml.KeyDescriptor.size() == 1
		xml.Organization.size() == 1
		xml.ContactPerson.size() == 2
		xml.ArtifactResolutionService.size() == 2
		xml.ArtifactResolutionService[0].@Binding == "http://artificatresbinding1.com"
		xml.ArtifactResolutionService[0].@index == "1"
		xml.SingleLogoutService.size() == 2
		xml.SingleLogoutService[0].@Binding == "http://slbinding1.com"
		xml.ManageNameIDService.size() == 2
		xml.ManageNameIDService[0].@Binding == "http://mnidbinding1.com"
		xml.NameIDFormat.size() == 2
		xml.NameIDFormat[0] == "nameid1"
		xml.SingleSignOnService.size() == 2
		xml.SingleSignOnService[0].@Binding == "http://ssobinding1.com"
		xml.NameIDMappingService.size() == 2
		xml.NameIDMappingService[0].@Binding == "http://nidmbinding1.com"
		xml.AssertionIDRequestService.size() == 2
		xml.AssertionIDRequestService[0].@Binding == "http://aidrbinding1.com"
		xml.AttributeProfile.size() == 2
		xml.AttributeProfile[0] == "attrprofile1"
		xml.Attribute.size() == 2
		xml.Attribute[0].@Name == "SomeAttr1"

		when: "Try to parse and validate schema"
		dt = smdmp.parseMessage(DEFAULT_CONTEXT,dtd, false)
		then:
		dt != null

		when: "Generate a minimal IDPSSODescriptor"
		dt = smdmp.genIDPSSODescriptor(null,null,["urn:oasis:names:tc:SAML:2.0:protocol"],
				null, null, null,null, null,null, null,
				null,null,null,
				null, createSingleSignOnServices(),null,null,null,null	)
		dtd = smdmp.marshall(mdOf.createIDPSSODescriptor(dt));
		//printXML(dtd)
		xml = slurpXml(dtd)
		then:
		xml.@ID.toString().startsWith("_")
		xml.@protocolSupportEnumeration == "urn:oasis:names:tc:SAML:2.0:protocol"
		xml.SingleSignOnService.size() == 2
		xml.SingleSignOnService[0].@Binding == "http://ssobinding1.com"

		when: "Try to parse and validate schema"
		dt = smdmp.parseMessage(DEFAULT_CONTEXT,dtd, false)
		then:
		dt != null
	}

	def "Verify that genSPSSODescriptor populates correctly"(){
		when: "Generate a full SPSSODescriptor"

        SPSSODescriptorType dt = smdmp.genSPSSODescriptor(validUntil,cacheDuration,["urn:oasis:names:tc:SAML:2.0:protocol", "urn:oasis:names:tc:SAML:profiles:query:attributes:X509-basic"],
				"http://someerrorURL", createExtensions(), createKeyDescriptor(),createOrganisation(),
				createContactPersons(),createOtherAttributes(), createArtifactResolutionServices(),
				createSingleLogoutServices(), createManageNameIDServices(), ["nameid1","nameid2"],
				true, false, createAssertionConsumerServices(), createAttributeConsumingServices())
		byte[] dtd = smdmp.marshall(mdOf.createSPSSODescriptor(dt));
		//printXML(dtd)
		def xml = slurpXml(dtd)
		then:
		xml.@ID.toString().startsWith("_")
		xml.@validUntil == MessageGenerateUtils.dateToXMLGregorianCalendarNoTimeZone(validUntil)
		xml.@cacheDuration == "P1Y1M1DT1H1M1S"
		xml.@protocolSupportEnumeration == "urn:oasis:names:tc:SAML:2.0:protocol urn:oasis:names:tc:SAML:profiles:query:attributes:X509-basic"
		xml.@errorURL == "http://someerrorURL"
		xml.@"ds:Algorithm" == "http://somealg"
		xml.@AuthnRequestsSigned == true
		xml.@WantAssertionsSigned == false
		xml.Extensions.size() == 1
		xml.KeyDescriptor.size() == 1
		xml.Organization.size() == 1
		xml.ContactPerson.size() == 2
		xml.ArtifactResolutionService.size() == 2
		xml.ArtifactResolutionService[0].@Binding == "http://artificatresbinding1.com"
		xml.ArtifactResolutionService[0].@index == "1"
		xml.SingleLogoutService.size() == 2
		xml.SingleLogoutService[0].@Binding == "http://slbinding1.com"
		xml.ManageNameIDService.size() == 2
		xml.ManageNameIDService[0].@Binding == "http://mnidbinding1.com"
		xml.NameIDFormat.size() == 2
		xml.NameIDFormat[0] == "nameid1"
		xml.AssertionConsumerService.size() == 2
		xml.AssertionConsumerService[0].@index == "1"
		xml.AssertionConsumerService[0].@Binding == "http://acbinding1.com"
		xml.AttributeConsumingService.size() == 1

		when: "Try to parse and validate schema"
		dt = smdmp.parseMessage(DEFAULT_CONTEXT,dtd, false)
		then:
		dt != null

		when: "Generate a minimal IDPSSODescriptor"
		dt = smdmp.genSPSSODescriptor(null,null,["urn:oasis:names:tc:SAML:2.0:protocol"],
				null, null, null,null, null,null, null,
				null,null,null,
				null, null,createAssertionConsumerServices(),null)
		dtd = smdmp.marshall(mdOf.createSPSSODescriptor(dt));
		//printXML(dtd)
		xml = slurpXml(dtd)
		then:
		xml.@ID.toString().startsWith("_")
		xml.@protocolSupportEnumeration == "urn:oasis:names:tc:SAML:2.0:protocol"
		xml.AssertionConsumerService.size() == 2
		xml.AssertionConsumerService[0].@Binding == "http://acbinding1.com"

		when: "Try to parse and validate schema"
		dt = smdmp.parseMessage(DEFAULT_CONTEXT,dtd, false)
		then:
		dt != null
	}


	def "Verify that genOrganization generates an organisation correctly"(){
		when:
        OrganizationType o = smdmp.genOrganization(createExtensions(),createOrganizationNames(),createOrganizationDisplayNames(),
		                                           createOrganizationURLs(),createOtherAttributes())
		then:
		o.extensions != null
		o.organizationName.size() == 2
		o.organizationName[0].value == "SomeCompany"
		o.organizationName[1].value == "Namn"
		o.organizationDisplayName.size() == 2
		o.organizationDisplayName[0].value == "Some Company"
		o.organizationDisplayName[1].value == "VisbartNamn"
		o.organizationURL.size() == 2
		o.organizationURL[0].value == "http://en.someorg.org"
		o.organizationURL[1].value == "http://sv.someorg.org"
		o.otherAttributes.size() == 1
		when: "Try to marshall"
		byte[] od = smdmp.marshall(mdOf.createOrganization(o))
		then:
		od != null;
		when: "Try to create minimal structure"
		o = smdmp.genOrganization(null,createOrganizationNames(),createOrganizationDisplayNames(),
				createOrganizationURLs(),null)
		then:
		o.extensions == null
		o.otherAttributes.size() == 0
		when: "Verify that at least on organsiationName must exist"
		smdmp.genOrganization(null,null,createOrganizationDisplayNames(),
				createOrganizationURLs(),null)
		then:
		thrown MessageContentException
		when: "Verify that at least on organsiationDisplayName must exist"
		smdmp.genOrganization(null,createOrganizationNames(),[],
				createOrganizationURLs(),null)
		then:
		thrown MessageContentException
		when: "Verify that at least on organsiationName must exist"
		smdmp.genOrganization(null,createOrganizationNames(),createOrganizationDisplayNames(),
				null,null)
		then:
		thrown MessageContentException

	}

	def "Verify that genContactType generates an contact person correctly"(){
		when:
        ContactType ct = smdmp.genContactType(ContactTypeType.ADMINISTRATIVE,createExtensions(), "SomeCompany",
				"SomeGivenName", "SomeSurname", ["email1@test.com","email2@test.com"],
		         ["12345","54321"], createOtherAttributes())
		then:
		ct.contactType == ContactTypeType.ADMINISTRATIVE
		ct.extensions != null
		ct.company  == "SomeCompany"
		ct.givenName == "SomeGivenName"
		ct.surName == "SomeSurname"
		ct.emailAddress.size() == 2
		ct.emailAddress[0]  == "email1@test.com"
		ct.emailAddress[1]  == "email2@test.com"
		ct.telephoneNumber.size() == 2
		ct.telephoneNumber[0]  == "12345"
		ct.telephoneNumber[1]  == "54321"
		ct.otherAttributes.size() == 1
		when: "try to marshall"
		byte[] ctd = smdmp.marshall(mdOf.createContactPerson(ct))
		//printXML(ctd)
		then:
		ctd != null
		when: "try to generate a minimal contact type"
		ct = smdmp.genContactType(ContactTypeType.BILLING,null,null,null,null,null,null,null)
		then:
		ct.contactType == ContactTypeType.BILLING
		ct.extensions == null
		ct.company == null
		ct.givenName == null
		ct.surName == null
		ct.emailAddress.size() == 0
		ct.telephoneNumber.size() == 0
		ct.otherAttributes.size() == 0
	}

	def "Verify genKeyDescriptor() generates a valid key descriptor"(){

		when:
        KeyDescriptorType kdt = smdmp.genKeyDescriptor(KeyTypes.ENCRYPTION,secProv.getSigningCertificate(),createEncryptionMethods())
		then:
		kdt.use == KeyTypes.ENCRYPTION
		kdt.keyInfo.content.size() == 1
		kdt.encryptionMethod.size() == 2
		when: "Try to marshall"
		byte[] kdtd = smdmp.marshall(mdOf.createKeyDescriptor(kdt))
		//printXML(kdtd)
		def xml = slurpXml(kdtd)
		then:
		xml.KeyInfo.X509Data.X509Certificate.size() == 1

	}

	def "Verify genEndpoint() generates a valid endpoint type"(){
		when:
        EndpointType et = smdmp.genEndpoint("SomeBinding","SomeLocation", "SomeResponseLocation",
		createAnyXML(), createOtherAttributes());
		then:
		et.binding == "SomeBinding"
		et.location == "SomeLocation"
		et.responseLocation == "SomeResponseLocation"
		et.getAny().size() == 2
		et.getOtherAttributes().size() == 1
		when:
		byte[] etd = smdmp.marshall(mdOf.createAssertionIDRequestService(et))
		//printXML(etd)
		def xml = slurpXml(etd)
		then:
		etd != null
		xml.@"ds:Algorithm" == "http://somealg"
		xml.KeyName.size() == 2
		xml.KeyName[0] == "SomeKeyName1"
		xml.KeyName[1] == "SomeKeyName2"
		when: "Generate minimal"
		et = smdmp.genEndpoint("SomeBinding","SomeLocation", null,null,null)
		etd = smdmp.marshall(mdOf.createAssertionIDRequestService(et))
		//printXML(etd)
		xml = slurpXml(etd)
		then:
		xml.KeyName.size() == 0

	}

	def "Verify genAttributeConsumingService populates correctly"(){
		when: "Generate full data structure"
        AttributeConsumingServiceType t = smdmp.genAttributeConsumingService(1,true,createServiceNames(),createServiceDescriptions(),createRequestedAttributes())
		byte[] td = smdmp.marshall(mdOf.createAttributeConsumingService(t))
		//printXML(td);
		def xml = slurpXml(td)
		then:
		xml.@index == 1
		xml.@isDefault == true
		xml.ServiceName.size() == 2
		xml.ServiceName[0] == "ServiceName"
		xml.ServiceDescription.size() == 2
		xml.ServiceDescription[0] == "ServiceDescription"
		xml.RequestedAttribute.size() == 2
		xml.RequestedAttribute[0].@isRequired == true
		xml.RequestedAttribute[0].@Name == "SomeAttr1"

		when: "Generate minimal data structure"
		t = smdmp.genAttributeConsumingService(1,null,createServiceNames(),null,createRequestedAttributes())
		td = smdmp.marshall(mdOf.createAttributeConsumingService(t))
		//printXML(td);
		xml = slurpXml(td)
		then:
		xml.@index == 1
		xml.ServiceName.size() == 2
		xml.RequestedAttribute.size() == 2
	}

	def "Verify genIndextedEndpoint() generates a valid endpoint type"(){
		when:
		EndpointType et = smdmp.genIndexedEndpoint("SomeBinding","SomeLocation", "SomeResponseLocation",
				1, true,
				createAnyXML(), createOtherAttributes());
		then:
		et.binding == "SomeBinding"
		et.location == "SomeLocation"
		et.responseLocation == "SomeResponseLocation"
		et.index == 1
		et.isDefault == true
		et.getAny().size() == 2
		et.getOtherAttributes().size() == 1
	}

	def "Verify that signed EntitiesDescriptor are generated correctly"(){
		setup:
		EntityDescriptorType edt1 = smdmp.genEntityDescriptor("SomeEntityId", null,null, null,
				[createIDP()], null,
				null, null, null);
		EntityDescriptorType edt2 = smdmp.genEntityDescriptor("SomeEntityId", null,null, null,
				[createSP()], null,
				null, null, null);
		when:
		byte[] edd = smdmp.genEntitiesDescriptor(DEFAULT_CONTEXT,validUntil,cacheDuration,"SomeName",createExtensions(),[edt1,edt2], true);
		//printXML(edd)
		def xml = slurpXml(edd)
		then:
		xml.Signature.size() == 1

		when:
		EntitiesDescriptorType edt = smdmp.parseMessage(DEFAULT_CONTEXT,edd,true)
		then:
		edt.signature != null


		when:
		edd = smdmp.genEntitiesDescriptor(DEFAULT_CONTEXT,null,null,null,null,[edt1], true);
		//printXML(edd)
		xml = slurpXml(edd)
		then:
		xml.Signature.size() == 1

		when:
		edt = smdmp.parseMessage(DEFAULT_CONTEXT,edd,true)
		then:
		edt.signature != null

		when:
		edd = smdmp.genEntitiesDescriptor(DEFAULT_CONTEXT,null,null,null,null,[edt1], false);
		//printXML(edd)
		xml = slurpXml(edd)
		then:
		xml.Signature.size() == 0

		when:
		smdmp.parseMessage(DEFAULT_CONTEXT,edd,true)
		then:
		thrown MessageContentException

		when:
		edt = smdmp.parseMessage(DEFAULT_CONTEXT,edd,false)
		then:
		edt.signature == null
	}

	def "Verify that signed EntityDescriptor are generated correctly"(){
		when:
		byte[] edd = smdmp.genEntityDescriptor(DEFAULT_CONTEXT,"SomeEntityId", validUntil,cacheDuration, createExtensions(),
				[createIDP(), createSP()], createOrganisation(),
				createContactPersons(), createMetadataLocations(), createOtherAttributes(),true);
		//printXML(edd)
		def xml = slurpXml(edd)
		then:
		xml.Signature.size() == 1

		when:
		EntityDescriptorType edt = smdmp.parseMessage(DEFAULT_CONTEXT,edd,true)
		then:
		edt.signature != null


		when:
		edd = smdmp.genEntityDescriptor(DEFAULT_CONTEXT,"SomeEntityId", null,null, null, [createIDP()], null, null, null, null, true);
		//printXML(edd)
		xml = slurpXml(edd)
		then:
		xml.Signature.size() == 1

		when:
		edt = smdmp.parseMessage(DEFAULT_CONTEXT,edd,true)
		then:
		edt.signature != null

		when:
		edd = smdmp.genEntityDescriptor(DEFAULT_CONTEXT,"SomeEntityId", null,null, null, [createIDP()], null, null, null, null, false);
		//printXML(edd)
		xml = slurpXml(edd)
		then:
		xml.Signature.size() == 0

		when:
		smdmp.parseMessage(DEFAULT_CONTEXT,edd,true)
		then:
		thrown MessageContentException

		when:
		edt = smdmp.parseMessage(DEFAULT_CONTEXT,edd,false)
		then:
		edt.signature == null
	}

	def "Verify that signed IDPSSODescriptor are generated correctly"() {
		when:
		IDPSSODescriptorType dt = smdmp.genIDPSSODescriptor(validUntil, cacheDuration, ["urn:oasis:names:tc:SAML:2.0:protocol", "urn:oasis:names:tc:SAML:profiles:query:attributes:X509-basic"],
				"http://someerrorURL", createExtensions(), createKeyDescriptor(), createOrganisation(),
				createContactPersons(), createOtherAttributes(), createArtifactResolutionServices(),
				createSingleLogoutServices(), createManageNameIDServices(), ["nameid1", "nameid2"],
				true, createSingleSignOnServices(), createNameIDMappingServices(), createAssertionIDRequestServices(),
				["attrprofile1", "attrprofile2"], createSAMLAttributes())
		JAXBElement<IDPSSODescriptorType> jdt = mdOf.createIDPSSODescriptor(dt)
		byte[] dtd = smdmp.marshallAndSign(DEFAULT_CONTEXT,jdt)
		//printXML(dtd)
		def xml = slurpXml(dtd)
		then:
		xml.Signature.size() == 1

		when:
		dt = smdmp.parseMessage(DEFAULT_CONTEXT,dtd,true)
		then:
		dt.signature != null

		when:
		dt = smdmp.genIDPSSODescriptor(null,null,["urn:oasis:names:tc:SAML:2.0:protocol"],
				null, null, null,null, null,null, null,
				null,null,null,
				null, createSingleSignOnServices(),null,null,null,null	)
		jdt = mdOf.createIDPSSODescriptor(dt)
		dtd = smdmp.marshallAndSign(DEFAULT_CONTEXT,jdt)
		//printXML(dtd)
		xml = slurpXml(dtd)
		then:
		xml.Signature.size() == 1

		when:
		dt = smdmp.parseMessage(DEFAULT_CONTEXT,dtd,true)
		then:
		dt.signature != null
	}

	def "Verify that signed IDPSSODescriptor with RequestedPricipalSelection are generated correctly"() {
		when:
		IDPSSODescriptorType dt = smdmp.genIDPSSODescriptor(validUntil, cacheDuration, ["urn:oasis:names:tc:SAML:2.0:protocol", "urn:oasis:names:tc:SAML:profiles:query:attributes:X509-basic"],
				"http://someerrorURL", createRequestedPrincipalSelectionExtensions(), createKeyDescriptor(), createOrganisation(),
				createContactPersons(), createOtherAttributes(), createArtifactResolutionServices(),
				createSingleLogoutServices(), createManageNameIDServices(), ["nameid1", "nameid2"],
				true, createSingleSignOnServices(), createNameIDMappingServices(), createAssertionIDRequestServices(),
				["attrprofile1", "attrprofile2"], createSAMLAttributes())
		JAXBElement<IDPSSODescriptorType> jdt = mdOf.createIDPSSODescriptor(dt)
		byte[] dtd = smdmp.marshallAndSign(DEFAULT_CONTEXT,jdt)
		printXML(dtd)
		def xml = slurpXml(dtd)
		then:
		xml.Signature.size() == 1
		xml.Extensions.RequestedPrincipalSelection.MatchValue.size() == 2
		xml.Extensions.RequestedPrincipalSelection.MatchValue[0].@Name == "urn:oid:1.2.752.29.4.13"
		xml.Extensions.RequestedPrincipalSelection.MatchValue[1].@Name == "urn:oid:1.2.752.29.4.14"

		when:
		dt = smdmp.parseMessage(DEFAULT_CONTEXT,dtd,true)
		then:
		dt.extensions.any.size() == 1
		RequestedPrincipalSelectionType v = dt.extensions.any[0].value
		v.matchValue[0].name == "urn:oid:1.2.752.29.4.13"
		v.matchValue[1].name == "urn:oid:1.2.752.29.4.14"


	}

	def "Verify that signed SPSSODescriptor are generated correctly"() {
		when:
		SPSSODescriptorType dt = smdmp.genSPSSODescriptor(validUntil,cacheDuration,["urn:oasis:names:tc:SAML:2.0:protocol", "urn:oasis:names:tc:SAML:profiles:query:attributes:X509-basic"],
				"http://someerrorURL", createExtensions(), createKeyDescriptor(),createOrganisation(),
				createContactPersons(),createOtherAttributes(), createArtifactResolutionServices(),
				createSingleLogoutServices(), createManageNameIDServices(), ["nameid1","nameid2"],
				true, false, createAssertionConsumerServices(), createAttributeConsumingServices())
		byte[] dtd = smdmp.marshallAndSign(DEFAULT_CONTEXT,mdOf.createSPSSODescriptor(dt))
		//printXML(dtd)
		def xml = slurpXml(dtd)
		then:
		xml.Signature.size() == 1

		when:
		dt = smdmp.parseMessage(DEFAULT_CONTEXT,dtd,true)
		then:
		dt.signature != null

		when:
		dt = smdmp.genSPSSODescriptor(null,null,["urn:oasis:names:tc:SAML:2.0:protocol"],
				null, null, null,null, null,null, null,
				null,null,null,
				null, null,createAssertionConsumerServices(),null)
		//printXML(dtd)
		xml = slurpXml(dtd)
		then:
		xml.Signature.size() == 1

		when:
		dt = smdmp.parseMessage(DEFAULT_CONTEXT,dtd,true)
		then:
		dt.signature != null
	}



	def "Verify that genUIInfo generates a valid UIInfo type"(){
		when:
		JAXBElement<LogoType> logoEN = smdmp.genUILogo(123,324,"http://someURI.en", "en")
		JAXBElement<LogoType> logoSV = smdmp.genUILogo(123,324,"http://someURI.sv","sv")

		JAXBElement<LocalizedNameType> displayName = smdmp.genUIDisplayName("Some DisplayName","en")

		JAXBElement<LocalizedNameType> description = smdmp.genUIDescription("Some Description","en")

		JAXBElement<LocalizedURIType> privStatment = smdmp.genUIPrivacyStatementURL("http://SomePrivStatement","en")

		JAXBElement<LocalizedURIType> infoURL = smdmp.genUIInformationURL("http://SomeInfoURL ","en")

		JAXBElement<KeywordsType> kw = smdmp.genUIKeywords(["asdf asd","sdf"],"en")

		def otherXML = dsignObj.createKeyName("SomeKeyName1")

		JAXBElement<UIInfoType> uiInfo = smdmp.genUIInfo([logoEN,logoSV,displayName,description,privStatment,infoURL,kw, otherXML])

		def dt = smdmp.genSPSSODescriptor(null,null,["urn:oasis:names:tc:SAML:2.0:protocol"],
				null, smdmp.genExtensions([uiInfo]), null,null, null,null, null,
				null,null,null,
				null, null,createAssertionConsumerServices(),null)
		byte[] dtd = smdmp.marshall(mdOf.createSPSSODescriptor(dt))
		//printXML(dtd)
		def xml = slurpXml(dtd)
		then:
		xml.Extensions.size() == 1
		xml.Extensions.UIInfo.Logo.size() == 2
		xml.Extensions.UIInfo.DisplayName.size() == 1
		xml.Extensions.UIInfo.Description.size() == 1
		xml.Extensions.UIInfo.PrivacyStatementURL.size() == 1
		xml.Extensions.UIInfo.InformationURL.size() == 1
		xml.Extensions.UIInfo.Keywords.size() == 1
		xml.Extensions.UIInfo.Keywords == "asdf+asd sdf"
		xml.Extensions.UIInfo.KeyName == "SomeKeyName1"

		when:
		smdmp.genUIInfo([])
		then:
		def e = thrown(MessageContentException)
		e.message == "Error constructing UIInfo, at least one child element must exist."

		when:
		smdmp.genUIInfo(null)
		then:
		e = thrown(MessageContentException)
		e.message == "Error constructing UIInfo, at least one child element must exist."

	}

	def "Verify that genUIDiscoHints generates a valid DiscoHints type"(){
		when:
		JAXBElement<String> ipHint1 = smdmp.genUIIPHint("123.123.123.123")
		JAXBElement<String> ipHint2 = smdmp.genUIIPHint("124.124.124.124")

		JAXBElement<String> domainHint = smdmp.genUIDomainHint("domain1")

		JAXBElement<String> geoHint1 = smdmp.genUIGeolocationHint("geohint1")

		def otherXML = dsignObj.createKeyName("SomeKeyName1")

		JAXBElement<DiscoHintsType> discoHints = smdmp.genUIDiscoHints([ipHint1, ipHint2, domainHint, geoHint1, otherXML])

		def dt = smdmp.genSPSSODescriptor(null,null,["urn:oasis:names:tc:SAML:2.0:protocol"],
				null, smdmp.genExtensions([discoHints]), null,null, null,null, null,
				null,null,null,
				null, null,createAssertionConsumerServices(),null)
		byte[] dtd = smdmp.marshall(mdOf.createSPSSODescriptor(dt))
		//printXML(dtd)
		def xml = slurpXml(dtd)
		then:
		xml.Extensions.size() == 1
		xml.Extensions.DiscoHints.IPHint.size() == 2
		xml.Extensions.DiscoHints.DomainHint.size() == 1
		xml.Extensions.DiscoHints.GeolocationHint.size() == 1
		xml.Extensions.DiscoHints.KeyName == "SomeKeyName1"

		when:
		smdmp.genUIDiscoHints([])
		then:
		def e = thrown(MessageContentException)
		e.message == "Error constructing DiscoHints, at least one child element must exist."

		when:
		smdmp.genUIDiscoHints(null)
		then:
		e = thrown(MessageContentException)
		e.message == "Error constructing DiscoHints, at least one child element must exist."

	}

	def "Verify genUILogo sets all values"(){
		when:
		def l = smdmp.genUILogo(123,324,"http://someURI.en", "en")
		then:
		l.name.localPart == "Logo"
		l.value.width.toString() == "123"
		l.value.height.toString() == "324"
		l.value.value == "http://someURI.en"
		l.value.lang == "en"

		when: // Verify language is optional
		smdmp.genUILogo(123,324,"http://someURI.en", null)
		then:
		true
	}

	def "Verify genUIDisplayName sets all values"(){
		when:
		def l = smdmp.genUIDisplayName("SomeDispName", "en")
		then:
		l.name.localPart == "DisplayName"
		l.value.value == "SomeDispName"
		l.value.lang == "en"

		when: // Verify language is required
		smdmp.genUIDisplayName("SomeDispName",null)
		then:
		def e = thrown(MessageContentException)
		e.message == "lang attribute is required for MD UI DisplayName"
	}

	def "Verify genUIDescription sets all values"(){
		when:
		def l = smdmp.genUIDescription("SomeDescription", "en")
		then:
		l.name.localPart == "Description"
		l.value.value == "SomeDescription"
		l.value.lang == "en"

		when: // Verify language is required
		smdmp.genUIDescription("SomeDescription",null)
		then:
		def e = thrown(MessageContentException)
		e.message == "lang attribute is required for MD UI Description"
	}

	def "Verify genUIInformationURL sets all values"(){
		when:
		def l = smdmp.genUIInformationURL("SomeInformationURL", "en")
		then:
		l.name.localPart == "InformationURL"
		l.value.value == "SomeInformationURL"
		l.value.lang == "en"

		when: // Verify language is required
		smdmp.genUIInformationURL("SomeInformationURL",null)
		then:
		def e = thrown(MessageContentException)
		e.message == "lang attribute is required for MD UI InformationURL"
	}

	def "Verify genUIPrivacyStatementURL sets all values"(){
		when:
		def l = smdmp.genUIPrivacyStatementURL("SomePrivacyStatementURL", "en")
		then:
		l.name.localPart == "PrivacyStatementURL"
		l.value.value == "SomePrivacyStatementURL"
		l.value.lang == "en"

		when: // Verify language is required
		smdmp.genUIPrivacyStatementURL("SomePrivacyStatementURL",null)
		then:
		def e = thrown(MessageContentException)
		e.message == "lang attribute is required for MD UI PrivacyStatementURL"
	}

	def "Verify genUIKeywords sets all values"(){
		when:
		def l = smdmp.genUIKeywords(["SomeKeyword", "Some Spaced Keyword"], "en")
		then:
		l.name.localPart == "Keywords"
		l.value.value.size() == 2
		l.value.value[0] == "SomeKeyword"
		l.value.value[1] == "Some+Spaced+Keyword"
		l.value.lang == "en"

		when: // Verify language is required
		smdmp.genUIKeywords(["SomePrivacyStatementURL"],null)
		then:
		def e = thrown(MessageContentException)
		e.message == "lang attribute is required for MD UI Keywords"
	}

	def "Verify genUIIPHint sets all values"(){
		when:
		def l = smdmp.genUIIPHint("123.123.123.123")
		then:
		l.name.localPart == "IPHint"
		l.value == "123.123.123.123"
	}

	def "Verify genUIDomainHint sets all values"(){
		when:
		def l = smdmp.genUIDomainHint("SomeDomain")
		then:
		l.name.localPart == "DomainHint"
		l.value == "SomeDomain"
	}

	def "Verify genUIGeolocationHint sets all values"(){
		when:
		def l = smdmp.genUIGeolocationHint("SomeGeoLocation")
		then:
		l.name.localPart == "GeolocationHint"
		l.value == "SomeGeoLocation"
	}

	def "Verify that genMDAttribute generates valid extension data in a EntityDataType"(){
		when: "Generate MD Entity Attributes extensions"
		def extension = smdmp.genMDEntityAttributes(createSAMLAttributes())

		and:  "Generate minimal entity data structure using the extension"
		def dt = smdmp.genEntityDescriptor("SomeEntityId", null,null, smdmp.genExtensions([extension]),
				[createIDP()], null,
				null, null, null);
		def dtd = smdmp.marshall(mdOf.createEntityDescriptor(dt))
		//printXML(dtd)
		def xml = slurpXml(dtd)

		then:
		xml.Extensions.EntityAttributes.size() == 1
		xml.Extensions.EntityAttributes.Attribute.size() == 2
	}

	def "Verify that genMDAttribute throws MessageContentException if invalid parameter is given"(){
		when:
		smdmp.genMDEntityAttributes([new AttributeType(), new EntitiesDescriptorType()])
		then:
		def e = thrown(MessageContentException)
		e.message == "Error constructing MDAttr EntityAttributes, only AttributeType or AssertionType is allowed as attributes."
		when: "Verify that both attriutetype and assertion type is valid"
		def t = smdmp.genMDEntityAttributes([new AttributeType(), new AssertionType()])
		then:
		t.value.attributeOrAssertion.size() == 2
	}

	def "Verify that parser can parse a MD document containing UIInfo and DiscoHints"(){
		when:
		EntityDescriptorType edt = smdmp.parseMessage(null,MDWithUIElementsAndAttrAndRequestedPricipalSelection,false)
		then:
		edt.roleDescriptorOrIDPSSODescriptorOrSPSSODescriptor[0].extensions.any.size() == 3
		edt.roleDescriptorOrIDPSSODescriptorOrSPSSODescriptor[0].extensions.any[0].name.localPart == "UIInfo"
		edt.roleDescriptorOrIDPSSODescriptorOrSPSSODescriptor[0].extensions.any[0].value.displayNameOrDescriptionOrKeywords.size() == 8

		edt.roleDescriptorOrIDPSSODescriptorOrSPSSODescriptor[0].extensions.any[1].name.localPart == "DiscoHints"
		edt.roleDescriptorOrIDPSSODescriptorOrSPSSODescriptor[0].extensions.any[1].value.ipHintOrDomainHintOrGeolocationHint.size() == 4

		edt.roleDescriptorOrIDPSSODescriptorOrSPSSODescriptor[0].extensions.any[2].name.localPart == "RequestedPrincipalSelection"
		edt.roleDescriptorOrIDPSSODescriptorOrSPSSODescriptor[0].extensions.any[2].value.matchValue.size() == 2
		edt.roleDescriptorOrIDPSSODescriptorOrSPSSODescriptor[0].extensions.any[2].value.matchValue[0].name == "urn:oid:1.2.752.29.4.13"
		edt.roleDescriptorOrIDPSSODescriptorOrSPSSODescriptor[0].extensions.any[2].value.matchValue[1].name == "urn:oid:1.2.752.29.4.14"
	}

	def "Verify that parser can parse a MD document containing md attributes"(){
		when:
		EntityDescriptorType edt = smdmp.parseMessage(null,MDWithUIElementsAndAttrAndRequestedPricipalSelection,false)
		then:
		edt.extensions.any.size() == 1
		edt.extensions.any[0].name.localPart == "EntityAttributes"
		edt.extensions.any[0].value.attributeOrAssertion.size() == 1
		edt.extensions.any[0].value.attributeOrAssertion[0].attributeValue.size() == 6
	}

	private ExtensionsType createExtensions(){
		return smdmp.genExtensions([dsignObj.createKeyName("SomeKeyName")])
	}

	private ExtensionsType createRequestedPrincipalSelectionExtensions(){
		MatchValueType mv1 = new MatchValueType()
		mv1.name = "urn:oid:1.2.752.29.4.13"
		MatchValueType mv2 = new MatchValueType()
		mv2.name = "urn:oid:1.2.752.29.4.14"
		def rpcs = new PrincipalSelectionGenerator().genRequestedPrincipalSelectionElement([mv1,mv2])
		return smdmp.genExtensions([rpcs])
	}

	private List<Object> createAnyXML(){
		return [dsignObj.createKeyName("SomeKeyName1"),dsignObj.createKeyName("SomeKeyName2")]
	}

	private List<LocalizedNameType> createOrganizationNames(){
		LocalizedNameType orgENName = mdOf.createLocalizedNameType()
		orgENName.lang = "en"
		orgENName.value = "SomeCompany"
		LocalizedNameType orgSVName = mdOf.createLocalizedNameType()
		orgSVName.lang = "sv"
		orgSVName.value = "Namn"
		return [orgENName, orgSVName]
	}

	private List<LocalizedNameType> createOrganizationDisplayNames(){
		LocalizedNameType orgENDisplayName = mdOf.createLocalizedNameType()
		orgENDisplayName.lang = "en"
		orgENDisplayName.value = "Some Company"
		LocalizedNameType orgSVDisplayName = mdOf.createLocalizedNameType()
		orgSVDisplayName.lang = "sv"
		orgSVDisplayName.value = "VisbartNamn"
		return [orgENDisplayName, orgSVDisplayName]
	}

	private List<LocalizedNameType> createOrganizationURLs(){
		LocalizedURIType orgENURI = mdOf.createLocalizedURIType()
		orgENURI.lang = "en"
		orgENURI.value = "http://en.someorg.org"
		LocalizedURIType orgSVURI = mdOf.createLocalizedURIType()
		orgSVURI.lang = "sv"
		orgSVURI.value = "http://sv.someorg.org"
		return [orgENURI, orgSVURI]
	}

	private Map<QName,String> createOtherAttributes(){
		Map retval = [:]
		retval.put(new QName("http://www.w3.org/2000/09/xmldsig#","Algorithm"), "http://somealg")
		return retval
	}

	private List<EncryptionMethodType> createEncryptionMethods(){
		org.signatureservice.messages.xenc.jaxb.ObjectFactory encOf = new org.signatureservice.messages.xenc.jaxb.ObjectFactory();
		EncryptionMethodType emt1 = encOf.createEncryptionMethodType()
		emt1.algorithm = "http://alg1"
		EncryptionMethodType emt2 = encOf.createEncryptionMethodType()
		emt2.algorithm = "http://alg2"
		return [emt1,emt2]
	}

	private List<KeyDescriptorType> createKeyDescriptor(){
		return [smdmp.genKeyDescriptor(KeyTypes.ENCRYPTION,secProv.getSigningCertificate(),createEncryptionMethods())]
	}

	private OrganizationType createOrganisation(){
		return smdmp.genOrganization(createExtensions(),createOrganizationNames(),createOrganizationDisplayNames(),
				createOrganizationURLs(),createOtherAttributes())
	}

	private List<ContactType> createContactPersons(){
		return [smdmp.genContactType(ContactTypeType.ADMINISTRATIVE,null, "SomeCompany",null,null,null,null,null),
				smdmp.genContactType(ContactTypeType.BILLING,null, "SomeCompany",null,null,null,null,null)]
	}

	private List<IndexedEndpointType> createArtifactResolutionServices(){
		return [smdmp.genIndexedEndpoint("http://artificatresbinding1.com","http://artificatreslocation1.com", null, 1 , null,null,null),
				smdmp.genIndexedEndpoint("http://artificatresbinding2.com","http://artificatreslocation2.com", null, 1 , null,null,null)]
	}
	private List<EndpointType> createSingleLogoutServices(){
		return [smdmp.genEndpoint("http://slbinding1.com","http://sllocation1.com", null,null,null),
				smdmp.genEndpoint("http://slbinding2.com","http://sllocation2.com", null,null,null)]
	}
	private List<EndpointType> createManageNameIDServices(){
		return [smdmp.genEndpoint("http://mnidbinding1.com","http://mnidlocation1.com", null,null,null),
				smdmp.genEndpoint("http://mnidbinding2.com","http://mnidlocation2.com", null,null,null)]
	}

	private List<EndpointType> createSingleSignOnServices(){
		return [smdmp.genEndpoint("http://ssobinding1.com","http://ssolocation1.com", null,null,null),
				smdmp.genEndpoint("http://ssobinding2.com","http://ssolocation2.com", null,null,null)]
	}

	private List<EndpointType> createNameIDMappingServices(){
		return [smdmp.genEndpoint("http://nidmbinding1.com","http://nidmlocation1.com", null,null,null),
				smdmp.genEndpoint("http://nidmbinding2.com","http://nidmlocation2.com", null,null,null)]
	}

	private List<EndpointType> createAssertionIDRequestServices(){
		return [smdmp.genEndpoint("http://aidrbinding1.com","http://aidrlocation1.com", null,null,null),
				smdmp.genEndpoint("http://aidrbinding2.com","http://aidrlocation2.com", null,null,null)]
	}

	private List<AttributeType> createSAMLAttributes(){
		AttributeType attr1 = of.createAttributeType()
		attr1.name = "SomeAttr1"
		attr1.attributeValue.add("SomeValue1")
		AttributeType attr2 = of.createAttributeType()
		attr2.name = "SomeAttr2"
		attr2.attributeValue.add("SomeValue2")
		return [attr1, attr2]
	}

	private List<RequestedAttributeType> createRequestedAttributes(){
		RequestedAttributeType attr1 = mdOf.createRequestedAttributeType();
		attr1.name = "SomeAttr1"
		attr1.attributeValue.add("SomeValue1")
		attr1.setIsRequired(true);
		RequestedAttributeType attr2 = mdOf.createRequestedAttributeType();
		attr2.name = "SomeAttr2"
		attr2.attributeValue.add("SomeValue2")
		return [attr1, attr2]
	}

	private List<LocalizedNameType> createServiceDescriptions(){
		LocalizedNameType enName = mdOf.createLocalizedNameType()
		enName.lang = "en"
		enName.value = "ServiceDescription"
		LocalizedNameType svName = mdOf.createLocalizedNameType()
		svName.lang = "sv"
		svName.value = "TjänstBeskr"
		return [enName, svName]
	}

	private List<LocalizedNameType> createServiceNames(){
		LocalizedNameType enName = mdOf.createLocalizedNameType()
		enName.lang = "en"
		enName.value = "ServiceName"
		LocalizedNameType svName = mdOf.createLocalizedNameType()
		svName.lang = "sv"
		svName.value = "TjänstNamn"
		return [enName, svName]
	}

	private List<IndexedEndpointType> createAssertionConsumerServices(){
		return [smdmp.genIndexedEndpoint("http://acbinding1.com","http://aclocation1.com", null, 1 , null,null,null),
				smdmp.genIndexedEndpoint("http://acbinding2.com","http://aclocation2.com", null, 1 , null,null,null)]
	}

	private List<AttributeConsumingServiceType> createAttributeConsumingServices(){
		return [smdmp.genAttributeConsumingService(1,true,createServiceNames(),createServiceDescriptions(),createRequestedAttributes())]
	}

	private IDPSSODescriptorType createIDP(){
		return smdmp.genIDPSSODescriptor(null,null,["urn:oasis:names:tc:SAML:2.0:protocol"],
				null, null, null,null, null,null, null,
				null,null,null,
				null, createSingleSignOnServices(),null,null,null,null	)
	}

	private SPSSODescriptorType createSP(){
		return smdmp.genSPSSODescriptor(null,null,["urn:oasis:names:tc:SAML:2.0:protocol"],
				null, null, null,null, null,null, null,
				null,null,null,
				null, null,createAssertionConsumerServices(),null)
	}

	private List<AdditionalMetadataLocationType> createMetadataLocations(){
		AdditionalMetadataLocationType t = mdOf.createAdditionalMetadataLocationType()
		t.setNamespace(DefaultCSMessageParser.XMLDSIG_NAMESPACE)
		t.value="http://somevalue"
		return [t]
	}

	private AffiliationDescriptorType createAffiliationDescriptor(){
		AffiliationDescriptorType t = mdOf.createAffiliationDescriptorType()
		t.setAffiliationOwnerID("SomeOwnerId")
		t.getAffiliateMember().add("SomeMember")
		return t
	}



	static final MDWithUIElementsAndAttrAndRequestedPricipalSelection = """
<EntityDescriptor entityID="https://idp.switch.ch/idp/shibboleth" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <Extensions>
    <mdattr:EntityAttributes
          xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute">
      <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            Name="FinnishAuthMethod"
            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" 
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
              xsi:type="xs:string">
          urn:oid:1.2.246.517.3002.110.1
        </saml:AttributeValue>
        <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" 
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
              xsi:type="xs:string">
          urn:oid:1.2.246.517.3002.110.2
        </saml:AttributeValue>
        <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" 
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
              xsi:type="xs:string">
          urn:oid:1.2.246.517.3002.110.3
        </saml:AttributeValue>
        <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" 
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
              xsi:type="xs:string">
          urn:oid:1.2.246.517.3002.110.5
        </saml:AttributeValue>
        <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" 
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
              xsi:type="xs:string">
          urn:oid:1.2.246.517.3002.110.6
        </saml:AttributeValue>
        <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" 
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
              xsi:type="xs:string">
          urn:oid:1.2.246.517.3002.110.999
        </saml:AttributeValue>
      </saml:Attribute>
    </mdattr:EntityAttributes>
  </Extensions>
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <Extensions>
      <mdui:UIInfo>
        <mdui:DisplayName xml:lang="en">SWITCH</mdui:DisplayName>
        <mdui:DisplayName xml:lang="de">SWITCH</mdui:DisplayName>
        <mdui:Description xml:lang="en">
            Switzerland's national research and eduction network.
        </mdui:Description>
        <mdui:Description xml:lang="de">
            Das schweizerische Hochschul- und Forschungsnetzwerk.
        </mdui:Description>
        <mdui:Logo height="16" width="16">https://switch.ch/resources/images/smalllogo.png</mdui:Logo>
        <mdui:Logo height="97" width="172">https://switch.ch/resources/images/logo.png</mdui:Logo>
        <mdui:InformationURL xml:lang="en">http://switch.ch</mdui:InformationURL>
        <mdui:InformationURL xml:lang="de">http://switch.ch/de</mdui:InformationURL>
      </mdui:UIInfo>
      <mdui:DiscoHints>
        <mdui:IPHint>130.59.0.0/16</mdui:IPHint>
        <mdui:IPHint>2001:620::0/96</mdui:IPHint>
        <mdui:DomainHint>switch.ch</mdui:DomainHint>
        <mdui:GeolocationHint>geo:47.37328,8.531126</mdui:GeolocationHint>
      </mdui:DiscoHints>
      <psc:RequestedPrincipalSelection 
         xmlns:psc="http://id.swedenconnect.se/authn/1.0/principal-selection/ns">
      <psc:MatchValue Name="urn:oid:1.2.752.29.4.13" />
      <psc:MatchValue Name="urn:oid:1.2.752.29.4.14" />
    </psc:RequestedPrincipalSelection>
    </Extensions>
    <SingleSignOnService Binding="http://ssobinding1.com" Location="http://ssolocation1.com"/>
  </IDPSSODescriptor>
</EntityDescriptor>""".getBytes("UTF-8")



}
