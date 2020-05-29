package org.certificateservices.messages.saml2.metadata;

import org.certificateservices.messages.ContextMessageSecurityProvider;
import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.MessageSecurityProvider;
import org.certificateservices.messages.csmessages.DefaultCSMessageParser;
import org.certificateservices.messages.csmessages.XSDLSInput;
import org.certificateservices.messages.saml2.BaseSAMLMessageParser;
import org.certificateservices.messages.saml2.assertion.jaxb.AssertionType;
import org.certificateservices.messages.saml2.assertion.jaxb.AttributeType;
import org.certificateservices.messages.saml2.metadata.attr.jaxb.EntityAttributesType;
import org.certificateservices.messages.saml2.metadata.jaxb.*;
import org.certificateservices.messages.saml2.metadata.ui.jaxb.DiscoHintsType;
import org.certificateservices.messages.saml2.metadata.ui.jaxb.KeywordsType;
import org.certificateservices.messages.saml2.metadata.ui.jaxb.LogoType;
import org.certificateservices.messages.saml2.metadata.ui.jaxb.UIInfoType;
import org.certificateservices.messages.utils.MessageGenerateUtils;
import org.certificateservices.messages.utils.XMLSigner;
import org.certificateservices.messages.xenc.jaxb.EncryptionMethodType;
import org.certificateservices.messages.xmldsig.jaxb.KeyInfoType;
import org.certificateservices.messages.xmldsig.jaxb.X509DataType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBElement;
import javax.xml.datatype.Duration;
import javax.xml.namespace.QName;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * SAML Meta Data Message Parser for generating EntitiesDescriptor and EntityDescriptor.
 * <p>
 *     The parser will sign the root element only of generated documents, and assume only root element is signed
 *     when verifying signatures.
 * </p>
 *
 * @see <a href="https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf">https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf</a>
 *
 * Created by philip on 02/01/17.
 */
public class SAMLMetaDataMessageParser extends BaseSAMLMessageParser {

    public static final String NAMESPACE = "urn:oasis:names:tc:SAML:2.0:metadata";

    private static final String BASE_JAXB_CONTEXT = "org.certificateservices.messages.saml2.assertion.jaxb:org.certificateservices.messages.saml2.metadata.jaxb:org.certificateservices.messages.saml2.metadata.ui.jaxb:org.certificateservices.messages.saml2.metadata.attr.jaxb:org.certificateservices.messages.xenc.jaxb:org.certificateservices.messages.xmldsig.jaxb";

    protected static final String METADATA_XSD_SCHEMA_2_0_RESOURCE_LOCATION = "/cs-message-saml-schema-metadata-2.0.xsd";

    private SAML2MetaDataSignatureLocationFinder signatureLocationFinder = new SAML2MetaDataSignatureLocationFinder();

    private static ObjectFactory mdOf = new ObjectFactory();
    private static org.certificateservices.messages.saml2.metadata.ui.jaxb.ObjectFactory uiOf = new org.certificateservices.messages.saml2.metadata.ui.jaxb.ObjectFactory();
    private static org.certificateservices.messages.saml2.metadata.attr.jaxb.ObjectFactory attrOf = new org.certificateservices.messages.saml2.metadata.attr.jaxb.ObjectFactory();

    @Override
    public String getNameSpace() {
        return NAMESPACE;
    }

    @Override
    public String getJAXBPackages() {
        return BASE_JAXB_CONTEXT;
    }

    @Override
    public String[] getDefaultSchemaLocations() throws SAXException {
        return new String[] {DefaultCSMessageParser.XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION,
                DefaultCSMessageParser.XMLENC_XSD_SCHEMA_RESOURCE_LOCATION,
                ASSERTION_XSD_SCHEMA_2_0_RESOURCE_LOCATION,
                METADATA_XSD_SCHEMA_2_0_RESOURCE_LOCATION};
    }

    @Override
    protected String lookupSchemaForElement(String type, String namespaceURI, String publicId, String systemId, String baseURI) {
        if(namespaceURI != null){
            if(namespaceURI.equals(DefaultCSMessageParser.XMLDSIG_NAMESPACE)){
                return DefaultCSMessageParser.XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION;
            }
            if(namespaceURI.equals(DefaultCSMessageParser.XMLENC_NAMESPACE)){
                return DefaultCSMessageParser.XMLENC_XSD_SCHEMA_RESOURCE_LOCATION;
            }
            if(namespaceURI.equals(NAMESPACE)){
                return METADATA_XSD_SCHEMA_2_0_RESOURCE_LOCATION;
            }
            if(namespaceURI.equals(ASSERTION_NAMESPACE)){
                return BaseSAMLMessageParser.ASSERTION_XSD_SCHEMA_2_0_RESOURCE_LOCATION;
            }
            if(namespaceURI.equals("http://www.w3.org/XML/1998/namespace")){
                return "/xml.xsd";
            }
        }
        return null;
    }

    /**
     * The<EntityDescriptor> element specifies metadata for a single SAML entity. A single entity may act
     * in many different roles in the support of multiple profiles. This specification directly supports the following
     * concrete roles as well as the abstract <RoleDescriptor> element for extensibility (see subsequent sections for
     * more details):
     * <li>SSO Identity Provider</li>
     * <li>SSO Service Provider</li>
     * <li>Authentication Authority</li>
     * <li>Attribute Authority</li>
     * <li>Policy Decision Point</li>
     * <li>Affiliation</li>
     * <p>
     *     When used as the root element of a metadata instance, this element MUST contain either a validUntil
     *     or cacheDuration attribute. It is RECOMMENDED that only the root element of a metadata instance
     *     contain either attribute.
     * </p>
     * <p>
     *     It is RECOMMENDED that if multiple role descriptor elements of the same type appear, that they do not
     *     share overlapping protocolSupportEnumeration values. Selecting from among multiple role
     *     descriptor elements of the same type that do share a protocolSupportEnumeration value is
     *     undefined within this specification, but MAY be defined by metadata profiles, possibly through the use of
     *     other distinguishing extension attributes.
     * </p>
     *
     * @param entityID Specifies the unique identifier of the SAML entity whose metadata is described by the element's
     *                 contents. (Required)
     * @param validUntil Optional attribute indicates the expiration time of the metadata contained in the element
     *                   and any contained elements. (Optional, use null to not set).
     * @param cacheDuration Optional attribute indicates the maximum length of time a consumer should cache the metadata
     *                      contained in the element and any contained elements. (Optional, use null to not set).
     * @param extensions This contains optional metadata extensions that are agreed upon between a metadata publisher
     *                   and consumer. Extension elements MUST be namespace-qualified by a non-SAML-defined
     *                   namespace. (Optional, use null to not set).
     * @param descriptors The primary content of the element is either a sequence of one or more role descriptor elements,
     *                    or a specialized descriptor that defines an affiliation. Either a list of RoleDescriptorType or One
     *                    AffiliationDescriptorType.
     * @param organisation Optional element i dentifying the organization responsible for the SAML entity described by the
     *                     element. (Optional, use null to not set).
     * @param contactPersons Optional sequence of elements identifying various kinds of contact personnel. (Optional,
     *                       use null to not set).
     * @param additionalMetadataLocations Optional sequence of namespace-qualified locations where additional metadata exists for
     *                                    the SAML entity. This may include metadata in alternate formats or describing
     *                                    adherence to other non-SAML specifications. (Optional, use null to not set).
     * @param otherAttributes Arbitrary namespace-qualified attributes from non-SAML-defined namespaces. (Optional, use null to not set).
     * @return a populated EntityDescriptorType
     * @throws MessageProcessingException if internal error occurred generating the message.
     * @throws MessageContentException if bad message format was detected.
     */
    public EntityDescriptorType genEntityDescriptor(String entityID, Date validUntil, Duration cacheDuration,
                                                         ExtensionsType extensions, List<Object> descriptors,
                                                         OrganizationType organisation, List<ContactType> contactPersons,
                                                         List<AdditionalMetadataLocationType> additionalMetadataLocations,
                                                         Map<QName, String> otherAttributes) throws MessageProcessingException, MessageContentException {
        EntityDescriptorType edt = mdOf.createEntityDescriptorType();
        if(entityID == null){
            throw new MessageContentException("Error a entityID must be set to a Entity Descriptor.");
        }
        edt.setEntityID(entityID);
        edt.setID("_" + MessageGenerateUtils.generateRandomUUID());
        edt.setValidUntil(MessageGenerateUtils.dateToXMLGregorianCalendarNoTimeZone(validUntil));
        edt.setCacheDuration(cacheDuration);
        edt.setExtensions(extensions);

        if(descriptors != null){
            if(descriptors.size() == 1 && descriptors.get(0) instanceof AffiliationDescriptorType){
                edt.setAffiliationDescriptor((AffiliationDescriptorType) descriptors.get(0));
            }else{
                for(Object descriptor : descriptors){
                    if(descriptor instanceof RoleDescriptorType){
                        edt.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor().add((RoleDescriptorType) descriptor);
                    }
                    if(descriptor instanceof  AffiliationDescriptorType){
                        throw new MessageContentException("Error in Entity Descriptor data, cannot mix AffiliationDescriptorType with other types.");
                    }
                }
            }
        }

        if(edt.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor().size() == 0 && edt.getAffiliationDescriptor() == null){
            throw new MessageContentException("Error in Entity Descriptor data, at least one descriptor must exist.");
        }

        edt.setOrganization(organisation);
        if(contactPersons != null){
            edt.getContactPerson().addAll(contactPersons);
        }
        if(additionalMetadataLocations != null){
            edt.getAdditionalMetadataLocation().addAll(additionalMetadataLocations);
        }

        if(otherAttributes != null){
            edt.getOtherAttributes().putAll(otherAttributes);
        }
        return edt;
    }

    /**
     * The<EntityDescriptor> element specifies metadata for a single SAML entity. A single entity may act
     * in many different roles in the support of multiple profiles. This specification directly supports the following
     * concrete roles as well as the abstract <RoleDescriptor> element for extensibility (see subsequent sections for
     * more details):
     * <li>SSO Identity Provider</li>
     * <li>SSO Service Provider</li>
     * <li>Authentication Authority</li>
     * <li>Attribute Authority</li>
     * <li>Policy Decision Point</li>
     * <li>Affiliation</li>
     * <p>
     *     When used as the root element of a metadata instance, this element MUST contain either a validUntil
     *     or cacheDuration attribute. It is RECOMMENDED that only the root element of a metadata instance
     *     contain either attribute.
     * </p>
     * <p>
     *     It is RECOMMENDED that if multiple role descriptor elements of the same type appear, that they do not
     *     share overlapping protocolSupportEnumeration values. Selecting from among multiple role
     *     descriptor elements of the same type that do share a protocolSupportEnumeration value is
     *     undefined within this specification, but MAY be defined by metadata profiles, possibly through the use of
     *     other distinguishing extension attributes.
     * </p>
     *
     * @param context message security related context. Use null if no signature should be used.
     * @param entityID Specifies the unique identifier of the SAML entity whose metadata is described by the element's
     *                 contents. (Required)
     * @param validUntil Optional attribute indicates the expiration time of the metadata contained in the element
     *                   and any contained elements. (Optional, use null to not set).
     * @param cacheDuration Optional attribute indicates the maximum length of time a consumer should cache the metadata
     *                      contained in the element and any contained elements. (Optional, use null to not set).
     * @param extensions This contains optional metadata extensions that are agreed upon between a metadata publisher
     *                   and consumer. Extension elements MUST be namespace-qualified by a non-SAML-defined
     *                   namespace. (Optional, use null to not set).
     * @param descriptors The primary content of the element is either a sequence of one or more role descriptor elements,
     *                    or a specialized descriptor that defines an affiliation. Either a list of RoleDescriptorType or One
     *                    AffiliationDescriptorType.
     * @param organisation Optional element i dentifying the organization responsible for the SAML entity described by the
     *                     element. (Optional, use null to not set).
     * @param contactPersons Optional sequence of elements identifying various kinds of contact personnel. (Optional,
     *                       use null to not set).
     * @param additionalMetadataLocations Optional sequence of namespace-qualified locations where additional metadata exists for
     *                                    the SAML entity. This may include metadata in alternate formats or describing
     *                                    adherence to other non-SAML specifications. (Optional, use null to not set).
     * @param otherAttributes Arbitrary namespace-qualified attributes from non-SAML-defined namespaces. (Optional, use null to not set).
     * @param sign if returned message should contain a signature.
     * @return marshalled xml message in UTF-8 encoded byte array.
     * @throws MessageProcessingException if internal error occurred generating the message.
     * @throws MessageContentException if bad message format was detected.
     */
    public byte[] genEntityDescriptor(ContextMessageSecurityProvider.Context context,String entityID, Date validUntil, Duration cacheDuration,
                                      ExtensionsType extensions, List<Object> descriptors,
                                      OrganizationType organisation, List<ContactType> contactPersons,
                                      List<AdditionalMetadataLocationType> additionalMetadataLocations,
                                      Map<QName, String> otherAttributes, boolean sign) throws MessageProcessingException, MessageContentException {
        EntityDescriptorType edt = genEntityDescriptor(entityID, validUntil, cacheDuration, extensions, descriptors, organisation, contactPersons, additionalMetadataLocations, otherAttributes);
        JAXBElement<EntityDescriptorType> ed = mdOf.createEntityDescriptor(edt);
        if(sign){
            return marshallAndSign(context,ed);
        }
        return marshall(ed);
    }

    /**
     * The EntitiesDescriptor element contains the metadata for an optionally named group of SAML
     * entities. Its EntitiesDescriptor Type complex type contains a sequence of EntityDescriptor
     * elements, EntitiesDescriptor elements, or both. ID is generated automatically.
     *
     * @param validUntil Optional attribute indicates the expiration time of the metadata contained in the element
     *                   and any contained elements. (Optional, use null to not set).
     * @param cacheDuration Optional attribute indicates the maximum length of time a consumer should cache the metadata
     *                      contained in the element and any contained elements. (Optional, use null to not set).
     * @param name A string name that identifies a group of SAML entities in the context of some deployment.
     *             (Optional, use null to not set).
     * @param extensions This contains optional metadata extensions that are agreed upon between a metadata publisher
     *                   and consumer. Extension elements MUST be namespace-qualified by a non-SAML-defined
     *                   namespace. (Optional, use null to not set).
     * @param entityDescriptors Contains the metadata for one or more SAML entities, or a nested group of
     *                          additional metadata. (One is required)
     * @return a populated EntitiesDescriptorType
     * @throws MessageProcessingException if internal error occurred generating the message.
     */
    public EntitiesDescriptorType genEntitiesDescriptor(Date validUntil, Duration cacheDuration, String name,
                                                        ExtensionsType extensions, List<Object> entityDescriptors) throws MessageProcessingException {
        EntitiesDescriptorType edt = mdOf.createEntitiesDescriptorType();
        edt.setID("_" + MessageGenerateUtils.generateRandomUUID());
        edt.setValidUntil(MessageGenerateUtils.dateToXMLGregorianCalendarNoTimeZone(validUntil));
        edt.setCacheDuration(cacheDuration);
        edt.setExtensions(extensions);
        edt.setName(name);
        if(entityDescriptors != null){
            edt.getEntityDescriptorOrEntitiesDescriptor().addAll(entityDescriptors);
        }
        return edt;
    }

    /**
     * The EntitiesDescriptor element contains the metadata for an optionally named group of SAML
     * entities. Its EntitiesDescriptor Type complex type contains a sequence of EntityDescriptor
     * elements, EntitiesDescriptor elements, or both. ID is generated automatically.
     *
     * @param context message security related context. Use null if no signature should be used.
     * @param validUntil Optional attribute indicates the expiration time of the metadata contained in the element
     *                   and any contained elements. (Optional, use null to not set).
     * @param cacheDuration Optional attribute indicates the maximum length of time a consumer should cache the metadata
     *                      contained in the element and any contained elements. (Optional, use null to not set).
     * @param name A string name that identifies a group of SAML entities in the context of some deployment.
     *             (Optional, use null to not set).
     * @param extensions This contains optional metadata extensions that are agreed upon between a metadata publisher
     *                   and consumer. Extension elements MUST be namespace-qualified by a non-SAML-defined
     *                   namespace. (Optional, use null to not set).
     * @param entityDescriptors Contains the metadata for one or more SAML entities, or a nested group of
     *                          additional metadata. (One is required)
     * @param sign if the returned message should contain a signature.
     * @return marshalled xml message in UTF-8 encoded byte array.
     * @throws MessageProcessingException if internal error occurred generating the message.
     * @throws MessageContentException if bad message format was detected.
     */
    public byte[] genEntitiesDescriptor(ContextMessageSecurityProvider.Context context,Date validUntil, Duration cacheDuration, String name,
                                                        ExtensionsType extensions, List<Object> entityDescriptors,
                                                        boolean sign) throws MessageProcessingException, MessageContentException {
        EntitiesDescriptorType edt = genEntitiesDescriptor(validUntil,cacheDuration,name,extensions,entityDescriptors);
        JAXBElement<EntitiesDescriptorType> ed = mdOf.createEntitiesDescriptor(edt);
        if(sign){
            return marshallAndSign(context,ed);
        }
        return marshall(ed);
    }


    /**
     * The Organization element specifies basic information about an organization responsible for a SAML
     * entity or role. The use of this element is always optional. Its content is informative in nature and does not
     * directly map to any core SAML elements or attributes.
     *
     * @param extensions This contains optional metadata extensions that are agreed upon between a metadata publisher
     *                   and consumer.Extensions MUST NOT include global (non-namespace-qualified) elements or elements
     *                   qualified by a SAML-defined namespace within this element. (Optional, use null to not set).
     * @param organizationName One or more language-qualified names that may or may not be suitable for human
     *                         consumption. (Required)
     * @param organizationDisplayName One or more language-qualified names that are suitable for human consumption. (Required)
     * @param organizationURL One or more language-qualified URIs that specify a location to which to direct a user for additional
     *                        information. Note that the language qualifier refersto the content of the material at the specified
     *                        location. (Required)
     * @param otherAttributes Arbitrary namespace-qualified attributes from non-SAML-defined namespaces. (Optional, use null to not set).
     * @return a populated OrganizationType
     * @throws MessageContentException if bad message format was detected.
     */
    public OrganizationType genOrganization(ExtensionsType extensions, List<LocalizedNameType> organizationName,
                                            List<LocalizedNameType>  organizationDisplayName, List<LocalizedURIType> organizationURL,
                                            Map<QName, String> otherAttributes) throws MessageContentException{
        checkAtLeastOneInList(organizationName,"Organisation", "OrganizationName");
        checkAtLeastOneInList(organizationDisplayName,"Organisation", "OrganizationDisplayName");
        checkAtLeastOneInList(organizationURL,"Organisation", "OrganizationURL");

        OrganizationType o = mdOf.createOrganizationType();
        o.setExtensions(extensions);
        o.getOrganizationName().addAll(organizationName);
        o.getOrganizationDisplayName().addAll(organizationDisplayName);
        o.getOrganizationURL().addAll(organizationURL);

        if(otherAttributes != null){
            o.getOtherAttributes().putAll(otherAttributes);
        }
        return o;
    }

    /**
     * The ContactPerson element specifies basic contact information about a person responsible in some
     * capacity for a SAML entity or role. The use of this element is always optional. Its content is informative in
     * nature and does not directly map to any core SAML elements or attributes.
     *
     * @param contactType Specifies the type of contact using the ContactTypeType enumeration. The possible values are
     *                    technical,support,administrative,billing, and other. (Required)

     * @param extensions This contains optional metadata extensions that are agreed upon between a metadata publisher
     *                   and consumer.Extensions MUST NOT include global (non-namespace-qualified) elements or elements
     *                   qualified by a SAML-defined namespace within this element. (Optional, use null to not set).
     * @param company Optional string element that specifies the name of the company for the contact person. (Optional,
     *                use null to not set).
     * @param givenName Optional string element that specifies the given (first) name of the contact person.(Optional,
     *                use null to not set).
     * @param surName Optional string element that specifies the surname of the contact person. (Optional,
     *                use null to not set).
     * @param emailAddresses Zero or more elements containing mailto: URIs representing e-mail addresses belonging to the
     *                       contact person. (Optional, use null to not set).
     * @param telephoneNumbers Zero or more string elements specifying a telephone number of the
     *                         contact person. (Optional, use null to not set).
     * @param otherAttributes Arbitrary namespace-qualified attributes from non-SAML-defined namespaces.
     *                        (Optional, use null to not set).
     * @return a populated ContactType
     */
    public ContactType genContactType(ContactTypeType contactType, ExtensionsType extensions,
                                      String company, String givenName, String surName, List<String> emailAddresses,
                                      List<String> telephoneNumbers, Map<QName, String> otherAttributes) {
        ContactType ct = mdOf.createContactType();
        ct.setExtensions(extensions);
        ct.setContactType(contactType);
        ct.setCompany(company);
        ct.setGivenName(givenName);
        ct.setSurName(surName);
        if(emailAddresses != null) {
            ct.getEmailAddress().addAll(emailAddresses);
        }
        if(telephoneNumbers != null){
            ct.getTelephoneNumber().addAll(telephoneNumbers);
        }
        if(otherAttributes != null){
            ct.getOtherAttributes().putAll(otherAttributes);
        }

        return ct;
    }

    /**
     * The element provides information about the cryptographic key(s) that an entity uses
     * to sign data or receive encrypted keys, along with additional cryptographic details.
     *
     * @param use Optional attribute specifying the purpose of the key being described. Values are drawn from the
     *            KeyTypes enumeration, and consist of the values encryption and signing. (Optional, use null to not set)

     * @param keyInfo Element that directly or indirectly identifies a key. (Required)
     * @param encryptionMethods Optional element specifying an algorithm and algorithm-specific settings supported by the entity.
     *                          The exact content varies based on the algorithm supported. See [XMLEnc] for the definition of this
     *                          element's xenc:EncryptionMethodType complex type. (Optional, use null to not set)
     * @return a populated KeyDescriptorType
     */
    public KeyDescriptorType genKeyDescriptor(KeyTypes use, KeyInfoType keyInfo, List<EncryptionMethodType> encryptionMethods){
        KeyDescriptorType kdt = mdOf.createKeyDescriptorType();
        kdt.setUse(use);
        kdt.setKeyInfo(keyInfo);
        kdt.getEncryptionMethod().addAll(encryptionMethods);

        return kdt;
    }

    /**
     * Thel method to create a KeyDescriptorType from a certificate.
     *
     * @param use Optional attribute specifying the purpose of the key being described. Values are drawn from the
     *            KeyTypes enumeration, and consist of the values encryption and signing. (Optional, use null to not set)

     * @param certificate The certificate to generate the KeyInfoType from. (Required)
     * @param encryptionMethods Optional element specifying an algorithm and algorithm-specific settings supported by the entity.
     *                          The exact content varies based on the algorithm supported. See [XMLEnc] for the definition of this
     *                          element's xenc:EncryptionMethodType complex type. (Optional, use null to not set)
     * @return a populated KeyDescriptorType
     *  @throws MessageContentException if bad message format or certificate was detected.
     */
    public KeyDescriptorType genKeyDescriptor(KeyTypes use, X509Certificate certificate, List<EncryptionMethodType> encryptionMethods)
            throws MessageContentException{


        X509DataType x509DataType = dsigOf.createX509DataType();
        try {
            x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(dsigOf.createX509DataTypeX509Certificate(certificate.getEncoded()));
        } catch (CertificateEncodingException e) {
            throw new MessageContentException("Error encoding certificate when generating SAML Metadata: " + e.getMessage(),e);
        }

        KeyInfoType kit = dsigOf.createKeyInfoType();
        kit.getContent().add(dsigOf.createX509Data(x509DataType));
        return genKeyDescriptor(use,kit,encryptionMethods);
    }

    /**
     * The complex type EndpointType describes a SAML protocol binding endpoint at which a SAML entity can
     * be sent protocol messages. Various protocol or profile-specific metadata elements are
     * bound to this type.
     *
     * @param binding A required attribute that specifies the SAML binding supported by the endpoint. Each binding is
     *                assigned a URI to identify it. (Required)
     * @param location A required URI attribute that specifies the location of the endpoint. The allowable syntax
     *                 of this URI depends on the protocol binding. (Required)
     * @param responseLocation Optionally specifies a different location to which response messages sent as part
     *                         of the protocol or profile should be sent. The a llowable syntax of this URI
     *                         depends on the protocol binding. (Optional, use null to not set).
     * @param anyXML Non-SAML namespace XML added to the endpoint. (Optional, use null to not set).
     * @param otherAttributes Arbitrary namespace-qualified attributes from non-SAML-defined namespaces.
     *                        (Optional, use null to not set).
     * @return a newly generate endpoint type.
     */
    public EndpointType genEndpoint(String binding, String location,
                                    String responseLocation, List<Object> anyXML, Map<QName, String> otherAttributes){
        EndpointType et = mdOf.createEndpointType();
        populateEndpointType(et,binding,location,responseLocation,anyXML,otherAttributes);
        return et;
    }

    /**
     * The complex type EndpointType describes a SAML protocol binding endpoint at which a SAML entity can
     * be sent protocol messages. Various protocol or profile-specific metadata elements are
     * bound to this type.
     *
     * @param binding A required attribute that specifies the SAML binding supported by the endpoint. Each binding is
     *                assigned a URI to identify it. (Required)
     * @param location A required URI attribute that specifies the location of the endpoint. The allowable syntax
     *                 of this URI depends on the protocol binding. (Required)
     * @param responseLocation Optionally specifies a different location to which response messages sent as part
     *                         of the protocol or profile should be sent. The a llowable syntax of this URI
     *                         depends on the protocol binding. (Optional, use null to not set).
     * @param index A required attribute that assigns a unique integer value to the endpoint so that it can be
     *              referenced in a protocol message. The index value need only be unique within a collection of like
     *              elements contained within the same parent element (i.e., they need not be unique across the
     *              entire instance). (Required)
     * @param isDefault An optional boolean attribute used to designate the default endpoint among an indexed set. If
     *                  omitted, the value is assumed to be false. (Optional, use null to not set).
     * @param anyXML Non-SAML namespace XML added to the endpoint. (Optional, use null to not set).
     * @param otherAttributes Arbitrary namespace-qualified attributes from non-SAML-defined namespaces.
     *                        (Optional, use null to not set).
     * @return a newly generate endpoint type.
     */
    public IndexedEndpointType genIndexedEndpoint(String binding, String location,
                                    String responseLocation, int index, Boolean isDefault,
                                    List<Object> anyXML, Map<QName, String> otherAttributes){
        IndexedEndpointType et = mdOf.createIndexedEndpointType();
        populateEndpointType(et,binding,location,responseLocation,anyXML,otherAttributes);
        et.setIndex(index);
        et.setIsDefault(isDefault);
        return et;
    }

    /**
     * The IDPSSODescriptor element extends SSODescriptorType with content reflecting profiles
     * specific to identity providers supporting SSO
     *
     * @param validUntil Optional attribute indicates the expiration time of the metadata
     *                   contained in the element and any contained elements. (Optional, use null to not set).
     * @param cacheDuration Optional attribute indicates the maximum length of time a consumer should cache the metadata
     *                      contained in the element and any contained elements. (Optional, use null to not set).
     * @param protocolSupportEnumeration set of URIs that identify the set of protocol specifications supported by the
     *                                   role element. For SAML V2.0 entities, this set MUST include the SAML protocol
     *                                   namespace URI,urn:oasis:names:tc:SAML:2.0:protocol. Note that future SAML
     *                                   specifications might share the same namespace URI, but SHOULD provide
     *                                   alternate "protocol support" identifiers to ensure discrimination when necessary.
     *                                   (Required)
     * @param errorURL Optional URI attribute that specifies a location to direct a user for problem resolution and
     *                 additional support related to this role. (Optional, use null to not set).
     * @param extensions This contains optional metadata extensions that are agreed upon between a
     *                   metadata publisher and consumer. Extension elements MUST be namespace-qualified by
     *                   a non-SAML-defined namespace. (Optional, use null to not set).
     * @param keyDescriptorTypes Optional sequence of elements that provides information about the cryptographic keys
     *                           that the entity uses when acting in this role. (Optional, use null to not set).
     * @param organisation Optional element specifies the organization associated with this role. (Optional, use null to not set).
     * @param contactPersons Optional sequence of elements specifying contacts associated with this role. (Optional, use null to not set).
     * @param otherAttributes Arbitrary namespace-qualified attributes from non-SAML-defined namespaces.
     *                        (Optional, use null to not set).
     * @param artifactResolutionService Zero or more elements of type IndexedEndpointType
     *                          that describe indexed endpoints that support the Artifact
     *                          Resolution profile defined in [SAMLProf]. The ResponseLocation
     *                          attribute MUST be omitted. (Optional, use null to not set).
     * @param singleLogoutService Zero or more elements of type EndpointType that describe
     *                                  endpoints that support the Single Logout profiles defined in
     *                                  [SAMLProf]. (Optional, use null to not set).
     * @param manageNameIDService Zero or more elements of type EndpointType that describe endpoints that
     *                            support the Name Identifier Management profiles defined in [SAMLProf].
     *                            (Optional, use null to not set).
     * @param nameIDFormat Zero or more elements of type anyURI that enumerate the name identifier formats supported by
     *                     this system entity acting in this role. See Section 8.3 of [SAMLCore] for some possible values for
     *                     this element. (Optional, use null to not set).
     * @param wantAuthnRequestsSigned Optional attribute that indicates a requirement for the samlp:AuthnRequest
     *                                messages received by this identity provider to be signed. If omitted,
     *                                the value is assumed to be false. (Optional, use null to not set).
     * @param singleSignOnServices One or more elements of type EndpointType that describe endpoints that support
     *                             the profiles of the Authentication Request protocol defined in [SAMLProf].
     *                             All identity providers support at least one such endpoint, by definition. The
     *                             ResponseLocation attribute MUST be omitted. (One Required)
     * @param nameIDMappingServices Zero or more elements of type EndpointType that describe endpoints that support the Name
     *                              Identifier Mapping profile defined in [SAMLProf]. The ResponseLocation attribute MUST be
     *                              omitted. (Optional, use null to not set).
     * @param assertionIDRequestServices Zero or more elements of type EndpointType that describe endpoints that support
     *                                   the profile of the Assertion Request protocol defined in [SAMLProf] or the special
     *                                   URI binding for assertion requests defined in [SAMLBind]. (Optional, use null to not set).
     * @param attributeProfiles Zero or more elements of type anyURI that enumerate the attribute profiles supported by this
     *                          identity provider. See [SAMLProf] for some possible values for this element.
     *                          (Optional, use null to not set).
     * @param attributes Zero or more elements that identify the SAML attributes supported by the identity provider.
     *                   Specific values MAY optionally be included, indicating that only certain values permitte
     *                   d by the attribute's definition are supported. In this context, "support" for an attribute
     *                   means that the identity provider has the capability to include it when delivering assertions
     *                   during single sign-on.(Optional, use null to not set).
     * @return a newly populated IDPSSODescriptorType
     * @throws MessageProcessingException if internal error occurred generating the message.
     * @throws MessageContentException if bad message format was detected.
     */
    public IDPSSODescriptorType genIDPSSODescriptor(Date validUntil, Duration cacheDuration,
                                                    List<String> protocolSupportEnumeration,
                                                    String errorURL, ExtensionsType extensions, List<KeyDescriptorType> keyDescriptorTypes,
                                                    OrganizationType organisation, List<ContactType> contactPersons,
                                                    Map<QName, String> otherAttributes,
                                                    List<IndexedEndpointType> artifactResolutionService,
                                                    List<EndpointType> singleLogoutService, List<EndpointType> manageNameIDService,
                                                    List<String> nameIDFormat, Boolean wantAuthnRequestsSigned,
                                                    List<EndpointType> singleSignOnServices,
                                                    List<EndpointType> nameIDMappingServices,
                                                    List<EndpointType> assertionIDRequestServices,
                                                    List<String> attributeProfiles,
                                                    List<AttributeType> attributes) throws MessageProcessingException, MessageContentException {
        IDPSSODescriptorType dt = mdOf.createIDPSSODescriptorType();
        populateRoleDescriptor(dt,validUntil,cacheDuration,protocolSupportEnumeration,errorURL,extensions,
                keyDescriptorTypes,organisation,contactPersons,otherAttributes);
        populateSSODescriptor(dt,artifactResolutionService,singleLogoutService,manageNameIDService,nameIDFormat);
        dt.setWantAuthnRequestsSigned(wantAuthnRequestsSigned);
        if(singleSignOnServices != null){
            dt.getSingleSignOnService().addAll(singleSignOnServices);
        }
        if(nameIDMappingServices != null){
            dt.getNameIDMappingService().addAll(nameIDMappingServices);
        }
        if(assertionIDRequestServices != null){
            dt.getAssertionIDRequestService().addAll(assertionIDRequestServices);
        }
        if(attributeProfiles != null){
            dt.getAttributeProfile().addAll(attributeProfiles);
        }
        if(attributes != null){
            dt.getAttribute().addAll(attributes);
        }
        return dt;
    }

    /**
     * The IDPSSODescriptor element extends SSODescriptorType with content reflecting profiles
     * specific to identity providers supporting SSO
     *
     * @param validUntil Optional attribute indicates the expiration time of the metadata
     *                   contained in the element and any contained elements. (Optional, use null to not set).
     * @param cacheDuration Optional attribute indicates the maximum length of time a consumer should cache the metadata
     *                      contained in the element and any contained elements. (Optional, use null to not set).
     * @param protocolSupportEnumeration set of URIs that identify the set of protocol specifications supported by the
     *                                   role element. For SAML V2.0 entities, this set MUST include the SAML protocol
     *                                   namespace URI,urn:oasis:names:tc:SAML:2.0:protocol. Note that future SAML
     *                                   specifications might share the same namespace URI, but SHOULD provide
     *                                   alternate "protocol support" identifiers to ensure discrimination when necessary.
     *                                   (Required)
     * @param errorURL Optional URI attribute that specifies a location to direct a user for problem resolution and
     *                 additional support related to this role. (Optional, use null to not set).
     * @param extensions This contains optional metadata extensions that are agreed upon between a
     *                   metadata publisher and consumer. Extension elements MUST be namespace-qualified by
     *                   a non-SAML-defined namespace. (Optional, use null to not set).
     * @param keyDescriptorTypes Optional sequence of elements that provides information about the cryptographic keys
     *                           that the entity uses when acting in this role. (Optional, use null to not set).
     * @param organisation Optional element specifies the organization associated with this role. (Optional, use null to not set).
     * @param contactPersons Optional sequence of elements specifying contacts associated with this role. (Optional, use null to not set).
     * @param otherAttributes Arbitrary namespace-qualified attributes from non-SAML-defined namespaces.
     *                        (Optional, use null to not set).
     * @param artifactResolutionService Zero or more elements of type IndexedEndpointType
     *                          that describe indexed endpoints that support the Artifact
     *                          Resolution profile defined in [SAMLProf]. The ResponseLocation
     *                          attribute MUST be omitted. (Optional, use null to not set).
     * @param singleLogoutService Zero or more elements of type EndpointType that describe
     *                                  endpoints that support the Single Logout profiles defined in
     *                                  [SAMLProf]. (Optional, use null to not set).
     * @param manageNameIDService Zero or more elements of type EndpointType that describe endpoints that
     *                            support the Name Identifier Management profiles defined in [SAMLProf].
     *                            (Optional, use null to not set).
     * @param nameIDFormat Zero or more elements of type anyURI that enumerate the name identifier formats supported by
     *                     this system entity acting in this role. See Section 8.3 of [SAMLCore] for some possible values for
     *                     this element. (Optional, use null to not set).
     * @param authnRequestsSigned Optional attribute that indicates whether the samlp:AuthnRequest messages sent by this
     *                            service provider will be signed. If omitted, the value is assumed to be false.
     *                            (Optional, use null to not set).
     * @param wantAssertionsSigned Optional attribute that indicates a requirement for the saml:Assertion elements received by
     *                             this service provider to be signed. If omitted, the value is assumed to be false.
     *                             This requirement is in addition to any requirement for signing derived from the use of a
     *                             particular profile/binding combination. (Optional, use null to not set).
     * @param assertionConsumerServices One or more elements that describe indexed endpoints that support the profiles of the
     *                                  Authentication Request protocol defined in [SAMLProf]. All service providers support at
     *                                  least one such endpoint, by definition. (One is Required).
     * @param attributeConsumingServices Zero or more elements that describe an application or service provided by the service
     *                                   provider that requires or desires the use of SAML attributes. (Optional, use null to not set).
     * @return a new populated SPSSODescriptorType
     * @throws MessageProcessingException if internal error occurred generating the message.
     * @throws MessageContentException if bad message format was detected.
     */
    public SPSSODescriptorType genSPSSODescriptor(Date validUntil, Duration cacheDuration,
                                                    List<String> protocolSupportEnumeration,
                                                    String errorURL, ExtensionsType extensions, List<KeyDescriptorType> keyDescriptorTypes,
                                                    OrganizationType organisation, List<ContactType> contactPersons,
                                                    Map<QName, String> otherAttributes,
                                                    List<IndexedEndpointType> artifactResolutionService,
                                                    List<EndpointType> singleLogoutService, List<EndpointType> manageNameIDService,
                                                    List<String> nameIDFormat, Boolean authnRequestsSigned, Boolean wantAssertionsSigned,
                                                    List<IndexedEndpointType> assertionConsumerServices,
                                                    List<AttributeConsumingServiceType> attributeConsumingServices
                                                  ) throws MessageProcessingException, MessageContentException {
        SPSSODescriptorType dt = mdOf.createSPSSODescriptorType();
        populateRoleDescriptor(dt,validUntil,cacheDuration,protocolSupportEnumeration,errorURL,extensions,
                keyDescriptorTypes,organisation,contactPersons,otherAttributes);
        populateSSODescriptor(dt,artifactResolutionService,singleLogoutService,manageNameIDService,nameIDFormat);
        dt.setAuthnRequestsSigned(authnRequestsSigned);
        dt.setWantAssertionsSigned(wantAssertionsSigned);
        if(assertionConsumerServices != null){
            dt.getAssertionConsumerService().addAll(assertionConsumerServices);
        }
        if(attributeConsumingServices != null){
            dt.getAttributeConsumingService().addAll(attributeConsumingServices);
        }
        return dt;
    }

    /**
     * The AttributeConsumingService element defines a particular service offered by the service
     * provider in terms of the attributes the service requires or desires.
     *
     * @param index A required attribute that assigns a unique integer value to the element so that it can be referenced
     *              in a protocol message. (Required)
     * @param isDefault Identifies the default service supported by the service provider. Useful if the specific service is not
     *                  otherwise indicated by application context. If omitted, the value is assumed to be false.
     *                  (Optional, use null to not set).
     * @param serviceNames One or more language-qualified names for the service. (One required)
     * @param serviceDescriptions Zero or more language-qualified strings that describe the service. (Optional, use null to not set).
     * @param requestedAttributes One or more elements specifying attributes required or desired by this service. (One required)
     * @return a new populated AttributeConsumingServiceType
     */
    public AttributeConsumingServiceType genAttributeConsumingService(int index, Boolean isDefault,
                                                                      List<LocalizedNameType> serviceNames,
                                                                      List<LocalizedNameType> serviceDescriptions,
                                                                      List<RequestedAttributeType> requestedAttributes){
        AttributeConsumingServiceType t = mdOf.createAttributeConsumingServiceType();
        t.setIndex(index);
        t.setIsDefault(isDefault);
        if(serviceNames != null){
            t.getServiceName().addAll(serviceNames);
        }
        if(serviceDescriptions != null){
            t.getServiceDescription().addAll(serviceDescriptions);
        }
        if(requestedAttributes != null){
            t.getRequestedAttribute().addAll(requestedAttributes);
        }

        return t;
    }

    /**
     * Help method to generate a extensions type to be used with
     *
     * @param extentionObjects list of extensions elements (JAXBElements) to include.
     * @return a newly generated ExtensionsType object.
     */
    public ExtensionsType genExtensions(List<Object> extentionObjects){
        ExtensionsType extensions = mdOf.createExtensionsType();
        extensions.getAny().addAll(extentionObjects);
        return extensions;
    }


    /**
     * Method to generate a MD UIInfo JAXBElement with given child elements.
     *
     * @param childElements a least one child element.
     *
     * @return a new JAXBElement containing a UI info of all child elements.
     * @throws MessageContentException if no child elements where specified.
     */
    public JAXBElement<UIInfoType> genUIInfo(List<JAXBElement<?>> childElements) throws MessageContentException{
        if(childElements == null || childElements.size() == 0){
            throw new MessageContentException("Error constructing UIInfo, at least one child element must exist.");
        }

        UIInfoType uiInfoType = uiOf.createUIInfoType();
        uiInfoType.getDisplayNameOrDescriptionOrKeywords().addAll(childElements);

        return uiOf.createUIInfo(uiInfoType);
    }

    /**
     * Method to generate a MD UI DiscoHints JAXBElement with given child elements.
     *
     * @param childElements a least one child element.
     *
     * @return a new JAXBElement containing a DiscoHints of all child elements.
     * @throws MessageContentException if no child elements where specified.
     */
    public JAXBElement<DiscoHintsType> genUIDiscoHints(List<JAXBElement<?>> childElements) throws MessageContentException{
        if(childElements == null || childElements.size() == 0){
            throw new MessageContentException("Error constructing DiscoHints, at least one child element must exist.");
        }
        DiscoHintsType discoHintsType = uiOf.createDiscoHintsType();
        discoHintsType.getIPHintOrDomainHintOrGeolocationHint().addAll(childElements);
        return uiOf.createDiscoHints(discoHintsType);
    }

    /**
     * Help method to generate a MD UI Logo element. Specifies the external location of a localized logo fit for
     * display to users.
     *
     * @param width The rendered width of the logo measured in pixels.
     * @param heigth The rendered height of the logo measured in pixels.
     * @param uri the URI pointing to the logo.
     * @param lang optional language specifier.
     * @return a JAXBElement containing the logo.
     */
    public JAXBElement<LogoType> genUILogo(int width, int heigth, String uri, String lang){
        LogoType l = uiOf.createLogoType();

        l.setWidth(BigInteger.valueOf(width));
        l.setHeight(BigInteger.valueOf(heigth));
        l.setValue(uri);
        l.setLang(lang);

        return uiOf.createLogo(l);
    }

    /**
     * Help method to generate a MD UI DisplayName element for the specified language. Specifies a localized name fit
     * for display to users. Such names are meant to allow a user to distinguish and identify the entity acting in a
     * particular role. The content of this element should be suitable for use in constructing accessible user
     * interfaces for those with disabilities.
     *
     * @param name a string display name of related service.
     * @param lang required language specifier.
     * @return a JAXBElement containing the description.
     * @throws MessageContentException if lang is not set.
     */
    public JAXBElement<LocalizedNameType> genUIDisplayName(String name, String lang) throws MessageContentException{
        isSet(lang,"lang attribute is required for MD UI DisplayName");
        LocalizedNameType n = mdOf.createLocalizedNameType();
        n.setValue(name);
        n.setLang(lang);
        return uiOf.createDisplayName(n);
    }

    /**
     * Help method to generate a MD UI Description element for the specified language. Specifies a brief, localized
     * description fit for display to users. In the case of an md:SPSSODescriptor role, this SHOULD be a description
     * of the service being offered. In the case of an md:IDPSSODescriptor role this SHOULD include a description of
     * the user community serviced.
     * <p>
     *     In all cases this text MUST be standalone, meaning it is not to be used as a template requiring additional
     *     text (e.g., "This service offers $description").
     *
     * @param description a string description
     * @param lang required language specifier.
     * @return a JAXBElement containing the description.
     * @throws MessageContentException if lang is not set.
     */
    public JAXBElement<LocalizedNameType> genUIDescription(String description, String lang) throws MessageContentException{
        isSet(lang,"lang attribute is required for MD UI Description");
        LocalizedNameType d = mdOf.createLocalizedNameType();
        d.setValue(description);
        d.setLang(lang);
        return uiOf.createDescription(d);
    }

    /**
     * Help method to generate a MD UI Information URL element for the specified language. Specifies an external
     * location for localized information about the entity acting in a given role meant to be viewed by users. The
     * content found at the URL SHOULD provide more complete information than what would be provided by the
     * mdui:Description element.
     *
     * @param url valid URL.
     * @param lang required language specifier.
     * @return a JAXBElement containing the URL.
     * @throws MessageContentException if lang is not set.
     */
    public JAXBElement<LocalizedURIType> genUIInformationURL(String url, String lang) throws MessageContentException{
        isSet(lang,"lang attribute is required for MD UI InformationURL");
        LocalizedURIType u = mdOf.createLocalizedURIType();
        u.setValue(url);
        u.setLang(lang);
        return uiOf.createInformationURL(u);
    }

    /**
     * Help method to generate a MD UI Privacy Statement URL element for the specified language. Statements are meant to
     * provide a user with information about how information will be used and managed by the entity acting in a given
     * role.
     *
     * @param url valid URL.
     * @param lang required language specifier.
     * @return a JAXBElement containing the URL.
     * @throws MessageContentException if lang is not set.
     */
    public JAXBElement<LocalizedURIType> genUIPrivacyStatementURL(String url, String lang) throws MessageContentException{
        isSet(lang,"lang attribute is required for MD UI PrivacyStatementURL");
        LocalizedURIType u = mdOf.createLocalizedURIType();
        u.setValue(url);
        u.setLang(lang);
        return uiOf.createPrivacyStatementURL(u);
    }

    /**
     * Help method to generate a MD UI Info Keywords element for the specified language. A keyword specifies a list of
     * localized search keywords, tags, categories, or labels that apply to the containing role. This element extends
     * the mdui:listOfStrings schema type with the following attribute.
     *
     * @param keywords a "list" of strings in the XML Schema [Schema2] sense, which means the keyword strings are
     *                 space-delimited. Spaces within individual keywords are encoded with a {@literal "}plus{@literal "} (+) character; as
     *                 a consequence, keywords may not contain that character.
     * @param lang required language specifier.
     * @return a JAXBElement containing the key words
     * @throws MessageContentException if lang is not set.
     */
    public JAXBElement<KeywordsType> genUIKeywords(List<String> keywords, String lang) throws MessageContentException{
        isSet(lang,"lang attribute is required for MD UI Keywords");
        KeywordsType k = uiOf.createKeywordsType();
        for(String keyword : keywords){
            k.getValue().add(keyword.replaceAll(" ","+"));
        }
        k.setLang(lang);
        return uiOf.createKeywords(k);
    }

    /**
     * Help method to generate a MD UI Discovery IP Hint.
     *
     * @param value specifies an [RFC4632] block associated with, or serviced by, the entity.  Both IPv4 and IPv6 CIDR blocks MUST be supported.
     * @return a JAXBElement containing the IP Hint
     */
    public JAXBElement<String> genUIIPHint(String value){
        return uiOf.createIPHint(value);
    }

    /**
     * Help method to generate a MD UI Discovery Domain Hint.
     *
     * @param value specifies a DNS domain associated with, or serviced by, the entity.
     * @return a JAXBElement containing the Domain Hint
     */
    public JAXBElement<String> genUIDomainHint(String value){
        return uiOf.createDomainHint(value);
    }

    /**
     * Help method to generate a MD UI Discovery Geolocation Hint.
     *
     * @param value specifies a set of geographic coordinates associated with, or serviced by, the entity. Coordinates are given in URI form using the geo URI scheme [RFC5870].
     * @return a JAXBElement containing the Geolocation Hint
     */
    public JAXBElement<String> genUIGeolocationHint(String value){
        return uiOf.createGeolocationHint(value);
    }

    /**
     * Help method to generate MD Entity Attribute used as an extension in EntityId
     * @param attributeOrAssertion an array of AttributeType or AssertionType to and to the EntityAttribute element
     * @return a new EntityAttributes element
     * @throws MessageContentException if invalid type was given in list
     */
    public JAXBElement<EntityAttributesType> genMDEntityAttributes(List<Object> attributeOrAssertion) throws MessageContentException{
        EntityAttributesType entityAttributes = attrOf.createEntityAttributesType();

        for(Object o : attributeOrAssertion){
            if(o instanceof AttributeType || o instanceof AssertionType){
                entityAttributes.getAttributeOrAssertion().add(o);
            }else{
                throw new MessageContentException("Error constructing MDAttr EntityAttributes, only AttributeType or AssertionType is allowed as attributes.");
            }

        }

        return attrOf.createEntityAttributes(entityAttributes);
    }

    /**
     * Method that verifies that a given value is set (i.e not null or empty string) or throws MessageContentException with given
     * error message.
     */
    protected void isSet(String value, String errorMessage) throws MessageContentException{
        if(value == null || value.trim().equals("")){
            throw new MessageContentException(errorMessage);
        }
    }

    /**
     * Method to populate the base RoleDescriptor type. ID Attribute is automatically generated.
     *
     * @param roleDescriptor The role descriptor to populate.
     * @param validUntil Optional attribute indicates the expiration time of the metadata
     *                   contained in the element and any contained elements. (Optional, use null to not set).
     * @param cacheDuration Optional attribute indicates the maximum length of time a consumer should cache the metadata
     *                      contained in the element and any contained elements. (Optional, use null to not set).
     * @param protocolSupportEnumeration set of URIs that identify the set of protocol specifications supported by the
     *                                   role element. For SAML V2.0 entities, this set MUST include the SAML protocol
     *                                   namespace URI,urn:oasis:names:tc:SAML:2.0:protocol. Note that future SAML
     *                                   specifications might share the same namespace URI, but SHOULD provide
     *                                   alternate "protocol support" identifiers to ensure discrimination when necessary.
     *                                   (Required)
     * @param errorURL Optional URI attribute that specifies a location to direct a user for problem resolution and
     *                 additional support related to this role. (Optional, use null to not set).
     * @param extensions This contains optional metadata extensions that are agreed upon between a
     *                   metadata publisher and consumer. Extension elements MUST be namespace-qualified by
     *                   a non-SAML-defined namespace. (Optional, use null to not set).
     * @param keyDescriptorTypes Optional sequence of elements that provides information about the cryptographic keys
     *                           that the entity uses when acting in this role. (Optional, use null to not set).
     * @param organisation Optional element specifies the organization associated with this role. (Optional, use null to not set).
     * @param contactPersons Optional sequence of elements specifying contacts associated with this role. (Optional, use null to not set).
     * @param otherAttributes Arbitrary namespace-qualified attributes from non-SAML-defined namespaces.
     *                        (Optional, use null to not set).
     * @throws MessageProcessingException if internal error occurred generating the message.
     * @throws MessageContentException if bad message format was detected.
     */
    protected void populateRoleDescriptor(RoleDescriptorType roleDescriptor,Date validUntil, Duration cacheDuration,
                                                        List<String> protocolSupportEnumeration,
                                                        String errorURL, ExtensionsType extensions, List<KeyDescriptorType> keyDescriptorTypes,
                                                        OrganizationType organisation, List<ContactType> contactPersons,
                                                        Map<QName, String> otherAttributes) throws MessageContentException, MessageProcessingException {

        roleDescriptor.setID("_" + MessageGenerateUtils.generateRandomUUID());
        roleDescriptor.setValidUntil(MessageGenerateUtils.dateToXMLGregorianCalendarNoTimeZone(validUntil));
        roleDescriptor.setCacheDuration(cacheDuration);
        if(protocolSupportEnumeration != null) {
            roleDescriptor.getProtocolSupportEnumeration().addAll(protocolSupportEnumeration);
        }
        roleDescriptor.setErrorURL(errorURL);
        roleDescriptor.setExtensions(extensions);
        if(keyDescriptorTypes != null) {
            roleDescriptor.getKeyDescriptor().addAll(keyDescriptorTypes);
        }
        roleDescriptor.setOrganization(organisation);
        if(contactPersons != null) {
            roleDescriptor.getContactPerson().addAll(contactPersons);
        }
        if(otherAttributes != null) {
            roleDescriptor.getOtherAttributes().putAll(otherAttributes);
        }
    }

    /**
     * The SSODescriptorType abstract type is a common base type for the concrete types
     * SPSSODescriptorType and IDPSSODescriptorType.
     *
     * @param ssoDescriptorType the SSO Descriptor type to populate.
     * @param artifactResolutionService Zero or more elements of type IndexedEndpointType
     *                          that describe indexed endpoints that support the Artifact
     *                          Resolution profile defined in [SAMLProf]. The ResponseLocation
     *                          attribute MUST be omitted. (Optional, use null to not set).
     * @param singleLogoutService Zero or more elements of type EndpointType that describe
     *                                  endpoints that support the Single Logout profiles defined in
     *                                  [SAMLProf]. (Optional, use null to not set).
     * @param manageNameIDService Zero or more elements of type EndpointType that describe endpoints that
     *                            support the Name Identifier Management profiles defined in [SAMLProf].
     *                            (Optional, use null to not set).
     * @param nameIDFormat Zero or more elements of type anyURI that enumerate the name identifier formats supported by
     *                     this system entity acting in this role. See Section 8.3 of [SAMLCore] for some possible values for
     *                     this element.(Optional, use null to not set).
     */
    protected void populateSSODescriptor(SSODescriptorType ssoDescriptorType, List<IndexedEndpointType> artifactResolutionService,
                                         List<EndpointType> singleLogoutService, List<EndpointType> manageNameIDService,
                                         List<String> nameIDFormat){
        if(artifactResolutionService != null) {
            ssoDescriptorType.getArtifactResolutionService().addAll(artifactResolutionService);
        }
        if(singleLogoutService != null){
            ssoDescriptorType.getSingleLogoutService().addAll(singleLogoutService);
        }
        if(manageNameIDService != null) {
            ssoDescriptorType.getManageNameIDService().addAll(manageNameIDService);
        }
        if(nameIDFormat != null) {
            ssoDescriptorType.getNameIDFormat().addAll(nameIDFormat);
        }
    }

    /**
     * Method to populate an endpoint type.
     *
     * @param endpointType the object to populate
     * @param binding A required attribute that specifies the SAML binding supported by the endpoint. Each binding is
     *                assigned a URI to identify it. (Required)
     * @param location A required URI attribute that specifies the location of the endpoint. The allowable syntax
     *                 of this URI depends on the protocol binding. (Required)
     * @param responseLocation Optionally specifies a different location to which response messages sent as part
     *                         of the protocol or profile should be sent. The a llowable syntax of this URI
     *                         depends on the protocol binding. (Optional, use null to not set).
     * @param anyXML Non-SAML namespace XML added to the endpoint. (Optional, use null to not set).
     * @param otherAttributes Arbitrary namespace-qualified attributes from non-SAML-defined namespaces.
     *                        (Optional, use null to not set).
     */
    protected void populateEndpointType(EndpointType endpointType, String binding, String location,
                                        String responseLocation, List<Object> anyXML, Map<QName, String> otherAttributes){
        endpointType.setBinding(binding);
        endpointType.setLocation(location);
        endpointType.setResponseLocation(responseLocation);
        if(anyXML != null) {
            endpointType.getAny().addAll(anyXML);
        }
        if(otherAttributes != null) {
            endpointType.getOtherAttributes().putAll(otherAttributes);
        }
    }

    @Override
    public XMLSigner.SignatureLocationFinder getSignatureLocationFinder() {
        return signatureLocationFinder;
    }

    @Override
    public XMLSigner.OrganisationLookup getOrganisationLookup() {
        return null;
    }


    public static class SAML2MetaDataSignatureLocationFinder implements XMLSigner.SignatureLocationFinder{

        public Element[] getSignatureLocations(Document doc)
                throws MessageContentException {
            try{
                if(doc.getDocumentElement().getNamespaceURI().equals(NAMESPACE)){
                    return new Element[] {doc.getDocumentElement()};
                }
            }catch(Exception e){
            }
            throw new MessageContentException("Invalid SAMLP message type sent for signature.");
        }

        @Override
        public String getIDAttribute() {
            return "ID";
        }

        @Override
        public String getIDValue(Element signedElement) throws MessageContentException {
            return signedElement.getAttribute(getIDAttribute());
        }

        @Override
        public List<QName> getSiblingsBeforeSignature(Element element) throws MessageContentException {
            List<QName> retval = null;
            if(element.getLocalName().equals("EntitiesDescriptor")){
                retval = new ArrayList<QName>();
                retval.add(new QName(NAMESPACE,"Extensions"));
                retval.add(new QName(NAMESPACE,"EntitiesDescriptor"));
                retval.add(new QName(NAMESPACE,"EntityDescriptor"));
            }
            if(element.getLocalName().equals("EntityDescriptor")){
                retval = new ArrayList<QName>();
                retval.add(new QName(NAMESPACE,"Extensions"));
                retval.add(new QName(NAMESPACE,"RoleDescriptor"));
                retval.add(new QName(NAMESPACE,"IDPSSODescriptor"));
                retval.add(new QName(NAMESPACE,"SPSSODescriptor"));
                retval.add(new QName(NAMESPACE,"AuthnAuthorityDescriptor"));
                retval.add(new QName(NAMESPACE,"AttributeAuthorityDescriptor"));
                retval.add(new QName(NAMESPACE,"PDPDescriptor"));
                retval.add(new QName(NAMESPACE,"AffiliationDescriptor"));
            }
            if(element.getLocalName().equals("IDPSSODescriptor")){
                retval = new ArrayList<QName>();
                retval.add(new QName(NAMESPACE,"Extensions"));
                retval.add(new QName(NAMESPACE,"KeyDescriptor"));
                retval.add(new QName(NAMESPACE,"Organization"));
                retval.add(new QName(NAMESPACE,"ContactPerson"));
                retval.add(new QName(NAMESPACE,"ArtifactResolutionService"));
                retval.add(new QName(NAMESPACE,"SingleLogoutService"));
                retval.add(new QName(NAMESPACE,"ManageNameIDService"));
                retval.add(new QName(NAMESPACE,"NameIDFormat"));
                retval.add(new QName(NAMESPACE,"SingleSignOnService"));
            }
            if(element.getLocalName().equals("SPSSODescriptor")){
                retval = new ArrayList<QName>();
                retval.add(new QName(NAMESPACE,"Extensions"));
                retval.add(new QName(NAMESPACE,"KeyDescriptor"));
                retval.add(new QName(NAMESPACE,"Organization"));
                retval.add(new QName(NAMESPACE,"ContactPerson"));
                retval.add(new QName(NAMESPACE,"ArtifactResolutionService"));
                retval.add(new QName(NAMESPACE,"SingleLogoutService"));
                retval.add(new QName(NAMESPACE,"ManageNameIDService"));
                retval.add(new QName(NAMESPACE,"NameIDFormat"));
                retval.add(new QName(NAMESPACE,"AssertionConsumerService"));
            }
            if(element.getLocalName().equals("AuthnAuthorityDescriptor")){
                retval = new ArrayList<QName>();
                retval.add(new QName(NAMESPACE,"Extensions"));
                retval.add(new QName(NAMESPACE,"KeyDescriptor"));
                retval.add(new QName(NAMESPACE,"Organization"));
                retval.add(new QName(NAMESPACE,"ContactPerson"));
                retval.add(new QName(NAMESPACE,"ArtifactResolutionService"));
                retval.add(new QName(NAMESPACE,"SingleLogoutService"));
                retval.add(new QName(NAMESPACE,"ManageNameIDService"));
                retval.add(new QName(NAMESPACE,"NameIDFormat"));
                retval.add(new QName(NAMESPACE,"AuthnQueryService"));
            }
            if(element.getLocalName().equals("AuthnAuthorityDescriptor")){
                retval = new ArrayList<QName>();
                retval.add(new QName(NAMESPACE,"Extensions"));
                retval.add(new QName(NAMESPACE,"KeyDescriptor"));
                retval.add(new QName(NAMESPACE,"Organization"));
                retval.add(new QName(NAMESPACE,"ContactPerson"));
                retval.add(new QName(NAMESPACE,"ArtifactResolutionService"));
                retval.add(new QName(NAMESPACE,"SingleLogoutService"));
                retval.add(new QName(NAMESPACE,"ManageNameIDService"));
                retval.add(new QName(NAMESPACE,"NameIDFormat"));
                retval.add(new QName(NAMESPACE,"AuthzService"));
            }
            if(element.getLocalName().equals("AttributeAuthorityDescriptor")){
                retval = new ArrayList<QName>();
                retval.add(new QName(NAMESPACE,"Extensions"));
                retval.add(new QName(NAMESPACE,"KeyDescriptor"));
                retval.add(new QName(NAMESPACE,"Organization"));
                retval.add(new QName(NAMESPACE,"ContactPerson"));
                retval.add(new QName(NAMESPACE,"ArtifactResolutionService"));
                retval.add(new QName(NAMESPACE,"SingleLogoutService"));
                retval.add(new QName(NAMESPACE,"ManageNameIDService"));
                retval.add(new QName(NAMESPACE,"NameIDFormat"));
                retval.add(new QName(NAMESPACE,"AttributeService"));
            }
            if(element.getLocalName().equals("AffiliationDescriptor")){
                retval = new ArrayList<QName>();
                retval.add(new QName(NAMESPACE,"Extensions"));
                retval.add(new QName(NAMESPACE,"AffiliateMember"));
            }
            return retval;
        }
    }

    private void checkAtLeastOneInList(List<?> list, String objectType, String fieldName) throws MessageContentException{
        if(list == null || list.size() == 0){
            throw new MessageContentException("Error constructing meta data " + objectType + ", at least on " + fieldName + " must be specified");
        }
    }


}
