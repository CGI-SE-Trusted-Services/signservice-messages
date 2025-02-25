package org.signatureservice.messages.sweeid2.dssextenstions1_1;

import org.signatureservice.messages.ContextMessageSecurityProvider;
import org.signatureservice.messages.MessageContentException;
import org.signatureservice.messages.MessageProcessingException;
import org.signatureservice.messages.NoDecryptionKeyFoundException;
import org.signatureservice.messages.csmessages.DefaultCSMessageParser;
import org.signatureservice.messages.dss1.core.DSS1CoreMessageParser;
import org.signatureservice.messages.dss1.core.jaxb.*;
import org.signatureservice.messages.saml2.BaseSAMLMessageParser;
import org.signatureservice.messages.saml2.assertion.jaxb.*;
import org.signatureservice.messages.sweeid2.dssextenstions1_1.jaxb.*;
import org.signatureservice.messages.sweeid2.dssextenstions1_1.jaxb.AnyType;
import org.signatureservice.messages.sweeid2.dssextenstions1_1.jaxb.ObjectFactory;
import org.signatureservice.messages.utils.MessageGenerateUtils;
import org.signatureservice.messages.utils.XMLEncrypter;
import org.signatureservice.messages.xenc.jaxb.EncryptedDataType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.namespace.QName;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * MessageParser for generating generate DSS 1.0 messages with
 * Swedish Eid 2.0 DSS Extensions definet by http://www.elegnamnden.se.
 * <p>
 *     This message parser extends the DSS1 Core Message Parser
 * </p>
 * Created by philip on 02/01/17.
 */
public class SweEID2DSSExtensionsMessageParser extends DSS1CoreMessageParser{

    public static final String NAMESPACE = "http://id.elegnamnden.se/csig/1.1/dss-ext/ns";

    private static final String BASE_JAXB_CONTEXT = "org.signatureservice.messages.sweeid2.dssextenstions1_1.jaxb:org.signatureservice.messages.saml2.assertion.jaxb:org.signatureservice.messages.xenc.jaxb";

    private static final String SWEEID_DSS_EXTENSTIONS_XSD_SCHEMA_1_1_RESOURCE_LOCATION = "/eid-dss-extensions-1.1.2.xsd";


    protected ObjectFactory eid2Of = new ObjectFactory();

    protected SignMessageXMLConverter signMessageXMLConverter =new SignMessageXMLConverter();


    private static Map<String,String> NAMESPACETOPREFIXMAP = new HashMap<String, String>();
    private static Map<String,String> PREFIXTONAMESPACEMAP = new HashMap<String, String>();

    static{
        NAMESPACETOPREFIXMAP.put(NAMESPACE,"csig");
        NAMESPACETOPREFIXMAP.put(DSS1CoreMessageParser.NAMESPACE,"dss");
        NAMESPACETOPREFIXMAP.put(BaseSAMLMessageParser.ASSERTION_NAMESPACE,"saml");
        NAMESPACETOPREFIXMAP.put(DefaultCSMessageParser.XMLDSIG_NAMESPACE,"ds");
        NAMESPACETOPREFIXMAP.put(DefaultCSMessageParser.XMLENC_NAMESPACE,"xenc");

        for(String k : NAMESPACETOPREFIXMAP.keySet()){
            PREFIXTONAMESPACEMAP.put(NAMESPACETOPREFIXMAP.get(k),k);
        }
    }

    @Override
    public String getNameSpace() {
        return NAMESPACE;
    }

    @Override
    public String getJAXBPackages() { return  BASE_JAXB_CONTEXT + ":"+ super.getJAXBPackages();
    }

    @Override
    public String[] getDefaultSchemaLocations() throws SAXException {
        return new String[] {DefaultCSMessageParser.XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION,
                DSS1CoreMessageParser.DSS_XSD_SCHEMA_1_0_RESOURCE_LOCATION,
                SWEEID_DSS_EXTENSTIONS_XSD_SCHEMA_1_1_RESOURCE_LOCATION,
                BaseSAMLMessageParser.ASSERTION_XSD_SCHEMA_2_0_RESOURCE_LOCATION,
                DefaultCSMessageParser.XMLENC_XSD_SCHEMA_RESOURCE_LOCATION,
                DSS1CoreMessageParser.ASSERTION_XSD_SCHEMA_1_1_RESOURCE_LOCATION};
    }

    @Override
    protected String lookupSchemaForElement(String type, String namespaceURI, String publicId, String systemId, String baseURI) {
        if(namespaceURI != null){
            if(namespaceURI.equals(NAMESPACE)){
                return SWEEID_DSS_EXTENSTIONS_XSD_SCHEMA_1_1_RESOURCE_LOCATION;
            }
            if(namespaceURI.equals(ASSERTION_NAMESPACE)){
                return BaseSAMLMessageParser.ASSERTION_XSD_SCHEMA_2_0_RESOURCE_LOCATION;
            }
            if(namespaceURI.equals(DefaultCSMessageParser.XMLENC_NAMESPACE)){
                return DefaultCSMessageParser.XMLENC_XSD_SCHEMA_RESOURCE_LOCATION;
            }
        }
        return super.lookupSchemaForElement(type,namespaceURI,publicId,systemId,baseURI);
    }

    /**
     * Special metod for generating a DSS 1.0 SignRequest with correct saml: prefix namespacing. This due to
     * DSS 1.0 specification uses SAML 1 and Swedish EID Extensions use SAML 2.
     *
     * @param context message security related context. Use null if no signature should be used.
     * @param requestID This attribute is used to correlate requests with responses.
     *                  When present in a request, the server MUST return it in the response.
     *                  (Optional, use null to not set).
     * @param profile This attribute indicates a particular DSS profile.  It may be used to select a profile
     *                if a server supports multiple profiles, or as a sanity-check to m
     * @param signRequestExtension the SignRequestExtension that will be added to OptionalInputs element.
     * @param signTasks the SignTasks Elemenet that will be added to the InputDocuments element.
     * @param sign if the message should be signed.
     * @return a marshalled sign request.
     * @throws MessageProcessingException if internal error occurred generating the message.
     * @throws MessageContentException if bad message format was detected.
     */
    public byte[] genSignRequest(ContextMessageSecurityProvider.Context context,String requestID, String profile, JAXBElement<SignRequestExtensionType> signRequestExtension, JAXBElement<SignTasksType> signTasks, boolean sign) throws MessageProcessingException, MessageContentException {

        Document optionalInputContent = marshallToSweEID2ExtensionDoc(signRequestExtension);
        Document inputDocumentContent = marshallToSweEID2ExtensionDoc(signTasks);
        org.signatureservice.messages.dss1.core.jaxb.AnyType at = dssOf.createAnyType();
        InputDocuments inputDocuments = dssOf.createInputDocuments();
        inputDocuments.getDocumentOrTransformedDataOrDocumentHash().add(at);
        SignRequest signRequest = genSignRequest(requestID,profile,new ArrayList<Object>(),inputDocuments);
        Document doc = marshallToDSSDoc(signRequest);
        Element OptionalInputsElement = (Element) doc.getElementsByTagNameNS(DSS1CoreMessageParser.NAMESPACE,"OptionalInputs").item(0);
        OptionalInputsElement.appendChild(doc.importNode(optionalInputContent.getDocumentElement(),true));
        Element OtherElement = (Element) doc.getElementsByTagNameNS(DSS1CoreMessageParser.NAMESPACE,"Other").item(0);
        OtherElement.appendChild(doc.importNode(inputDocumentContent.getDocumentElement(),true));
        if(sign){
            return xmlSigner.marshallAndSign(context,doc,getSignatureLocationFinder());
        }
        return xmlSigner.marshallDoc(doc);
    }

    /**
     * Special metod for generating a DSS 1.0 SignRequest with correct saml: prefix namespacing. This due to
     * DSS 1.0 specification uses SAML 1 and Swedish EID Extensions use SAML 2.
     *
     * @param context message security related context. Use null if no signature should be used.
     * @param requestID This attribute is used to correlate requests with responses.
     *                  When present in a request, the server MUST return it in the response.
     *                  (Optional, use null to not set).
     * @param profile This attribute indicates a particular DSS profile.  It may be used to select a profile
     *                if a server supports multiple profiles, or as a sanity-check to.
     * @param result the result to insert in the response
     * @param signResponseExtension the SignResponseExtension that will be added to OptionalInputs element.
     * @param signTasks the SignTasks Elemenet that will be added to the InputDocuments element.
     * @param sign if the message should be signed.
     * @return a marshalled sign request.
     * @throws MessageProcessingException if internal error occurred generating the message.
     * @throws MessageContentException if bad message format was detected.
     */
    public byte[] genSignResponse(ContextMessageSecurityProvider.Context context, String requestID, String profile, Result result, JAXBElement<SignResponseExtensionType> signResponseExtension, JAXBElement<SignTasksType> signTasks, boolean sign)
            throws MessageProcessingException, MessageContentException {
        Document optionalInputContent = marshallToSweEID2ExtensionDoc(signResponseExtension);
        Document signatureObjectContent = marshallToSweEID2ExtensionDoc(signTasks);

        SignatureObject signatureObject = dssOf.createSignatureObject();
        signatureObject.setOther(dssOf.createAnyType());
        SignResponse signResponse = genSignResponse(requestID,profile,result, new ArrayList<Object>(),signatureObject);
        Document doc = marshallToDSSDoc(signResponse);
        Element OptionalOutputsElement = (Element) doc.getElementsByTagNameNS(DSS1CoreMessageParser.NAMESPACE,"OptionalOutputs").item(0);
        OptionalOutputsElement.appendChild(doc.importNode(optionalInputContent.getDocumentElement(),true));
        Element OtherElement = (Element) doc.getElementsByTagNameNS(DSS1CoreMessageParser.NAMESPACE,"Other").item(0);
        OtherElement.appendChild(doc.importNode(signatureObjectContent.getDocumentElement(),true));
        if(sign){
            return xmlSigner.marshallAndSign(context,doc,getSignatureLocationFinder());
        }
        return xmlSigner.marshallDoc(doc);
    }


    /**
     * The SignRequestExtension element allows a requesting service to add essential sign request
     * information to a DSS Sign request. When present, this element MUST be included in the dss:OptionalInputs
     * element in a DSS Sign Request.
     *
     * @param version The version of this specification. If absent, the version value defaults to "1.1". This
     *                attribute provides means for the receiving service to determine the expected syntax of the request
     *                based on the protocol version. (Optional, use null not to set. Default: 1.1)
     * @param requestTime The time when this request was created. (Required)
     * @param conditionsType    Conditions that MUST be evaluated when assessing the validity of and/or when using the
     *                          Sign Request. See Section 2.5 of [SAML2.0]for additional information on how to evaluate
     *                          conditions. This element MUST include the attributes NotBefore and
     *                          NotOnOrAfter and MUST includethe element saml:AudienceRestriction which in turn MUST contain one
     *                          saml:Audience element, specifying the return URL for any resulting Sign Response message.
     *                          (Required)
     * @param signer The identity of the signer expressed as a sequence of SAML attributes using the
     *               saml:AttributeStatementType complex type. If this element is present, then the Signing
     *               Service MUST verify that the authenticated identity of the signer is consistent with the
     *               attributes in this element. (Optional, use null not to set.)
     * @param identityProvider The SAML EntityID of the Identity Provider that MUST be used to authenticate the signer
     *                         before signing.  (Required)
     * @param signRequester The SAML EntityID of the service that sends this request to the Signing Service.  (Required)
     * @param signService The SAML EntityID of the service to which this Sign Request is sent. (Required)
     * @param requestedSignatureAlgorithm An identifier of the signature algorithm the requesting service prefers when generating the
     *                                    requested signature. (Optional, use null not to set.)
     * @param signMessage Optional sign message with information to the signer about the requested signature.
     *                    (Optional, use null not to set.)
     * @param certRequestProperties An optional set of requested properties of the signature certificate that is generated as part
     *                              of the signature process. (Optional, use null not to set.)
     * @param otherRequestInfo Any additional inputs to the request extension. (Optional, use null not to set.)
     * @return a newly created SignRequestExtension
     * @throws MessageProcessingException if internal problems occurred generating message.
     */
    public JAXBElement<SignRequestExtensionType> genSignRequestExtension(String version, Date requestTime, ConditionsType conditionsType,
                                                                         AttributeStatementType signer, String identityProvider,
                                                                         String signRequester, String signService,
                                                                         String requestedSignatureAlgorithm, SignMessageType signMessage,
                                                                         CertRequestPropertiesType certRequestProperties,
                                                                         List<Object> otherRequestInfo) throws MessageProcessingException {
        return genSignRequestExtension(version,requestTime,conditionsType,signer,genNameIdWithEntityFormat(identityProvider),
                genNameIdWithEntityFormat(signRequester), genNameIdWithEntityFormat(signService), requestedSignatureAlgorithm,
                signMessage,certRequestProperties,otherRequestInfo);
    }

    /**
     * The SignRequestExtension element allows a requesting service to add essential sign request
     * information to a DSS Sign request. When present, this element MUST be included in the dss:OptionalInputs
     * element in a DSS Sign Request.
     *
     * @param version The version of this specification. If absent, the version value defaults to "1.1". This
     *                attribute provides means for the receiving service to determine the expected syntax of the request
     *                based on the protocol version. (Optional, use null not to set. Default: 1.1)
     * @param requestTime The time when this request was created. (Required)
     * @param conditionsType    Conditions that MUST be evaluated when assessing the validity of and/or when using the
     *                          Sign Request. See Section 2.5 of [SAML2.0]for additional information on how to evaluate
     *                          conditions. This element MUST include the attributes NotBefore and
     *                          NotOnOrAfter and MUST includethe element saml:AudienceRestriction which in turn MUST contain one
     *                          saml:Audience element, specifying the return URL for any resulting Sign Response message.
     *                          (Required)
     * @param signer The identity of the signer expressed as a sequence of SAML attributes using the
     *               saml:AttributeStatementType complex type. If this element is present, then the Signing
     *               Service MUST verify that the authenticated identity of the signer is consistent with the
     *               attributes in this element. (Optional, use null not to set.)
     * @param identityProvider The SAML EntityID of the Identity Provider that MUST be used to authenticate the signer
     *                         before signing.  (Required)
     * @param authnProfile An opaque string that can be used to inform the Signing Service about
     *                     specific requirements regarding the user authentication at the given
     *                     Identity Provider. (Optional)
     * @param signRequester The SAML EntityID of the service that sends this request to the Signing Service.  (Required)
     * @param signService The SAML EntityID of the service to which this Sign Request is sent. (Required)
     * @param requestedSignatureAlgorithm An identifier of the signature algorithm the requesting service prefers when generating the
     *                                    requested signature. (Optional, use null not to set.)
     * @param signMessage Optional sign message with information to the signer about the requested signature.
     *                    (Optional, use null not to set.)
     * @param certRequestProperties An optional set of requested properties of the signature certificate that is generated as part
     *                              of the signature process. (Optional, use null not to set.)
     * @param otherRequestInfo Any additional inputs to the request extension. (Optional, use null not to set.)
     * @return a newly created SignRequestExtension
     * @throws MessageProcessingException if internal problems occurred generating message.
     */
    public JAXBElement<SignRequestExtensionType> genSignRequestExtension(String version, Date requestTime, ConditionsType conditionsType,
                                                                         AttributeStatementType signer, String identityProvider, String authnProfile,
                                                                         String signRequester, String signService,
                                                                         String requestedSignatureAlgorithm, SignMessageType signMessage,
                                                                         CertRequestPropertiesType certRequestProperties,
                                                                         List<Object> otherRequestInfo) throws MessageProcessingException {
        return genSignRequestExtension(version,requestTime,conditionsType,signer,genNameIdWithEntityFormat(identityProvider),
                authnProfile, genNameIdWithEntityFormat(signRequester), genNameIdWithEntityFormat(signService), requestedSignatureAlgorithm,
                signMessage,certRequestProperties,otherRequestInfo);
    }

    /**
     * The SignRequestExtension element allows a requesting service to add essential sign request
     * information to a DSS Sign request. When present, this element MUST be included in the dss:OptionalInputs
     * element in a DSS Sign Request.
     *
     * @param version The version of this specification. If absent, the version value defaults to "1.1". This
     *                attribute provides means for the receiving service to determine the expected syntax of the request
     *                based on the protocol version. (Optional, use null not to set. Default: 1.1)
     * @param requestTime The time when this request was created. (Required)
     * @param conditionsType    Conditions that MUST be evaluated when assessing the validity of and/or when using the
     *                          Sign Request. See Section 2.5 of [SAML2.0]for additional information on how to evaluate
     *                          conditions. This element MUST include the attributes NotBefore and
     *                          NotOnOrAfter and MUST includethe element saml:AudienceRestriction which in turn MUST contain one
     *                          saml:Audience element, specifying the return URL for any resulting Sign Response message.
     *                          (Required)
     * @param signer The identity of the signer expressed as a sequence of SAML attributes using the
     *               saml:AttributeStatementType complex type. If this element is present, then the Signing
     *               Service MUST verify that the authenticated identity of the signer is consistent with the
     *               attributes in this element. (Optional, use null not to set.)
     * @param identityProvider The SAML EntityID of the Identity Provider that MUST be used to authenticate the signer
     *                         before signing. The EntitID value is specified using the saml:NameIDType
     *                         complex type and MUST include a Format attribute with the value
     *                         urn:oasis:names:tc:SAML:2.0:nameid-format:entity. (Required)
     * @param signRequester The SAML EntityID of the service that sends this request to the Signing Service. The
     *                      EntityID value is specified using the saml:NameIDType complex type and MUST include a
     *                      Format attribute with the value urn:oasis:names:tc:SAML:2.0:nameid-format:entity. (Required)
     * @param signService The SAML EntityID of the service to which this Sign Request is sent. The EntityID value is
     *                    specified using the saml:NameIDType complex type and MUST include a Format attribute
     *                    with the value urn:oasis:names:tc:SAML:2.0:nameid-format:entity. (Required)
     * @param requestedSignatureAlgorithm An identifier of the signature algorithm the requesting service prefers when generating the
     *                                    requested signature. (Optional, use null not to set.)
     * @param signMessage Optional sign message with information to the signer about the requested signature.
     *                    (Optional, use null not to set.)
     * @param certRequestProperties An optional set of requested properties of the signature certificate that is generated as part
     *                              of the signature process. (Optional, use null not to set.)
     * @param otherRequestInfo Any additional inputs to the request extension. (Optional, use null not to set.)
     * @return a newly created SignRequestExtension
     * @throws MessageProcessingException if internal problems occurred generating message.
     */
    public JAXBElement<SignRequestExtensionType> genSignRequestExtension(String version, Date requestTime, ConditionsType conditionsType,
                                                            AttributeStatementType signer, NameIDType identityProvider,
                                                            NameIDType signRequester, NameIDType signService,
                                                            String requestedSignatureAlgorithm, SignMessageType signMessage,
                                                            CertRequestPropertiesType certRequestProperties,
                                                            List<Object> otherRequestInfo) throws MessageProcessingException {

        return genSignRequestExtension(version,requestTime,conditionsType,signer,identityProvider,null,signRequester,
                signService,requestedSignatureAlgorithm,signMessage,certRequestProperties,otherRequestInfo);
    }

    /**
     * The SignRequestExtension element allows a requesting service to add essential sign request
     * information to a DSS Sign request. When present, this element MUST be included in the dss:OptionalInputs
     * element in a DSS Sign Request.
     *
     * @param version The version of this specification. If absent, the version value defaults to "1.1". This
     *                attribute provides means for the receiving service to determine the expected syntax of the request
     *                based on the protocol version. (Optional, use null not to set. Default: 1.1)
     * @param requestTime The time when this request was created. (Required)
     * @param conditionsType    Conditions that MUST be evaluated when assessing the validity of and/or when using the
     *                          Sign Request. See Section 2.5 of [SAML2.0]for additional information on how to evaluate
     *                          conditions. This element MUST include the attributes NotBefore and
     *                          NotOnOrAfter and MUST includethe element saml:AudienceRestriction which in turn MUST contain one
     *                          saml:Audience element, specifying the return URL for any resulting Sign Response message.
     *                          (Required)
     * @param signer The identity of the signer expressed as a sequence of SAML attributes using the
     *               saml:AttributeStatementType complex type. If this element is present, then the Signing
     *               Service MUST verify that the authenticated identity of the signer is consistent with the
     *               attributes in this element. (Optional, use null not to set.)
     * @param identityProvider The SAML EntityID of the Identity Provider that MUST be used to authenticate the signer
     *                         before signing. The EntitID value is specified using the saml:NameIDType
     *                         complex type and MUST include a Format attribute with the value
     *                         urn:oasis:names:tc:SAML:2.0:nameid-format:entity. (Required)
     * @param authnProfile An opaque string that can be used to inform the Signing Service about
     *                     specific requirements regarding the user authentication at the given
     *                     Identity Provider. (Optional)
     * @param signRequester The SAML EntityID of the service that sends this request to the Signing Service. The
     *                      EntityID value is specified using the saml:NameIDType complex type and MUST include a
     *                      Format attribute with the value urn:oasis:names:tc:SAML:2.0:nameid-format:entity. (Required)
     * @param signService The SAML EntityID of the service to which this Sign Request is sent. The EntityID value is
     *                    specified using the saml:NameIDType complex type and MUST include a Format attribute
     *                    with the value urn:oasis:names:tc:SAML:2.0:nameid-format:entity. (Required)
     * @param requestedSignatureAlgorithm An identifier of the signature algorithm the requesting service prefers when generating the
     *                                    requested signature. (Optional, use null not to set.)
     * @param signMessage Optional sign message with information to the signer about the requested signature.
     *                    (Optional, use null not to set.)
     * @param certRequestProperties An optional set of requested properties of the signature certificate that is generated as part
     *                              of the signature process. (Optional, use null not to set.)
     * @param otherRequestInfo Any additional inputs to the request extension. (Optional, use null not to set.)
     * @return a newly created SignRequestExtension
     * @throws MessageProcessingException if internal problems occurred generating message.
     */
    public JAXBElement<SignRequestExtensionType> genSignRequestExtension(String version, Date requestTime, ConditionsType conditionsType,
                                                                         AttributeStatementType signer, NameIDType identityProvider,
                                                                         String authnProfile,
                                                                         NameIDType signRequester, NameIDType signService,
                                                                         String requestedSignatureAlgorithm, SignMessageType signMessage,
                                                                         CertRequestPropertiesType certRequestProperties,
                                                                         List<Object> otherRequestInfo) throws MessageProcessingException {

        SignRequestExtensionType t = eid2Of.createSignRequestExtensionType();
        t.setVersion(version);
        t.setRequestTime(MessageGenerateUtils.dateToXMLGregorianCalendarNoTimeZone(requestTime));
        t.setConditions(conditionsType);
        t.setSigner(signer);
        t.setIdentityProvider(identityProvider);
        t.setAuthnProfile(authnProfile);
        t.setSignRequester(signRequester);
        t.setSignService(signService);
        t.setRequestedSignatureAlgorithm(requestedSignatureAlgorithm);
        t.setSignMessage(signMessage);
        t.setCertRequestProperties(certRequestProperties);
        if(otherRequestInfo != null){
            AnyType at = eid2Of.createAnyType();
            at.getAny().addAll(otherRequestInfo);
            t.setOtherRequestInfo(at);
        }
        return eid2Of.createSignRequestExtension(t);
    }

    /**
     * Method to generate  basic conditions type to be used in SignRequestExtension
     * @param notBefore not used before this date. (Required)
     * @param notOnOrAfter not used on or after this date. (Required)
     * @param audience the return URL for any resulting Sign Response message. (Required)
     * @return a newly created ConditionsType
     * @throws MessageProcessingException  if internal problems occurred generating message.
     */
    public ConditionsType genBasicConditions(Date notBefore, Date notOnOrAfter, String audience) throws MessageProcessingException {
        ConditionsType conditionsType = of.createConditionsType();
        conditionsType.setNotBefore(MessageGenerateUtils.dateToXMLGregorianCalendarNoTimeZone(notBefore));
        conditionsType.setNotOnOrAfter(MessageGenerateUtils.dateToXMLGregorianCalendarNoTimeZone(notOnOrAfter));
        AudienceRestrictionType art = of.createAudienceRestrictionType();
        art.getAudience().add(audience);
        conditionsType.getConditionOrAudienceRestrictionOrOneTimeUse().add(art);
        return conditionsType;
    }


    /**
     * The CertRequestPropertiesType complex type is used to specify requested properties of the
     * signature certificate that is associated with the generated signature.
     *
     * @param certType An enumeration of certificate types, default "PKC". The supported values are "PKC", "QC"
     *                 and "QC/SSCD". "QC" means that the certificate is requested to be a Qualified Certificate
     *                 according to legal definitions in national law governing the issuer. "QC/SSCD" means a
     *                 Qualified Certificate where the private key is declared to be residing within a Secure
     *                 Signature Creation Device according to national law. "PKC" (Public Key Certificate) means a
     *                 certificate that is not a Qualified Certificate. (Optional, use null not to set, Default "PKC")

     * @param authnContextClassRef A URI identifying the requested level of assurance that authentication of the signature
     *                             certificate subject MUST comply with in order to complete signing and certificate issuance. A
     *                             Signing Service MUST NOT issue signature certificates and generate the requested
     *                             signature unless the authentication process used to authenticate the requested signer meets
     *                             the requested level of assurance expressed in this element. If this element is absent, the
     *                             locally configured policy of the Signing Service is assumed. (Optional, use null not to set)
     * @param requestedCertAttributes Element holding a SAML Entity ID of an Attribute Authority that MAY be used to obtain an
     *                                attribute value for the requested attribute. The EntityID value is specified using the
     *                                saml:NameIDType complex type and MUST include a Format attribute with the value
     *                                urn:oasis:names:tc:SAML:2.0:nameid-format:entity. (Optional, use null not to set)
     * @param otherProperties Other requested properties of the signature certificates. (Optional, use null not to set)
     * @return a newly created CertRequestPropertiesType
     */
    public CertRequestPropertiesType genCertRequestProperties(CertType certType, String authnContextClassRef,
                                                              List<MappedAttributeType> requestedCertAttributes,
                                                              List<Object> otherProperties){
        ArrayList<String> authContextClassRefs = null;
        if(authnContextClassRef != null) {
            authContextClassRefs = new ArrayList<>();
            authContextClassRefs.add(authnContextClassRef);
        }
        return genCertRequestProperties(certType,authContextClassRefs,requestedCertAttributes,otherProperties);
    }

    /**
     * The CertRequestPropertiesType complex type is used to specify requested properties of the
     * signature certificate that is associated with the generated signature.
     *
     * @param certType An enumeration of certificate types, default "PKC". The supported values are "PKC", "QC"
     *                 and "QC/SSCD". "QC" means that the certificate is requested to be a Qualified Certificate
     *                 according to legal definitions in national law governing the issuer. "QC/SSCD" means a
     *                 Qualified Certificate where the private key is declared to be residing within a Secure
     *                 Signature Creation Device according to national law. "PKC" (Public Key Certificate) means a
     *                 certificate that is not a Qualified Certificate. (Optional, use null not to set, Default "PKC")

     * @param authnContextClassRefs A list of URI identifying the requested level of assurance that authentication of the signature
     *                             certificate subject MUST comply with in order to complete signing and certificate issuance. A
     *                             Signing Service MUST NOT issue signature certificates and generate the requested
     *                             signature unless the authentication process used to authenticate the requested signer meets
     *                             the requested level of assurance expressed in this element. If this element is absent, the
     *                             locally configured policy of the Signing Service is assumed. (Optional, use null not to set)
     * @param requestedCertAttributes Element holding a SAML Entity ID of an Attribute Authority that MAY be used to obtain an
     *                                attribute value for the requested attribute. The EntityID value is specified using the
     *                                saml:NameIDType complex type and MUST include a Format attribute with the value
     *                                urn:oasis:names:tc:SAML:2.0:nameid-format:entity. (Optional, use null not to set)
     * @param otherProperties Other requested properties of the signature certificates. (Optional, use null not to set)
     * @return a newly created CertRequestPropertiesType
     */
    public CertRequestPropertiesType genCertRequestProperties(CertType certType, List<String> authnContextClassRefs,
                                                              List<MappedAttributeType> requestedCertAttributes,
                                                              List<Object> otherProperties){
        CertRequestPropertiesType t = eid2Of.createCertRequestPropertiesType();
        if(certType != null) {
            t.setCertType(certType.getValue());
        }
        if(authnContextClassRefs != null) {
            t.getAuthnContextClassRef().addAll(authnContextClassRefs);
        }
        if(requestedCertAttributes != null){
            RequestedAttributesType rat = eid2Of.createRequestedAttributesType();
            rat.getRequestedCertAttribute().addAll(requestedCertAttributes);
            t.setRequestedCertAttributes(rat);
        }
        if(otherProperties != null){
            AnyType at = eid2Of.createAnyType();
            at.getAny().addAll(otherProperties);
            t.setOtherProperties(at);
        }

        return t;
    }

    /**
     * Generates a new populated MappedAttributeType
     * @param certAttributeRef A reference to the certificate attribute or name type where the requester wants to store this
     *                         attribute value. The information in this attribute depends on the selected CertNameType
     *                         attribute value. If the CertNameType is "rdn" or "sda", then this attribute MUST contain a
     *                         string representation of an object identifier (OID). If the CertNameType is "san"
     *                         (Subject Alternative Name) and the target name is a GeneralName, then this attribute MUST hold a
     *                         string representation of the tag value of the target GeneralName type, e.g. "1" for rfc822Name
     *                         (E-mail) or "2" for dNSName. If the CertNameType is "san" and the target name
     *                         form is an OtherName, then this attribute value MUST include a string representation of the
     *                         object identifier of the target OtherName form. Representation of an OID as a string in this attribute
     *                         MUST consist of a sequence of integers delimited by a dot. This string MUST not contain white space or
     *                         line breaks. Example: "2.5.4.32". (Optional, use null to not set)
     * @param certNameType An enumeration of the target name form for
     *                     storing the associated SAML attribute value in
     *                     the certificate. The available values are "rdn" for storing the attribute value as an attribute in
     *                     a Relative Distinguished Name in the subject field of the certificate, "san" for storing the
     *                     attribute value in a subject alternative name extension and "sda" for storing the attribute
     *                     value in a subject directory attribute extension. The default value for this attribute is "rdn".
     *                     (Optional, use null to not set)
     * @param friendlyName An optional friendly name of the subject attribute, e.g. "givenName". Note that this name
     *                     does not need to map to any particular naming convention and its value MUST NOT be used
     *                     by the Signing Service for attribute type mapping. This name is present for display purposes
     *                     only. (Optional, use null to not set)
     * @param defaultValue An optional default value for the requested attribute. This value MAY be used by the Signing
     *                     Service if no authoritative value for the attribute can be obtained when the Signing Service
     *                     authenticates the user. This value MUST NOT be used by the Signing Service unless th
     *                     is value is consistent with a defined policy at the Signing Service. A typical valid use of this
     *                     attribute is to hold a default countryName attribute value that matches a set of allowed
     *                     countryName values. By accepting the default attribute value provided
     *                     in this attribute, the Signing Service accept the requesting service as an authoritative source for this particular
     *                     requested attribute. (Optional, use null to not set)
     * @param required If this attribute is set to true, the Signing Service MUST ensure that the signing
     *                 certificate contains a subject attribute of the requested type, or else the Signing Service MUST NOT
     *                 generate the requested signature. (Optional, use null to not set, default: false)
     * @param attributeAuthorities  Element holding an Entity ID of an Attribute Authority that MAY be used to obtain an
     *                              attribute value for the requested attribute. The EntityID value is specified using the
     *                              saml:NameIDType complex type and MUST include a Format attribute with the value
     *                              urn:oasis:names:tc:SAML:2.0:nameid-format:entity. (Optional, use null to not set)
     * @param samlAttributeNames Element of type PreferredSAMLAttributeNameType complex type holding a name of a
     *                           SAML subject attribute that is allowed to provide the content value for the requested
     *                           certificate attribute. (Optional, use null to not set)
     * @return  a new populated MappedAttributeType
     */
    public MappedAttributeType genMappedAttribute(String certAttributeRef, CertNameType certNameType, String friendlyName,
                                                  String defaultValue, Boolean required, List<NameIDType> attributeAuthorities,
                                                  List<PreferredSAMLAttributeNameType> samlAttributeNames){
        MappedAttributeType t = eid2Of.createMappedAttributeType();
        t.setCertAttributeRef(certAttributeRef);
        if(certNameType != null) {
            t.setCertNameType(certNameType.name());
        }
        t.setFriendlyName(friendlyName);
        t.setDefaultValue(defaultValue);
        t.setRequired(required);
        if(attributeAuthorities != null){
            t.getAttributeAuthority().addAll(attributeAuthorities);
        }
        if(samlAttributeNames != null){
            t.getSamlAttributeName().addAll(samlAttributeNames);
        }
        return t;
    }

    /**
     * The PreferredSAMLAttributeNameType complex type holds a string value of a SAML attribute
     * name. This attribute name SHALL be mapped against attribute names in
     * saml:Attribute elements representing the subject in a SAML assertion that is used to authenticate the signer.
     *
     * @param order An integer specifying the order of preference of this SAML attribute. If more than one SAML
     *              attribute is listed, the SAML attribute with the lowest order integer value that is present as a
     *              subject attribute in the SAML assertion, SHALL be used. SAML attributes with an absent
     *              order attribute SHALL be treated as having an order value of 0. Multiple SAML attributes
     *              with an identical order attribute values SHALL be treated as having equal priority.
     *              (Optional, use null to not set.)
     * @param value the value of the attribute name
     * @return a populated PreferredSAMLAttributeNameType
     */
    public PreferredSAMLAttributeNameType genPreferredSAMLAttributeName(Integer order, String value){
        PreferredSAMLAttributeNameType t = eid2Of.createPreferredSAMLAttributeNameType();
        t.setOrder(order);
        t.setValue(value);
        return t;
    }

    /**
     * Method to generate a SignMessageType with unencrypted message.
     *
     * @param mustShow When this attribute is set to true then the requested signature MUST NOT be created
     *                 unless this message has been displayed and accepted by the signer. The default is false.
     *                 (Optional, use null if not set.)
     * @param displayEntity The EntityID of the entity responsible for displaying the sign message to the signer. When
     *                      the sign message is encrypted, then this entity is also the holder of the private decryption
     *                      key necessary to decrypt the sign message. (Optional, use null if not set.)
     * @param mimeType The mime type defining the message format. This is an enumeration of the valid attribute
     *                 values text (plain text), text/html (html) or text/markdown (markdown). This specification
     *                 does not specify any particular restrictions on the provided message but it is
     *                 RECOMMENDED that sign message content is restricted to a limited set of valid tags
     *                 and attributes, and that the display entity performs filtering to enforce these restrictions before
     *                 displaying the message. The means through which parties agree on such restrictions are
     *                 outside the scope of this specification, but one valid option to communicate
     *                 such restrictions could be through federation metadata. (Optional, use null if not set.)
     * @param message The base64 encoded sign message in unencrypted form. The message MUST be encoded using UTF-8.
     *                (Required).
     * @param otherAttributes Arbitrary namespace-qualified attributes (Optional, use null to not set).
     * @return a populated SignMessage
     */
    public SignMessageType genSignMessage(Boolean mustShow, String displayEntity, SignMessageMimeType mimeType,
                                 byte[] message, Map<QName, String> otherAttributes){
        SignMessageType t = eid2Of.createSignMessageType();
        populateSignMessage(t,mustShow,displayEntity,mimeType,otherAttributes);
        t.setMessage(message);
        return t;
    }

    /**
     * Method to generate a SignMessageType with encrypted message.
     *
     * @param mustShow When this attribute is set to true then the requested signature MUST NOT be created
     *                 unless this message has been displayed and accepted by the signer. The default is false.
     *                 (Optional, use null if not set.)
     * @param displayEntity The EntityID of the entity responsible for displaying the sign message to the signer. When
     *                      the sign message is encrypted, then this entity is also the holder of the private decryption
     *                      key necessary to decrypt the sign message. (Optional, use null if not set.)
     * @param mimeType The mime type defining the message format. This is an enumeration of the valid attribute
     *                 values text (plain text), text/html (html) or text/markdown (markdown). This specification
     *                 does not specify any particular restrictions on the provided message but it is
     *                 RECOMMENDED that sign message content is restricted to a limited set of valid tags
     *                 and attributes, and that the display entity performs filtering to enforce these restrictions before
     *                 displaying the message. The means through which parties agree on such restrictions are
     *                 outside the scope of this specification, but one valid option to communicate
     *                 such restrictions could be through federation metadata. (Optional, use null if not set.)
     * @param messageToEncrypt An message element to encrypt. The message MUST be encoded using UTF-8.
     *                (Required).
     * @param otherAttributes Arbitrary namespace-qualified attributes (Optional, use null to not set).
     * @param recipients a list of reciepiets of the message.
     * @return a populated SignMessage with a encrypted SignMessage.
     */
    public SignMessageType genSignEncryptedMessage(ContextMessageSecurityProvider.Context context, Boolean mustShow, String displayEntity, SignMessageMimeType mimeType,
                                                   byte[] messageToEncrypt, Map<QName, String> otherAttributes, List<X509Certificate> recipients) throws MessageProcessingException {
        SignMessageType t = eid2Of.createSignMessageType();
        populateSignMessage(t,mustShow,displayEntity,mimeType,otherAttributes);

        JAXBElement<byte[]> message = eid2Of.createMessage(messageToEncrypt);
        Document encryptedDoc = xmlEncrypter.encryptElement(context, message,recipients,false);

        EncryptedElementType encryptedElementType = null;
        try {
            EncryptedDataType encryptedDataType = (EncryptedDataType) ((JAXBElement<?>) getUnmarshaller().unmarshal(encryptedDoc)).getValue();
            encryptedElementType =  of.createEncryptedElementType();
            encryptedElementType.setEncryptedData(encryptedDataType);
        } catch (Exception e) {
            throw new MessageProcessingException("Error parsing generated encrypted message: " + e.getMessage(),e);
        }
        t.setEncryptedMessage(encryptedElementType);
        return t;
    }


    // TODO Support SAML EncryptedElementType encryptedKey Values
    /**
     * Method to decrypt a signed message.
     *
     * @param context message security related context. Use null if no signature should be used.
     * @param signMessage  with encrypted message that should be encrypted.
     * @return a decrypted signed message.
     * @throws MessageProcessingException if internal problems occurred generating message.
     * @throws MessageContentException if bad message format was detected.
     * @throws NoDecryptionKeyFoundException if decryption key couldn't be found.
     */
    public SignMessageType decryptSignMessageData(ContextMessageSecurityProvider.Context context,SignMessageType signMessage) throws MessageProcessingException, MessageContentException, NoDecryptionKeyFoundException {
        try {
            Document doc = getDocumentBuilder().newDocument();
            getMarshaller().marshal(eid2Of.createSignMessage(signMessage), doc);

            @SuppressWarnings("unchecked")
            JAXBElement<SignMessageType> decryptedSignMessage = (JAXBElement<SignMessageType>) xmlEncrypter.decryptDocument(context,doc, signMessageXMLConverter);

            schemaValidate(decryptedSignMessage);

            return decryptedSignMessage.getValue();
        } catch (JAXBException e) {
            throw new MessageContentException("Error parsing SignMessage : " + e.getMessage(), e);
        }catch (SecurityException e) {
            throw new MessageProcessingException("Internal error parsing SignMessage: " + e.getMessage(),e);
        }
    }

    private void populateSignMessage(SignMessageType signMessageType, Boolean mustShow, String displayEntity, SignMessageMimeType mimeType,
                                    Map<QName, String> otherAttributes){
        signMessageType.setMustShow(mustShow);
        signMessageType.setDisplayEntity(displayEntity);
        if(mimeType != null) {
            signMessageType.setMimeType(mimeType.getMimeType());
        }
        if(otherAttributes != null) {
            signMessageType.getOtherAttributes().putAll(otherAttributes);
        }
    }

    /**
     * Method to generate a SignResponseExtensionType.
     *
     * @param version The version of this specification. If absent, the version value defaults to "1.0". This attribute
     *                provides means for the receiving service to determine the expected syntax of the response
     *                based on the protocol version. (Optional, use null if not set.)
     * @param responseTime The time when the sign response was created. (Required)
     * @param request A dss:SignRequest element that contains the request related to
     *                this sign response. This element MUST be present if signing was successfull.
     *                (Optional, use null if not set.)
     * @param signerAssertionInfo An element of type SignerAssertionInfoType holding information about how the signer was
     *                            authenticated by the sign service as well as information about subject attribute values
     *                            present in the SAML assertion authenticating the signer, which was incorporated into the
     *                            signer certificate. This element MUST be present if signing was successful.
     *                            (Optional, use null if not set.)
     * @param signatureCertificateChain An element of type CertificateChainType holding the signer certificate as well as other
     *                                  certificates that may be used to validate the signature. This element MUST be present if
     *                                  signing was successful and MUST contain all certificates that are necessary to compile a
     *                                  complete and functional signed document. Certificates in SignatureCertificateChain
     *                                  MUST be provided in sequence with the signature certificate first followed by any CA
     *                                  certificates that can be used to verify the previous certificate in the sequence, ending
     *                                  with a self-signed root certificate. (Optional, use null if not set.)
     * @param otherResponseInfo Optional sign response elements that will be included in the AnyTupe. (Optional, use null if not set.)
     * @return a newly generated SignResponseExtensionType
     * @throws MessageProcessingException if internal problems occurred generating message.
     */
    public JAXBElement<SignResponseExtensionType> genSignResponseExtension(String version, Date responseTime,
                                                              SignRequest request, SignerAssertionInfoType signerAssertionInfo,
                                                              List<X509Certificate> signatureCertificateChain,
                                                              List<Object> otherResponseInfo) throws MessageProcessingException {
        byte[] requestData = null;
        if(request != null){
            requestData = marshall(request);
        }

        return  genSignResponseExtension(version, responseTime, requestData, signerAssertionInfo, signatureCertificateChain, otherResponseInfo);
    }

    /**
     * Method to generate a SignResponseExtensionType.
     *
     * @param version The version of this specification. If absent, the version value defaults to "1.0". This attribute
     *                provides means for the receiving service to determine the expected syntax of the response
     *                based on the protocol version. (Optional, use null if not set.)
     * @param responseTime The time when the sign response was created. (Required)
     * @param requestData A marshalled dss:SignRequest element that contains the request related to
     *                this sign response. This element MUST be present if signing was successfull.
     *                (Optional, use null if not set.)
     * @param signerAssertionInfo An element of type SignerAssertionInfoType holding information about how the signer was
     *                            authenticated by the sign service as well as information about subject attribute values
     *                            present in the SAML assertion authenticating the signer, which was incorporated into the
     *                            signer certificate. This element MUST be present if signing was successful.
     *                            (Optional, use null if not set.)
     * @param signatureCertificateChain An element of type CertificateChainType holding the signer certificate as well as other
     *                                  certificates that may be used to validate the signature. This element MUST be present if
     *                                  signing was successful and MUST contain all certificates that are necessary to compile a
     *                                  complete and functional signed document. Certificates in SignatureCertificateChain
     *                                  MUST be provided in sequence with the signature certificate first followed by any CA
     *                                  certificates that can be used to verify the previous certificate in the sequence, ending
     *                                  with a self-signed root certificate. (Optional, use null if not set.)
     * @param otherResponseInfo Optional sign response elements that will be included in the AnyTupe. (Optional, use null if not set.)
     * @return a newly generated SignResponseExtensionType
     * @throws MessageProcessingException if internal problems occurred generating message.
     */
    public JAXBElement<SignResponseExtensionType> genSignResponseExtension(String version, Date responseTime,
                                                              byte[] requestData, SignerAssertionInfoType signerAssertionInfo,
                                                              List<X509Certificate> signatureCertificateChain,
                                                              List<Object> otherResponseInfo) throws MessageProcessingException {
        SignResponseExtensionType t = eid2Of.createSignResponseExtensionType();
        t.setVersion(version);
        t.setResponseTime(MessageGenerateUtils.dateToXMLGregorianCalendarNoTimeZone(responseTime));
        t.setSignerAssertionInfo(signerAssertionInfo);
        t.setRequest(requestData);
        if(signatureCertificateChain != null){
            CertificateChainType certificateChainType = eid2Of.createCertificateChainType();
            for(X509Certificate cert : signatureCertificateChain){
                try {
                    certificateChainType.getX509Certificate().add(cert.getEncoded());
                } catch (CertificateEncodingException e) {
                    throw new MessageProcessingException("Error decoding signature certificate certificates : " + e.getMessage());
                }
            }
            t.setSignatureCertificateChain(certificateChainType);
        }
        if(otherResponseInfo != null){
            AnyType anyType = eid2Of.createAnyType();
            anyType.getAny().addAll(otherResponseInfo);
            t.setOtherResponseInfo(anyType);
        }
        return eid2Of.createSignResponseExtension(t);
    }

    /**
     * Generates a new SignerAssertionInfoType
     *
     * @param contextInfo This element of type ContextInfoType holds information about SAML authentication context
     *                    related to signer authentication through a SAML assertion. (Required)
     * @param attributeStatement This element of type saml:AttributeStatementType (see [SAML2.0]) holds subject
     *                           attributes obtained from the SAML assertion used to authenticate the signer at the Signing
     *                           Service. For integrity reasons, this element SHOULD only provide information about SAML
     *                           attribute values that maps to subject identity information in the signer's certificate.
     *                           (Required)
     * @param assertions Any number of relevant SAML assertions that was relevant for authenticating the sig
     *                       ner and signer's identity attributes at the Signing Service. (Optional, use null not to set.)
     * @return a newly created SignerAssertionInfoType
     * @throws MessageProcessingException if internal problems occurred generating message.
     */
    public SignerAssertionInfoType genSignerAssertionInfo(ContextInfoType contextInfo,
                                                          AttributeStatementType attributeStatement,
                                                          List<JAXBElement<AssertionType>> assertions) throws MessageProcessingException {

        ArrayList<byte[]> assertionDatas = null;
        if(assertions != null) {
            assertionDatas = new ArrayList<byte[]>();
            for(JAXBElement<AssertionType> assertion : assertions) {
                assertionDatas.add(marshall(assertion));
            }
        }
        return genSignerAssertionInfoFromAssertionData(contextInfo,attributeStatement, assertionDatas);
    }

    /**
     * Generates a new SignerAssertionInfoType
     *
     * @param contextInfo This element of type ContextInfoType holds information about SAML authentication context
     *                    related to signer authentication through a SAML assertion. (Required)
     * @param attributeStatement This element of type saml:AttributeStatementType (see [SAML2.0]) holds subject
     *                           attributes obtained from the SAML assertion used to authenticate the signer at the Signing
     *                           Service. For integrity reasons, this element SHOULD only provide information about SAML
     *                           attribute values that maps to subject identity information in the signer's certificate.
     *                           (Required)
     * @param assertionDatas Any number of relevant marshalled SAML assertions that was relevant for authenticating the sig
     *                       ner and signer's identity attributes at the Signing Service. (Optional, use null not to set.)
     * @return a newly created SignerAssertionInfoType
     */
    public SignerAssertionInfoType genSignerAssertionInfoFromAssertionData(ContextInfoType contextInfo,
                                                          AttributeStatementType attributeStatement,
                                                          List<byte[]> assertionDatas) {
        SignerAssertionInfoType t = eid2Of.createSignerAssertionInfoType();
        t.setContextInfo(contextInfo);
        t.setAttributeStatement(attributeStatement);
        if(assertionDatas != null) {
            SAMLAssertionsType sat = eid2Of.createSAMLAssertionsType();
            for(byte[] assertion : assertionDatas) {
                sat.getAssertion().add(assertion);
            }
            t.setSamlAssertions(sat);
        }
        return t;
    }

    /**
     * Generates a new ContextInfoType
     *
     * @param identityProvider The EntityID of the Identity Provider that
     *                         authenticated the signer to the Signing Service. (Required)
     * @param authenticationInstant The time when the Signing Service authenticated the signer. (Required)
     * @param authnContextClassRef A URI reference to the authentication context class
     *                             (see [SAML2.0]). (Required)
     * @param serviceID An arbitrary identifier of the instance of the Signing Service that authenticated the
     *                  signer. (Optional, use null not to set)
     * @param authType An arbitrary identifier of the service used by the Signing Service to authenticate
     *                 the signer (e.g. "shibboleth".) (Optional, use null not to set)
     * @param assertionRef A reference to the assertion used to identify the signer. This MAY be the ID
     *                     attribute of a saml:Assertion element but MAY also be any other reference that
     *                     can be used to locate and identify the assertion. (Optional, use null not to set)
     * @return a newly created ContextInfoType
     * @throws MessageProcessingException if internal problems occurred generating message.
     */
    public ContextInfoType genContextInfo(NameIDType identityProvider, Date authenticationInstant,
                                          String authnContextClassRef , String serviceID, String authType,
                                          String assertionRef) throws MessageProcessingException {
        ContextInfoType t = eid2Of.createContextInfoType();
        t.setIdentityProvider(identityProvider);
        t.setAuthenticationInstant(MessageGenerateUtils.dateToXMLGregorianCalendarNoTimeZone(authenticationInstant));
        t.setAuthnContextClassRef(authnContextClassRef);
        t.setServiceID(serviceID);
        t.setAuthType(authType);
        t.setAssertionRef(assertionRef);
        return t;
    }

    /**
     * Generates a populated SignTaskData
     *
     * @param signTaskId An identifier of the signature task that is represented by this element. If the request contains
     *                   multiple instances of SignTaskData representing separate sign tasks, then each instance
     *                   of the element MUST have a SignatureId attribute value that is unique among all sign
     *                   tasks in the sign request. When this attribute is present, the same attribute
     *                   value MUST be returned in the corresponding SignTaskData element in the response that holds
     *                   corresponding signature result data. (Optional, use null not to set)
     * @param sigType Enumerated identifier of the type of signature format the canonicalized signed information
     *                octets in the ToBeSignedBytes element are associated with. This MUST be one of the enumerated
     *                values "XML", "PDF", "CMS" of "ASiC". (Required)
     * @param adESType Specifies the type of AdES signature. BES means that the signing certificate hash must be
     *                 covered by the signature. EPES means that the signing certificate hash and a signature
     *                 policy identifier must be covered by the signature. (Optional, use null not to set)
     * @param processingRules A URI identifying one or more processing rules that the Signing Service MUST apply when
     *                        processing and using the provided signed information octets. The Signing Service MUST
     *                        NOT process and complete the signature request if this attribute contains a URI that is not
     *                        recognized by the Signing Service. When this attribute is present in the sign response, it
     *                        represents a statement by the Signing Service that the identified processing rule was
     *                        successfully executed. (Optional, use null not to set)
     * @param toBeSignedBytes The bytes to be hashed and signed when generating the requested signature. For an XML
     *                        signature this MUST be the canonicalized octets of a dss:SignedInfo element. For a
     *                        PDF signature this MUST be the octets of the DER encoded SignedAttrs value (signed
     *                        attributes). If this data was altered by the signature process, for example as a result of
     *                        changing a signing time attribute in PDF SignedAttrs, or as a result f adding a reference to
     *                        a hash of the signature certificate in an XAdES signature, the altered data MUST be
     *                        returned in the sign response using this element. (Required)
     * @param adESObject An element of type AdESObjectType complex type holding data to support generation of a
     *                   signature according to any of the ETSI Advanced Electronic Signature (AdES) standard
     *                   formats. (Optional, use null not to set)
     * @param base64Signature The output signature value of the signature creation process associated with this sign task.
     *                        This element's optional Type attribute, if present, SHALL contain a URI indicating the
     *                        signature algorithm that was used to generate the signature value. (Optional, use null not to set)
     * @param base64SignatureType The type to set as attribute to the Base64Signature
     * @param otherSignTaskData  Other input or output data elements associated with the sign task. (Optional)
     * @return a populated SignTaskDataType
     *
     * @throws MessageContentException if bad message format was detected.
     */
    public SignTaskDataType genSignTaskData(String signTaskId, SigType sigType, AdESType adESType,
                                            String processingRules, byte[] toBeSignedBytes,
                                            AdESObjectType adESObject, byte[] base64Signature,
                                            String base64SignatureType,
                                            List<Object> otherSignTaskData) throws MessageContentException {
        SignTaskDataType t = eid2Of.createSignTaskDataType();
        t.setSignTaskId(signTaskId);
        t.setSigType(sigType.name());
        if(adESType != null) {
            t.setAdESType(adESType.name());
        }
        t.setProcessingRules(processingRules);
        t.setToBeSignedBytes(toBeSignedBytes);
        t.setAdESObject(adESObject);
        if(base64Signature != null){
            if(base64SignatureType == null){
                throw new MessageContentException("Error base64Signature must have a defined type");
            }
            Base64SignatureType bt = eid2Of.createBase64SignatureType();
            bt.setType(base64SignatureType);
            bt.setValue(base64Signature);
            t.setBase64Signature(bt);
        }
        if(otherSignTaskData != null){
            AnyType at = eid2Of.createAnyType();
            at.getAny().addAll(otherSignTaskData);
            t.setOtherSignTaskData(at);
        }

        return t;
    }


    /**
     * This element holds information about sign tasks that are requested in a sign request and returned in
     * a sign response. If information about a sign task is provided using this element in a sign request,
     * then the corresponding signature result data MUST also be provided using this element in the sign
     * response.
     * @param signTasks Input and output data associated with a sign task. A request MAY contain several instances
     *      of this element. When multiple instances of this element are present in the request, this
     *      means that the Signing Service is requested to generate multiple signatures (one for each
     *      SignTaskData element) using the same signing key and signature certificate. This allows
     *      batch signing of several different documents in the same signing instance or creation of
     *      multiple signatures on the same document such as signing XML content of a PDF document
     *      with an XML signature, while signing the rest of the document with a PDF signature.
     *      (One is required.)
     * @return a generated SignTasks
     */
    public JAXBElement<SignTasksType> genSignTasks(List<SignTaskDataType> signTasks){
        SignTasksType t = eid2Of.createSignTasksType();
        t.getSignTaskData().addAll(signTasks);
        return eid2Of.createSignTasks(t);
    }

    /**
     * Help method to set create a NameId with format "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
     * @param value the value to set to the NameId
     * @return createed NameID or null if value is null.
     */
    protected NameIDType genNameIdWithEntityFormat(String value){
        if(value == null){
            return null;
        }
        NameIDType t = of.createNameIDType();
        t.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
        t.setValue(value);
        return t;
    }

    /**
     * Converter that replaces all decrypted EncryptedAssertions with Assertions
     */
    public static class SignMessageXMLConverter implements XMLEncrypter.DecryptedXMLConverter {

        public Document convert(Document doc) throws MessageContentException {
            NodeList nodeList = doc.getElementsByTagNameNS(NAMESPACE, "EncryptedMessage");
            for(int i =0; i < nodeList.getLength(); i++){
                Element encMessage= (Element) nodeList.item(i);
                Node message = encMessage.getFirstChild();
                Element parent = (Element) encMessage.getParentNode();
                if(parent.getLocalName().equals("SignMessage") && parent.getNamespaceURI().equals(NAMESPACE)){
                    parent.appendChild(message);
                    parent.removeChild(encMessage);
                }

            }

            return doc;
        }

    }

    protected Document marshallToDSSDoc(Object object) throws MessageProcessingException {
        try {
            Document doc = getDocumentBuilder().newDocument();
            getDSSMarshaller().marshal(object,doc);
            return doc;
        } catch (JAXBException e) {
            throw new MessageProcessingException("Error marshalling object: " + e.getMessage(),e);
        }
    }

    protected Marshaller getDSSMarshaller() throws JAXBException{
        Marshaller dssMarshaller = getDSSJAXBContext().createMarshaller();
        dssMarshaller.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
        return dssMarshaller;
    }

    private JAXBContext dssJaxbContext = null;

    /**
     * Help method maintaining the Extension specific JAXB Context to handle multiple SAML namespaces.
     */
    protected JAXBContext getDSSJAXBContext() throws JAXBException{
        if(dssJaxbContext== null){
            dssJaxbContext = JAXBContext.newInstance(super.BASE_JAXB_CONTEXT);

        }
        return dssJaxbContext;
    }

    protected Document marshallToSweEID2ExtensionDoc(Object object) throws MessageProcessingException {
        try {
            Document doc = getDocumentBuilder().newDocument();
            getSweEID2ExtensionMarshaller().marshal(object,doc);
            return doc;
        } catch (JAXBException e) {
            throw new MessageProcessingException("Error marshalling object: " + e.getMessage(),e);
        }
    }

    protected Marshaller getSweEID2ExtensionMarshaller() throws JAXBException{
        Marshaller sweEID2Marshaller = getSweEID2ExtensionJAXBContext().createMarshaller();
        sweEID2Marshaller.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
        return sweEID2Marshaller;
    }

    private JAXBContext sweEID2JaxbContext = null;

    /**
     * Help method maintaining the Extension specific JAXB Context to handle multiple SAML namespaces.
     */
    protected JAXBContext getSweEID2ExtensionJAXBContext() throws JAXBException{
        if(sweEID2JaxbContext== null){
            sweEID2JaxbContext = JAXBContext.newInstance(BASE_JAXB_CONTEXT);

        }
        return sweEID2JaxbContext;
    }
}
