package org.certificateservices.messages.saml2.protocol;

import org.certificateservices.messages.ContextMessageSecurityProvider;
import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.assertion.ResponseStatusCodes;
import org.certificateservices.messages.csmessages.DefaultCSMessageParser;
import org.certificateservices.messages.saml2.BaseSAMLMessageParser;
import org.certificateservices.messages.saml2.assertion.jaxb.ConditionsType;
import org.certificateservices.messages.saml2.assertion.jaxb.NameIDType;
import org.certificateservices.messages.saml2.assertion.jaxb.SubjectType;
import org.certificateservices.messages.saml2.protocol.jaxb.*;
import org.certificateservices.messages.utils.MessageGenerateUtils;
import org.certificateservices.messages.utils.XMLSigner;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.List;

/**
 * MessageParser for generating generate SAML 2.0 Protocol messages. This should be used when generating messages such
 * as AuthNRequest and SAMLP Responses that is not connected to CSMessages.
 * <p>
 *     For CSMessage related assertions use AssertionPayloadParser.
 * </p>
 *
 * Created by philip on 02/01/17.
 */
public class SAMLProtocolMessageParser extends BaseSAMLMessageParser{

    private static final String BASE_JAXB_CONTEXT = "org.certificateservices.messages.saml2.assertion.jaxb:org.certificateservices.messages.saml2.protocol.jaxb:org.certificateservices.messages.xenc.jaxb:org.certificateservices.messages.xmldsig.jaxb";

    private AuthNSignatureLocationFinder authNSignatureLocationFinder = new AuthNSignatureLocationFinder();
    @Override
    public String getNameSpace() {
        return PROTOCOL_NAMESPACE;
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
                SAMLP_XSD_SCHEMA_2_0_RESOURCE_LOCATION};
    }

    @Override
    public XMLSigner.SignatureLocationFinder getSignatureLocationFinder(){
        return samlpSignatureLocationFinder;
    }

    @Override
    public XMLSigner.OrganisationLookup getOrganisationLookup(){
        return null;
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
            if(namespaceURI.equals(ASSERTION_NAMESPACE)){
                return BaseSAMLMessageParser.ASSERTION_XSD_SCHEMA_2_0_RESOURCE_LOCATION;
            }
            if(namespaceURI.equals(PROTOCOL_NAMESPACE)){
                return BaseSAMLMessageParser.SAMLP_XSD_SCHEMA_2_0_RESOURCE_LOCATION;
            }
        }
        return null;
    }


    /**
     * Method to generate a complex AuthNRequest Message.
     * <p>
     *     To request that an identity provider issue an assertion with an authentication statement, a presenter authenticates to that identity provider
     * 	   (or relies on an existing security context) and sends it an <AuthnRequest> message that describes the properties that the resulting assertion
     *     needs to have to satisfy its purpose. Among these properties may be information that relates to the content of the assertion and/or information
     *     that relates to how the resulting <Response> message should be delivered to the requester. The process of authentication of the presenter may
     *     take place before, during, or after the initial delivery of the <AuthnRequest> message.
     * </p>
     * <p>
     *     The requester might not be the same as the presenter of the request if, for example, the requester is a relying party that intends to
     *     use the resulting assertion to authenticate or authorize the requested subject so that the relying party
     *     can decide whether to provide a service.
     * </p>
     * <p>
     *     The <AuthnRequest> message SHOULD be signed or otherwise authenticated and integrity protected by the protocol binding used to deliver the message.
     * </p>
     * @param context message security related context. Use null if no signature should be used.
     * @param id the id to set in the AuthNRequest
     * @param forceAuthn A Boolean value. If "true", the identity provider MUST authenticate the presenter directly rather than rely on a previous security context.
     *                      If a value is not provided, the default is "false". However, if both ForceAuthn and IsPassive are "true", the identity provider MUST NOT
     *                      freshly authenticate the presenter unless the constraints of IsPassive can be met. (Optional, use null of it shouldn't be set)
     * @param isPassive A Boolean value. If "true", the identity provider and the user agent itself MUST NOT visibly take control of the user interface from the requester
     *                     and interact with the presenter in a noticeable fashion. If a value is not provided, the default is "false". (Optional, use null of it shouldn't be set)
     * @param protocolBinding A URI reference that identifies a SAML protocol binding to be used when returning the <Response> message. See [SAMLBind] for more information about
     *                           protocol bindings and URI references defined for them. This attribute is mutually exclusive with the AssertionConsumerServiceIndex attribute and
     *                           is typically accompanied by the AssertionConsumerServiceURL attribute. (Optional, use null of it shouldn't be set)
     * @param assertionConsumerServiceIndex Indirectly identifies the location to which the <Response> message should be returned to the requester. It applies only to profiles in
     *                                         which the requester is different from the presenter, such as the Web Browser SSO profile in [SAMLProf]. The identity provider MUST
     *                                         have a trusted means to map the index value in the attribute to a location associated with the requester. [SAMLMeta] provides one
     *                                         possible mechanism. If omitted, then the identity provider MUST return the <Response> message to the default location associated
     *                                         with the requester for the profile of use. If the index specified is invalid, then the identity provider MAY return an error <Response>
     *                                         or it MAY use the default location. This attribute is mutually exclusive with the AssertionConsumerServiceURL and ProtocolBinding
     *                                         attributes. (Optional, use null of it shouldn't be set)
     * @param assertionConsumerServiceURL Specifies by value the location to which the <Response> message MUST be returned to the requester. The responder MUST ensure by
     *                                       some means that the value specified is in fact associated with the requester. [SAMLMeta] provides one possible mechanism; signing
     *                                       the enclosing <AuthnRequest> message is another. This attribute is mutually exclusive with the AssertionConsumerServiceIndex
     *                                       attribute and is typically accompanied by the ProtocolBinding attribute. (Optional, use null of it shouldn't be set)
     * @param attributeConsumingServiceIndex Indirectly identifies information associated with the requester describing the SAML attributes the requester desires or requires to be
     *                                         supplied by the identity provider in the <Response> message. The identity provider MUST have a trusted means to map the index value
     *                                         in the attribute to information associated with the requester. [SAMLMeta] provides one possible mechanism. The identity provider MAY
     *                                         use this information to populate one or more <saml:AttributeStatement> elements in the assertion(s) it returns.
     *                                         (Optional, use null of it shouldn't be set)
     * @param providerName Specifies the human-readable name of the requester for use by the presenter's user agent or the identity provider.
     *
     * @param destination A URI reference indicating the address to which this request has been sent. This is useful to prevent malicious forwarding of
     *                    requests to unintended recipients, a protection that is required by some protocol bindings. If it is present, the actual recipient
     *                    MUST check that the URI reference identifies the location at which the message was received. If it does not, the request MUST be
     *                    discarded. Some protocol bindings may require the use of this attribute (see [SAMLBind]). (Optional, use null of it shouldn't be set)
     * @param consent Indicates whether or not (and under what conditions) consent has been obtained from a principal in
     *                the sending of this request. See Section 8.4 for some URI references that MAY be used as the value.
     *                of the Consent attribute and their associated descriptions. If no Consent value is provided, the
     *                identifier urn:oasis:names:tc:SAML:2.0:consent:unspecified (see Section 8.4.1) is in effect. (Optional, use null of it shouldn't be set)
     *
     * @param issuer Identifies the entity that generated the request message. (For more information on this element, see Section 2.2.5.) (Optional, use null of it shouldn't be set)
     * @param extensions This extension point contains optional protocol message extension elements that are agreed on
     *                      between the communicating parties. No extension schema is required in order to make use of this
     *                      extension point, and even if one is provided, the lax validation setting does not impose a requirement
     *                      for the extension to be valid. SAML extension elements MUST be namespace-qualified in a non-
     *                      SAML-defined namespace. (Optional, use null of it shouldn't be set)
     * @param subject Specifies the requested subject of the resulting assertion(s). This may include one or more <saml:SubjectConfirmation> elements to indicate how and/or by whom
     *                   the resulting assertions can be confirmed. For more information on this element, see Section 2.4. If entirely omitted or if no identifier is included, the
     *                   presenter of the message is presumed to be the requested subject. If no <saml:SubjectConfirmation> elements are included, then the presenter
     *                   is presumed to be the only attesting entity required and the method is implied by the profile of use and/or the policies of the identity provider.
     *                   (Optional, use null of it shouldn't be set)
     * @param nameIdPolicy Specifies constraints on the name identifier to be used to represent the requested subject. If omitted, then any type of identifier supported by the identity provider for the
     *                        requested subject can be used, constrained by any relevant deployment-specific policies, with respect to privacy, for example. (Optional, use null of it shouldn't be set)
     * @param conditions Specifies the SAML conditions the requester expects to limit the validity and/or use of the resulting assertion(s). The responder MAY modify or supplement
     *                      this set as it deems necessary. The information in this element is used as input to the process of constructing the assertion, rather than as conditions on
     *                      the use of the request itself. (For more information on this element, see Section 2.5.) (Optional, use null of it shouldn't be set)
     * @param requestedAuthnContext Specifies the requirements, if any, that the requester places on the authentication context that applies to the responding provider's authentication
     *                                 of the presenter. See Section 3.3.2.2.1 for processing rules regarding this element. (Optional, use null of it shouldn't be set)
     * @param scoping Specifies a set of identity providers trusted by the requester to authenticate the presenter, as well as limitations and context related to proxying of the
     *                   <AuthnRequest> message to subsequent identity providers by the responder. (Optional, use null of it shouldn't be set)
     * @param signRequest true if the request should be signed.
     * @return a utf-8 encoded AuthNRequest message.
     * @throws MessageProcessingException if internal problem occurred generating the message.
     * @throws MessageContentException if invalid message format was detected.
     */
    public byte[] genAuthNRequest(ContextMessageSecurityProvider.Context context,String id, Boolean forceAuthn, Boolean isPassive, String protocolBinding, Integer assertionConsumerServiceIndex,
                                  String assertionConsumerServiceURL, Integer attributeConsumingServiceIndex,
                                  String providerName, String destination, String consent, NameIDType issuer, ExtensionsType extensions, SubjectType subject, NameIDPolicyType nameIdPolicy, ConditionsType conditions,
                                  RequestedAuthnContextType requestedAuthnContext, ScopingType scoping, boolean signRequest) throws MessageProcessingException, MessageContentException{

        AuthnRequestType art = samlpOf.createAuthnRequestType();

        populateRequestAbstractType(art,id, destination,consent,issuer,extensions);

        art.setForceAuthn(forceAuthn);
        art.setIsPassive(isPassive);
        art.setProtocolBinding(protocolBinding);
        art.setAssertionConsumerServiceIndex(assertionConsumerServiceIndex);
        art.setAssertionConsumerServiceURL(assertionConsumerServiceURL);
        art.setAttributeConsumingServiceIndex(attributeConsumingServiceIndex);
        art.setProviderName(providerName);

        art.setSubject(subject);
        art.setNameIDPolicy(nameIdPolicy);
        art.setConditions(conditions);
        art.setRequestedAuthnContext(requestedAuthnContext);
        art.setScoping(scoping);


        Document doc = getDocumentBuilder().newDocument();
        try {
            getMarshaller().marshal(samlpOf.createAuthnRequest(art), doc);
        } catch (JAXBException e) {
            throw new MessageProcessingException("Error marshalling message " + e.getMessage(), e);
        }

        if(signRequest){
            xmlSigner.sign(context, doc, authNSignatureLocationFinder);
        }

        return xmlSigner.marshallDoc(doc);

    }

    /**
     * Method to generate a generic SAMLP  Response message.
     *
     * @param context message security related context. Use null if no signature should be used.
     * @param inResponseTo the ID of the request, null if message was unreadable
     * @param issuer Identifies the entity that generated the response message. (Optional, null for no issuer)
     * @param destination  A URI reference indicating the address to which this response has been sent. This is useful to prevent
     *                        malicious forwarding of responses to unintended recipients, a protection that is required by some
     *                        protocol bindings. If it is present, the actual recipient MUST check that the URI reference identifies the
     *                        location at which the message was received. If it does not, the response MUST be discarded. Some
     *                        protocol bindings may require the use of this attribute. (Optional, null for no destination)
     * @param consent Indicates whether or not (and under what conditions) consent has been obtained from a principal in
     *                   the sending of this response. See Section 8.4 for some URI references that MAY be used as the value
     *                   of the Consent attribute and their associated descriptions. If no Consent value is provided, the
     *                   identifier urn:oasis:names:tc:SAML:2.0:consent:unspecified (see Section 8.4.1) is in
     *                   effect.
     * @param extensions This extension point contains optional protocol message extension elements that are agreed on
     *                      between the communicating parties. . No extension schema is required in order to make use of this
     *                      extension point, and even if one is provided, the lax validation setting does not impose a requirement
     *                      for the extension to be valid. SAML extension elements MUST be namespace-qualified in a non-SAML-defined namespace. (Optional, null for no extensions)
     * @param statusCode the failure code to respond to (Required)
     * @param statusDetail a container for generic status XML.
     * @param statusMessage a descriptive  message, may be null.
     * @param assertions a list of Assertions or EncryptedAssertions (Important, the type must be a JAXBElement not only the AssertionType or EncryptedElementType, (Optional)
     * @param signAssertions sign all included assetions.
     * @param signSAMLPResponse if the response should be signed.
     * @return a SAMLP failure message.
     * @throws MessageContentException if parameters where invalid.
     * @throws MessageProcessingException if internal problems occurred generated the message.
     */
    public byte[] genResponse(ContextMessageSecurityProvider.Context context, String inResponseTo, NameIDType issuer, String destination, String consent,
                              ExtensionsType extensions, ResponseStatusCodes statusCode, String statusMessage,
                              StatusDetailType statusDetail, List<JAXBElement<?>> assertions,
                              boolean signAssertions, boolean signSAMLPResponse) throws MessageContentException, MessageProcessingException{
        try{
            ResponseType responseType = samlpOf.createResponseType();

            populateStatusResponseType(responseType,inResponseTo,destination,consent,issuer,extensions,statusCode,statusMessage,statusDetail);

            if(assertions != null) {
                for(JAXBElement a : assertions) {
                    responseType.getAssertionOrEncryptedAssertion().add(a.getValue());
                }
            }

            JAXBElement<ResponseType> response = samlpOf.createResponse(responseType);

            return marshallAndSignSAMLPOrAssertion(context, response,signAssertions,signSAMLPResponse);

        }catch(Exception e){
            if(e instanceof MessageContentException){
                throw (MessageContentException) e;
            }
            if(e instanceof MessageProcessingException){
                throw (MessageProcessingException) e;
            }
            throw new MessageProcessingException("Error generation SAMLP Failure Message: " + e.getMessage(),e);
        }
    }

    /**
     * Help method to populate all base fields of a RequestAbstractType
     *
     * @param id the request id to set in the request.
     * @param destination A URI reference indicating the address to which this request has been sent. This is useful to prevent malicious forwarding of
     *                    requests to unintended recipients, a protection that is required by some protocol bindings. If it is present, the actual recipient
     *                    MUST check that the URI reference identifies the location at which the message was received. If it does not, the request MUST be
     *                    discarded. Some protocol bindings may require the use of this attribute (see [SAMLBind]). (Optional, use null of it shouldn't be set)
     * @param consent Indicates whether or not (and under what conditions) consent has been obtained from a principal in
     *                the sending of this request. See Section 8.4 for some URI references that MAY be used as the value.
     *                of the Consent attribute and their associated descriptions. If no Consent value is provided, the
     *                identifier urn:oasis:names:tc:SAML:2.0:consent:unspecified (see Section 8.4.1) is in effect. (Optional, use null of it shouldn't be set)
     *
     * @param issuer Identifies the entity that generated the request message. (For more information on this element, see Section 2.2.5.) (Optional, use null of it shouldn't be set)
     * @param extensions This extension point contains optional protocol message extension elements that are agreed on
     *                      between the communicating parties. No extension schema is required in order to make use of this
     *                      extension point, and even if one is provided, the lax validation setting does not impose a requirement
     *                      for the extension to be valid. SAML extension elements MUST be namespace-qualified in a non-
     *                      SAML-defined namespace. (Optional, use null of it shouldn't be set)
     * @throws MessageProcessingException if internal problem occurred generating the message.
     * @throws MessageContentException if invalid message format was detected.
     */
    protected void populateRequestAbstractType(RequestAbstractType requestAbstractType, String id, String destination, String consent, NameIDType issuer, ExtensionsType extensions) throws MessageProcessingException, MessageContentException{
        requestAbstractType.setID(id);
        requestAbstractType.setIssueInstant(MessageGenerateUtils.dateToXMLGregorianCalendar(systemTime.getSystemTime()));
        requestAbstractType.setVersion(DEFAULT_SAML_VERSION);

        requestAbstractType.setDestination(destination);
        requestAbstractType.setConsent(consent);

        requestAbstractType.setIssuer(issuer);
        requestAbstractType.setExtensions(extensions);

    }

    /**
     * Help method to populate all base fields of a RequestAbstractType
     *
     * @param destination A URI reference indicating the address to which this request has been sent. This is useful to prevent malicious forwarding of
     *                    requests to unintended recipients, a protection that is required by some protocol bindings. If it is present, the actual recipient
     *                    MUST check that the URI reference identifies the location at which the message was received. If it does not, the request MUST be
     *                    discarded. Some protocol bindings may require the use of this attribute (see [SAMLBind]). (Optional, use null of it shouldn't be set)
     * @param consent Indicates whether or not (and under what conditions) consent has been obtained from a principal in
     *                the sending of this request. See Section 8.4 for some URI references that MAY be used as the value.
     *                of the Consent attribute and their associated descriptions. If no Consent value is provided, the
     *                identifier urn:oasis:names:tc:SAML:2.0:consent:unspecified (see Section 8.4.1) is in effect. (Optional, use null of it shouldn't be set)
     *
     * @param issuer Identifies the entity that generated the request message. (For more information on this element, see Section 2.2.5.) (Optional, use null of it shouldn't be set)
     * @param extensions This extension point contains optional protocol message extension elements that are agreed on
     *                      between the communicating parties. No extension schema is required in order to make use of this
     *                      extension point, and even if one is provided, the lax validation setting does not impose a requirement
     *                      for the extension to be valid. SAML extension elements MUST be namespace-qualified in a non-
     *                      SAML-defined namespace. (Optional, use null of it shouldn't be set)
     * @throws MessageProcessingException if internal problem occurred generating the message.
     * @throws MessageContentException if invalid message format was detected.
     */
    protected void populateRequestAbstractType(RequestAbstractType requestAbstractType, String destination, String consent, NameIDType issuer, ExtensionsType extensions) throws MessageProcessingException, MessageContentException{
        populateRequestAbstractType(requestAbstractType, "_" + MessageGenerateUtils.generateRandomUUID(), destination,consent,issuer,extensions);

    }

    /**
     * Help method to populate the common fields of a StatusResponseType object.
     * @param inResponseTo the ID of the request, null if message was unreadable
     * @param issuer Identifies the entity that generated the response message. (Optional, null for no issuer)
     * @param destination  A URI reference indicating the address to which this response has been sent. This is useful to prevent
     *                        malicious forwarding of responses to unintended recipients, a protection that is required by some
     *                        protocol bindings. If it is present, the actual recipient MUST check that the URI reference identifies the
     *                        location at which the message was received. If it does not, the response MUST be discarded. Some
     *                        protocol bindings may require the use of this attribute. (Optional, null for no destination)
     * @param consent Indicates whether or not (and under what conditions) consent has been obtained from a principal in
     *                   the sending of this response. See Section 8.4 for some URI references that MAY be used as the value
     *                   of the Consent attribute and their associated descriptions. If no Consent value is provided, the
     *                   identifier urn:oasis:names:tc:SAML:2.0:consent:unspecified (see Section 8.4.1) is in
     *                   effect.
     * @param extensions This extension point contains optional protocol message extension elements that are agreed on
     *                      between the communicating parties. . No extension schema is required in order to make use of this
     *                      extension point, and even if one is provided, the lax validation setting does not impose a requirement
     *                      for the extension to be valid. SAML extension elements MUST be namespace-qualified in a non-SAML-defined namespace. (Optional, null for no extensions)
     * @param statusCode the failure code to respond to (Required)
     * @param statusMessage a descriptive  message, may be null.
     * @param statusDetail a container for generic status XML. (Optional)
     * @return a SAMLP failure message.
     * @throws MessageContentException if parameters where invalid.
     * @throws MessageProcessingException if internal problems occurred generated the message.
     */
    protected void populateStatusResponseType(StatusResponseType statusResponseType, String inResponseTo, String destination, String consent, NameIDType issuer, ExtensionsType extensions, ResponseStatusCodes statusCode, String statusMessage, StatusDetailType statusDetail) throws MessageProcessingException, MessageContentException{
        StatusCodeType statusCodeType = samlpOf.createStatusCodeType();
        statusCodeType.setValue(statusCode.getURIValue());

        StatusType statusType = samlpOf.createStatusType();
        statusType.setStatusCode(statusCodeType);

        statusType.setStatusMessage(statusMessage);
        statusType.setStatusDetail(statusDetail);

        statusResponseType.setID("_" + MessageGenerateUtils.generateRandomUUID());
        statusResponseType.setIssueInstant(MessageGenerateUtils.dateToXMLGregorianCalendar(systemTime.getSystemTime()));
        statusResponseType.setVersion(DEFAULT_SAML_VERSION);
        statusResponseType.setInResponseTo(inResponseTo);
        statusResponseType.setStatus(statusType);

        statusResponseType.setIssuer(issuer);
        statusResponseType.setDestination(destination);
        statusResponseType.setConsent(consent);
        statusResponseType.setExtensions(extensions);

    }

    /**
     * Method that extracts all unencrypted SAMLP assertions from a SAMLPResponse and
     * tries to retain any internal signature of existing assertions.
     * @param samlPResponse the SAMLPResponse to extract Assertions from.
     * @return a list containing all assertions found in SAMLP Document.
     */
    public List<Document> extractAssertionsFromSAMLP(Document samlPResponse) throws MessageContentException{
        try{
            List<Document> retval = new ArrayList<Document>();
            NodeList assertionNodes = samlPResponse.getElementsByTagNameNS(ASSERTION_NAMESPACE, "Assertion");
            for(int i=0; i < assertionNodes.getLength(); i++ ){
                Node assertionNode = assertionNodes.item(i);
                Document newDoc = getDocumentBuilder().newDocument();
                Node newNode = assertionNode.cloneNode(true);
                newDoc.adoptNode(newNode);
                newDoc.appendChild(newNode);
                retval.add(newDoc);
            }
            return retval;
        }catch(Exception e){
            throw new MessageContentException("Error extracting assertions from SAMLP Response: " + e.getMessage(), e);
        }
    }

    /**
     * AuthNSignature specific signature location finder.
     */
    private class AuthNSignatureLocationFinder extends SAMLPSignatureLocationFinder{

        @Override
        public List<QName> getSiblingsBeforeSignature(Element element) throws MessageContentException {
            List<QName> beforeSiblings = new ArrayList<QName>();
            beforeSiblings.add(new QName(PROTOCOL_NAMESPACE, "Extensions"));
            beforeSiblings.add(new QName(ASSERTION_NAMESPACE, "Subject"));
            beforeSiblings.add(new QName(PROTOCOL_NAMESPACE, "NameIDPolicy"));
            beforeSiblings.add(new QName(ASSERTION_NAMESPACE, "Conditions"));
            beforeSiblings.add(new QName(PROTOCOL_NAMESPACE, "RequestedAuthnContext"));
            beforeSiblings.add(new QName(PROTOCOL_NAMESPACE, "Scoping"));
            return beforeSiblings;
        }
    }


}
