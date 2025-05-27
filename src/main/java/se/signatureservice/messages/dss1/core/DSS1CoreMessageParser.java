package se.signatureservice.messages.dss1.core;

import se.signatureservice.messages.ContextMessageSecurityProvider;
import se.signatureservice.messages.MessageContentException;
import se.signatureservice.messages.MessageProcessingException;
import se.signatureservice.messages.csmessages.DefaultCSMessageParser;
import se.signatureservice.messages.dss1.core.jaxb.*;
import se.signatureservice.messages.dss1.core.jaxb.*;
import se.signatureservice.messages.saml2.BaseSAMLMessageParser;
import se.signatureservice.messages.utils.XMLSigner;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import jakarta.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import java.util.List;

/**
 * MessageParser for generating generate DSS 1.0 messages.
 *
 * Created by philip on 02/01/17.
 */
public class DSS1CoreMessageParser extends BaseSAMLMessageParser{

    public static final String NAMESPACE = "urn:oasis:names:tc:dss:1.0:core:schema";
    public static final String SAML_1_1_NAMESPACE = "urn:oasis:names:tc:SAML:1.0:assertion";

    protected static final String BASE_JAXB_CONTEXT = "se.signatureservice.messages.saml1_1.assertions.jaxb:se.signatureservice.messages.dss1.core.jaxb:se.signatureservice.messages.xmldsig.jaxb";

    protected static final String ASSERTION_XSD_SCHEMA_1_1_RESOURCE_LOCATION = "/cs-message-oasis-sstc-saml-schema-protocol-1.1.xsd";
    protected static final String DSS_XSD_SCHEMA_1_0_RESOURCE_LOCATION = "/cs-message-oasis-dss-core-schema-v1.0-os.xsd";


    protected ObjectFactory dssOf = new ObjectFactory();

    private DSS1CoreSignatureLocationFinder dss1CoreSignatureLocationFinder = new DSS1CoreSignatureLocationFinder();
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
                ASSERTION_XSD_SCHEMA_1_1_RESOURCE_LOCATION,
                DSS_XSD_SCHEMA_1_0_RESOURCE_LOCATION};
    }

    @Override
    public XMLSigner.SignatureLocationFinder getSignatureLocationFinder(){ return dss1CoreSignatureLocationFinder;}

    @Override
    public XMLSigner.OrganisationLookup getOrganisationLookup(){
        return null;
    }

    @Override
    protected String lookupSchemaForElement(String type, String namespaceURI, String publicId, String systemId, String baseURI) {
        if(namespaceURI != null){
            if(namespaceURI.equals("http://www.w3.org/XML/1998/namespace")){
                return "/xml.xsd";
            }
            if(namespaceURI.equals(DefaultCSMessageParser.XMLDSIG_NAMESPACE)){
                return DefaultCSMessageParser.XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION;
            }
            if(namespaceURI.equals(NAMESPACE)){
                return DSS_XSD_SCHEMA_1_0_RESOURCE_LOCATION;
            }
            if(namespaceURI.equals(SAML_1_1_NAMESPACE)){
                return ASSERTION_XSD_SCHEMA_1_1_RESOURCE_LOCATION;
            }
        }
        return null;
    }


    /**
     * Method to generate a SignRequest
     *
     * @param requestID This attribute is used to correlate requests with responses.
     *                  When present in a request, the server MUST return it in the response.
     *                  (Optional, use null to not set).
     * @param profile This attribute indicates a particular DSS profile.  It may be used to select a profile
     *                if a server supports multiple profiles, or as a sanity-check to make sure the server implements
     *                the profile the client expects. (Optional, use null to not set).
     * @param optionalInputs Any additional inputs to the request.  (Optional, use null to not set).
     * @param inputDocuments The input documents which the processing will be applied to.  (Optional, use null to not set).
     * @return a newly created SignRequest.
     */
    public SignRequest genSignRequest(String requestID, String profile, List<Object> optionalInputs, InputDocuments inputDocuments) {
        SignRequest sr = dssOf.createSignRequest();
        populateRequestBase(sr,requestID,profile,optionalInputs,inputDocuments);
        return sr;
    }

    /**
     * Method to generate a marshalled SignRequest that is optionally signed.
     * @param context message security related context. Use null if no signature should be used.
     * @param requestID This attribute is used to correlate requests with responses.
     *                  When present in a request, the server MUST return it in the response.
     *                  (Optional, use null to not set).
     * @param profile This attribute indicates a particular DSS profile.  It may be used to select a profile
     *                if a server supports multiple profiles, or as a sanity-check to make sure the server implements
     *                the profile the client expects. (Optional, use null to not set).
     * @param optionalInputs Any additional inputs to the request.  (Optional, use null to not set).
     * @param inputDocuments The input documents which the processing will be applied to.  (Optional, use null to not set).
     * @param sign if message should contains signature.
     * @return a marshalled an optionally signed message.
     * @throws MessageProcessingException if internal error occurred generating the message.
     * @throws MessageContentException if bad message format was detected.
     */
    public byte[] genSignRequest(ContextMessageSecurityProvider.Context context,String requestID, String profile, List<Object> optionalInputs, InputDocuments inputDocuments, boolean sign) throws MessageProcessingException, MessageContentException {
        SignRequest sr = genSignRequest(requestID,profile,optionalInputs,inputDocuments);
        if(sign) {
            return marshallAndSign(context,sr);
        }
        return marshall(sr);
    }

    /**
     * Method to generate a SignResponse.
     *
     * @param requestID This attribute is used to correlate requests with responses.
     *                  When present in a request, the server MUST return it in the response.
     *                  (Optional, use null to not set).
     * @param profile This attribute indicates a particular DSS profile.  It may be used to select a profile
     *                if a server supports multiple profiles, or as a sanity-check to make sure the server implements
     *                the profile the client expects. (Optional, use null to not set).
     * @param result A code representing the status of the request. (Required).
     * @param optionalOutputs Any additional outputs returned by the server.  (Optional, use null to not set).
     * @param signatureObject The result signature or timestamp or, in the case of a signature being enveloped in an
     *                        output document (see section 3.5.8), a pointer to the signature.In the case of
     *                        SignaturePlacement being used this MUST contain a SignaturePtr, having the same XPath
     *                        expression as in SignaturePlacement and pointing to a DocumentWithSignature using it's
     *                        WhichDocument attribute. (Optional, use null to not set).
     * @return a newly created SignResponse.
     */
    public SignResponse genSignResponse(String requestID, String profile, Result result, List<Object> optionalOutputs, SignatureObject signatureObject){
        SignResponse sr = dssOf.createSignResponse();
        populateResponseBase(sr,requestID,profile,result,optionalOutputs);
        sr.setSignatureObject(signatureObject);
        return sr;
    }

    /**
     * Method to generate a marshalled SignResponse that is optionally signed.
     * @param context message security related context. Use null if no signature should be used.
     * @param requestID This attribute is used to correlate requests with responses.
     *                  When present in a request, the server MUST return it in the response.
     *                  (Optional, use null to not set).
     * @param profile This attribute indicates a particular DSS profile.  It may be used to select a profile
     *                if a server supports multiple profiles, or as a sanity-check to make sure the server implements
     *                the profile the client expects. (Optional, use null to not set).
     * @param result A code representing the status of the request. (Required).
     * @param optionalOutputs Any additional outputs returned by the server.  (Optional, use null to not set).
     * @param signatureObject The result signature or timestamp or, in the case of a signature being enveloped in an
     *                        output document (see section 3.5.8), a pointer to the signature.In the case of
     *                        SignaturePlacement being used this MUST contain a SignaturePtr, having the same XPath
     *                        expression as in SignaturePlacement and pointing to a DocumentWithSignature using it's
     *                        WhichDocument attribute. (Optional, use null to not set).
     * @param sign if message should contain signature.
     * @return a marshalled an optionally signed message.
     * @throws MessageProcessingException if internal error occurred generating the message.
     * @throws MessageContentException if bad message format was detected.
     */
    public byte[] genSignResponse(ContextMessageSecurityProvider.Context context,String requestID, String profile, Result result, List<Object> optionalOutputs, SignatureObject signatureObject, boolean sign) throws MessageProcessingException, MessageContentException {
        SignResponse sr = genSignResponse(requestID,profile,result,optionalOutputs,signatureObject);
        if(sign) {
            return marshallAndSign(context,sr);
        }
        return marshall(sr);
    }
    /**
     * Method to generate a VerifyRequest
     *
     * @param requestID This attribute is used to correlate requests with responses.
     *                  When present in a request, the server MUST return it in the response.
     *                  (Optional, use null to not set).
     * @param profile This attribute indicates a particular DSS profile.  It may be used to select a profile
     *                if a server supports multiple profiles, or as a sanity-check to make sure the server implements
     *                the profile the client expects. (Optional, use null to not set).
     * @param optionalInputs Any additional inputs to the request.  (Optional, use null to not set).
     * @param inputDocuments The input documents which the processing will be applied to.  (Optional, use null to not set).
     * @param signatureObject This element contains a signature or timestamp, or else contains a SignaturePtr that points
     *                        to an XML signature in one of the input documents.  If this element is omitted, there must be
     *                        only a single InputDocument which the server will search to find the to-be-verified signature(s).
     *                        Either a SignaturePtr or a single InputDocument and no SignatureObject MUST be used whenever
     *                        the to-be-verified signature is an XML signature which uses an Enveloped Signature Transform;
     *                        otherwise the server would have difficulty locating the signature and applying the
     *                        Enveloped Signature Transform. (Optional, use null to not set).
     * @return a newly created VerifyRequest.
     */
    public VerifyRequest genVerifyRequest(String requestID, String profile, List<Object> optionalInputs,
                                          InputDocuments inputDocuments, SignatureObject signatureObject){
        VerifyRequest vr = dssOf.createVerifyRequest();
        populateRequestBase(vr,requestID,profile,optionalInputs,inputDocuments);
        vr.setSignatureObject(signatureObject);
        return vr;
    }

    /**
     * Method to generate a marshalled VerifyRequest that is optionally signed.
     *
     * @param context message security related context. Use null if no signature should be used.
     * @param requestID This attribute is used to correlate requests with responses.
     *                  When present in a request, the server MUST return it in the response.
     *                  (Optional, use null to not set).
     * @param profile This attribute indicates a particular DSS profile.  It may be used to select a profile
     *                if a server supports multiple profiles, or as a sanity-check to make sure the server implements
     *                the profile the client expects. (Optional, use null to not set).
     * @param optionalInputs Any additional inputs to the request.  (Optional, use null to not set).
     * @param inputDocuments The input documents which the processing will be applied to.  (Optional, use null to not set).
     * @param signatureObject This element contains a signature or timestamp, or else contains a SignaturePtr that points
     *                        to an XML signature in one of the input documents.  If this element is omitted, there must be
     *                        only a single InputDocument which the server will search to find the to-be-verified signature(s).
     *                        Either a SignaturePtr or a single InputDocument and no SignatureObject MUST be used whenever
     *                        the to-be-verified signature is an XML signature which uses an Enveloped Signature Transform;
     *                        otherwise the server would have difficulty locating the signature and applying the
     *                        Enveloped Signature Transform. (Optional, use null to not set).
     * @param sign if message should contain signature.
     * @return a marshalled an optionally signed message.
     * @throws MessageProcessingException if internal error occurred generating the message.
     * @throws MessageContentException if bad message format was detected.
     */
    public byte[] genVerifyRequest(ContextMessageSecurityProvider.Context context,String requestID, String profile, List<Object> optionalInputs,
                                   InputDocuments inputDocuments,SignatureObject signatureObject, boolean sign) throws MessageProcessingException, MessageContentException {
        VerifyRequest vr = genVerifyRequest(requestID,profile,optionalInputs,inputDocuments,signatureObject);
        if(sign) {
            return marshallAndSign(context,vr);
        }
        return marshall(vr);

    }
    /**
     * Method to generate a VerifyResponse.
     *
     * @param requestID This attribute is used to correlate requests with responses.
     *                  When present in a request, the server MUST return it in the response.
     *                  (Optional, use null to not set).
     * @param profile This attribute indicates a particular DSS profile.  It may be used to select a profile
     *                if a server supports multiple profiles, or as a sanity-check to make sure the server implements
     *                the profile the client expects. (Optional, use null to not set).
     * @param result A code representing the status of the request. (Required).
     * @param optionalOutputs Any additional outputs returned by the server.  (Optional, use null to not set).
     * @return  a newly created VerifyResponse.
     */
    public JAXBElement<ResponseBaseType> genVerifyResponse(String requestID, String profile, Result result, List<Object> optionalOutputs){
        ResponseBaseType rb = dssOf.createResponseBaseType();
        populateResponseBase(rb, requestID,profile,result,optionalOutputs);
        return dssOf.createVerifyResponse(rb);
    }

    /**
     * Method to generate a marshalled VerifyResponse that is optionally signed.
     *
     * @param context message security related context. Use null if no signature should be used.
     * @param requestID This attribute is used to correlate requests with responses.
     *                  When present in a request, the server MUST return it in the response.
     *                  (Optional, use null to not set).
     * @param profile This attribute indicates a particular DSS profile.  It may be used to select a profile
     *                if a server supports multiple profiles, or as a sanity-check to make sure the server implements
     *                the profile the client expects. (Optional, use null to not set).
     * @param result A code representing the status of the request. (Required).
     * @param optionalOutputs Any additional outputs returned by the server.  (Optional, use null to not set).
     * @param sign if message should contain signature.
     * @return a marshalled an optionally signed message.
     * @throws MessageProcessingException if internal error occurred generating the message.
     * @throws MessageContentException if bad message format was detected.
     */
    public byte[] genVerifyResponse(ContextMessageSecurityProvider.Context context,String requestID, String profile, Result result, List<Object> optionalOutputs, boolean sign) throws MessageProcessingException, MessageContentException {
        JAXBElement<ResponseBaseType> vr = genVerifyResponse(requestID,profile,result,optionalOutputs);
        if(sign) {
            return marshallAndSign(context,vr);
        }
        return marshall(vr);
    }


    /**
     * Method to populate all fields in a base request object
     *
     * @param requestBase the object to populate.
     * @param requestID This attribute is used to correlate requests with responses.
     *                  When present in a request, the server MUST return it in the response.
     *                  (Optional, use null to not set).
     * @param profile This attribute indicates a particular DSS profile.  It may be used to select a profile
     *                if a server supports multiple profiles, or as a sanity-check to make sure the server implements
     *                the profile the client expects. (Optional, use null to not set).
     * @param optionalInputs Any additional inputs to the request.  (Optional, use null to not set).
     * @param inputDocuments The input documents which the processing will be applied to.  (Optional, use null to not set).
     */
    public void populateRequestBase(RequestBaseType requestBase, String requestID, String profile, List<Object> optionalInputs, InputDocuments inputDocuments){
        requestBase.setRequestID(requestID);
        requestBase.setProfile(profile);
        if(optionalInputs != null) {
            AnyType anyType = dssOf.createAnyType();
            anyType.getAny().addAll(optionalInputs);
            requestBase.setOptionalInputs(anyType);
        }
        requestBase.setInputDocuments(inputDocuments);
    }

    /**
     * Help method to generate a Result structure.
     *
     * @see ResultMajorValues for applicable values for both resultMajor and resultMinor.
     *
     * @param resultMajor The most significant component of the result code. (Required)
     * @param resultMinor The least significant component of the result code. (Optional, use null to not set.)
     * @param resultMessage  message which MAY be returned to an operator, logged, used for debugging, etc. (Optional, use null to not set.)
     * @param resultMessageLang a xml:lang attribute to a human-readable string to specify the string's language. (Required if
     *                          resultMessage is set, otherwise null.
     * @return a populated result structure.
     */
    public Result genResult(String resultMajor, String resultMinor, String resultMessage, String resultMessageLang){
        Result r = dssOf.createResult();
        r.setResultMajor(resultMajor);
        r.setResultMinor(resultMinor);
        if(resultMessage != null) {
            InternationalStringType rm = dssOf.createInternationalStringType();
            rm.setLang(resultMessageLang);
            rm.setValue(resultMessage);
            r.setResultMessage(rm);
        }
        return r;
    }
    /**
     * Method to populate all fields in a base resposnse object
     *
     * @param responseBase the object to populate.
     * @param requestID This attribute is used to correlate requests with responses.
     *                  When present in a request, the server MUST return it in the response.
     *                  (Optional, use null to not set).
     * @param profile This attribute indicates a particular DSS profile.  It may be used to select a profile
     *                if a server supports multiple profiles, or as a sanity-check to make sure the server implements
     *                the profile the client expects. (Optional, use null to not set).
     * @param result A code representing the status of the request. (Required).
     * @param optionalOutputs Any additional outputs returned by the server.  (Optional, use null to not set).
     */
    protected void populateResponseBase(ResponseBaseType responseBase, String requestID, String profile, Result result, List<Object> optionalOutputs){
        responseBase.setRequestID(requestID);
        responseBase.setProfile(profile);
        responseBase.setResult(result);
        if(optionalOutputs != null) {
            AnyType anyType = dssOf.createAnyType();
            anyType.getAny().addAll(optionalOutputs);
            responseBase.setOptionalOutputs(anyType);
        }
    }



    public static class DSS1CoreSignatureLocationFinder implements XMLSigner.SignatureLocationFinder{

        public Element[] getSignatureLocations(Document doc)
                throws MessageContentException {
            try{
                Element docElement = doc.getDocumentElement();
                if(docElement.getNamespaceURI().equals(NAMESPACE)){
                    NodeList nl = docElement.getElementsByTagNameNS(NAMESPACE,"OptionalInputs");
                    if(nl.getLength() != 1) {
                        nl = docElement.getElementsByTagNameNS(NAMESPACE,"OptionalOutputs");
                    }
                    if(nl.getLength() != 1){
                        throw new MessageContentException("Error cannot sign DSS xml document that doesn't contain one OptionalInputs or OptionalOutputs child element.");
                    }
                    return new Element[] {(Element) nl.item(0)};
                }
            }catch(Exception e){
            }
            throw new MessageContentException("Invalid DSS message type sent for signature.");
        }

        // TODO, empty reference and verity the entire XML document is scoped.
        @Override
        public String getIDAttribute() {
            return null;
        }

        @Override
        public String getIDValue(Element signedElement) throws MessageContentException {
            return null;
        }

        @Override
        public List<QName> getSiblingsBeforeSignature(Element element) throws MessageContentException {
            return null;
        }
    }


}
