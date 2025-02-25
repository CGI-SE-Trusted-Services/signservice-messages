package org.signatureservice.messages.saml2.assertion;

import org.signatureservice.messages.ContextMessageSecurityProvider;
import org.signatureservice.messages.MessageContentException;
import org.signatureservice.messages.MessageProcessingException;
import org.signatureservice.messages.NoDecryptionKeyFoundException;
import org.signatureservice.messages.csmessages.DefaultCSMessageParser;
import org.signatureservice.messages.saml2.BaseSAMLMessageParser;
import org.signatureservice.messages.saml2.assertion.jaxb.*;
import org.signatureservice.messages.utils.MessageGenerateUtils;
import org.signatureservice.messages.utils.XMLEncrypter;
import org.signatureservice.messages.utils.XMLSigner;
import org.signatureservice.messages.xenc.jaxb.EncryptedDataType;
import org.signatureservice.messages.xenc.jaxb.ObjectFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 * MessageParser for generating generate SAML 2.0 Assertions. This should be used when generating SAML Assertions
 * that is not connected to CSMessages. For CSMessage related assertions use AssertionPayloadParser.
 *
 * Created by philip on 02/01/17.
 */
public class SAMLAssertionMessageParser extends BaseSAMLMessageParser{

    private static final String BASE_JAXB_CONTEXT = "org.signatureservice.messages.saml2.assertion.jaxb:org.signatureservice.messages.saml2.protocol.jaxb:org.signatureservice.messages.xenc.jaxb:org.signatureservice.messages.xmldsig.jaxb";

    EncryptedAssertionXMLConverter encryptedAssertionXMLConverter = new EncryptedAssertionXMLConverter();

    @Override
    public String getNameSpace() {
        return ASSERTION_NAMESPACE;
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
        return assertionSignatureLocationFinder;
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
            if(namespaceURI.equals(PROTOCOL_NAMESPACE)){
                return BaseSAMLMessageParser.SAMLP_XSD_SCHEMA_2_0_RESOURCE_LOCATION;
            }
            if(namespaceURI.equals(ASSERTION_NAMESPACE)){
                return BaseSAMLMessageParser.ASSERTION_XSD_SCHEMA_2_0_RESOURCE_LOCATION;
            }
        }
        return null;
    }

    /**
     * Method for generating a simple assertion data structure.
     * @param issuer the name if the issuer, set as NameIDType
     * @param notBefore the not before date
     * @param notOnOrAfter the expiration date
     * @param subjectId the name of the subject the assertion is related to.
     * @param attributes a list of attributes or encrypted attributes to add to the assertion.
     * @return a simply assertion.
     * @throws MessageProcessingException if internal problems occurred generating the assertion.
     */
    public JAXBElement<AssertionType> generateSimpleAssertion(String issuer, Date notBefore, Date notOnOrAfter, String subjectId, List<Object> attributes) throws MessageProcessingException{
        AttributeStatementType attributeStatementType = null;
        if(attributes != null) {
            attributeStatementType = of.createAttributeStatementType();
            for (Object attribute : attributes) {
                attributeStatementType.getAttributeOrEncryptedAttribute().add(attribute);
            }
        }

        NameIDType issuerNameType = of.createNameIDType();
        issuerNameType.setValue(issuer);


        NameIDType subjectNameType = of.createNameIDType();
        subjectNameType.setValue(subjectId);

        SubjectType subjectType = of.createSubjectType();
        subjectType.getContent().add(of.createNameID(subjectNameType));

        ConditionsType conditionsType = of.createConditionsType();
        conditionsType.setNotBefore(MessageGenerateUtils.dateToXMLGregorianCalendarNoTimeZone(notBefore));
        conditionsType.setNotOnOrAfter(MessageGenerateUtils.dateToXMLGregorianCalendarNoTimeZone(notOnOrAfter));

        AssertionType assertionType = of.createAssertionType();
        assertionType.setID("_" + MessageGenerateUtils.generateRandomUUID());
        assertionType.setIssueInstant(MessageGenerateUtils.dateToXMLGregorianCalendarNoTimeZone(systemTime.getSystemTime()));
        assertionType.setVersion(DEFAULT_SAML_VERSION);
        assertionType.setIssuer(issuerNameType);
        assertionType.setSubject(subjectType);
        assertionType.setConditions(conditionsType);
        if(attributeStatementType != null) {
            assertionType.getStatementOrAuthnStatementOrAuthzDecisionStatement().add(attributeStatementType);
        }
        return of.createAssertion(assertionType);
    }

    /**
     * Method to create an Encrypt an assertion and create an EncryptedAssertion Element
     * @param context message security related context.
     * @param assertion assertion to encrypt
     * @param reciepients a list of receipients
     * @param useKeyId, use a id of the key used instead of full certificates.
     * @return an decrypted assertion
     * @throws MessageContentException if content of message was invalid.
     * @throws MessageProcessingException if internal problems occurred parsing the assertions.
     */
    public JAXBElement<EncryptedElementType> genEncryptedAssertion(ContextMessageSecurityProvider.Context context, byte[] assertion, List<X509Certificate> reciepients, boolean useKeyId) throws MessageContentException, MessageProcessingException{
        try {
            Document doc = getDocumentBuilder().parse(new ByteArrayInputStream(assertion));
            Document encDoc = xmlEncrypter.encryptElement(context,doc,reciepients,useKeyId);
            JAXBElement<?> encryptedData = (JAXBElement<?>) getUnmarshaller().unmarshal(encDoc);
            EncryptedElementType encryptedElement = of.createEncryptedElementType();
            encryptedElement.setEncryptedData((EncryptedDataType) encryptedData.getValue());
            return of.createEncryptedAssertion(encryptedElement);

        } catch(JAXBException e ){
            throw new MessageProcessingException(e.getMessage(),e);
        } catch (SAXException e) {
            throw new MessageProcessingException(e.getMessage(),e);
        } catch (IOException e) {
            throw new MessageContentException(e.getMessage(),e);
        }
    }

    /**
     * Method to decrypt an EncryptedAssertion .
     *
     * @param context message security related context.
     * @param encryptedAssertion the encrypted assertion
     * @param verify if signature if decrypted assertion should be verified.
     * @return an decrypted assertion
     * @throws MessageContentException if content of message was invalid.
     * @throws MessageProcessingException if internal problems occurred parsing the assertions.
     * @throws NoDecryptionKeyFoundException if no key could be found decrypting the assertion.
     */
    public JAXBElement<AssertionType> decryptEncryptedAssertion(ContextMessageSecurityProvider.Context context, EncryptedElementType encryptedAssertion, boolean verify) throws MessageContentException, MessageProcessingException, NoDecryptionKeyFoundException{
        Document decryptedDoc = decryptEncryptedAssertionToDoc(context,encryptedAssertion);
        return marshallAndVerifyAssertionDoc(context,decryptedDoc,verify);
    }

    /**
     * Method to decrypt an EncryptedAssertion and convert it to Document. This method does not verify the signature nor schema. This
     * can be used by calling marshallAndVerifyAssertionDoc() afterwards or just call decryptEncryptedAssertion().
     *
     * @param context message security related context.
     * @param encryptedAssertion the encrypted assertion
     * @return an decrypted assertion i Document format.
     * @throws MessageContentException if content of message was invalid.
     * @throws MessageProcessingException if internal problems occurred parsing the assertions.
     * @throws NoDecryptionKeyFoundException if no key could be found decrypting the assertion.
     */
    public Document decryptEncryptedAssertionToDoc(ContextMessageSecurityProvider.Context context, EncryptedElementType encryptedAssertion) throws MessageContentException, MessageProcessingException, NoDecryptionKeyFoundException{
        try {
            ObjectFactory xmlEncOf = new ObjectFactory();
            Document doc = getDocumentBuilder().newDocument();

            getMarshaller().marshal(xmlEncOf.createEncryptedData(encryptedAssertion.getEncryptedData()), doc);

            return xmlEncrypter.decryptDoc(context, doc,null);
        } catch (JAXBException e) {
            throw new MessageContentException("Error parsing assertion : " + e.getMessage(), e);
        }catch (SecurityException e) {
            throw new MessageProcessingException("Internal error parsing assertion: " + e.getMessage(),e);
        }
    }

    /**
     * Method to decrypt an EncryptedAssertion .
     *
     * @param context message security related context.
     * @param assertionDoc the encrypted assertion
     * @param verify if signature if decrypted assertion should be verified.
     * @return an decrypted assertion
     * @throws MessageContentException if content of message was invalid.
     * @throws MessageProcessingException if internal problems occurred parsing the assertions.
     * @throws NoDecryptionKeyFoundException if no key could be found decrypting the assertion.
     */
    public JAXBElement<AssertionType> marshallAndVerifyAssertionDoc(ContextMessageSecurityProvider.Context context, Document assertionDoc, boolean verify) throws MessageContentException, MessageProcessingException, NoDecryptionKeyFoundException {
        try {
            if (verify) {
                xmlSigner.verifyEnvelopedSignature(context, assertionDoc, getSignatureLocationFinder(), getOrganisationLookup());
            }
            @SuppressWarnings("unchecked")
            JAXBElement<AssertionType> assertion = (JAXBElement<AssertionType>) getUnmarshaller().unmarshal(assertionDoc);

            schemaValidate(assertion);

            return assertion;
        } catch (JAXBException e) {
            throw new MessageContentException("Error parsing assertion : " + e.getMessage(), e);
        } catch (SecurityException e) {
            throw new MessageProcessingException("Internal error parsing assertion: " + e.getMessage(), e);
        } catch (SAXException e) {
            throw new MessageContentException("Error parsing assertion : " + e.getMessage(), e);
        }
    }




            /**
             * Method to verify a signature of an assertion in a parsed SAML message.
             * @param context message security related context.
             * @param assertion the assertion to verify.
             * @throws MessageContentException if assertion contained invalid data.
             * @throws MessageProcessingException  if internal error occurred processing the assertion.
             */
    public  void verifyAssertionSignature(ContextMessageSecurityProvider.Context context,AssertionType assertion) throws MessageContentException, MessageProcessingException {
        Document doc = getDocumentBuilder().newDocument();
        try {
            getMarshaller().marshal(of.createAssertion(assertion), doc);
        } catch (JAXBException e) {
            throw new MessageContentException("Error marshalling assertion: " + e.getMessage(),e);
        }

        xmlSigner.verifyEnvelopedSignature(context,doc,getSignatureLocationFinder(),getOrganisationLookup());
    }


    /**
     * Converter that replaces all decrypted EncryptedAssertion with Assertion
     */
    public static class EncryptedAssertionXMLConverter implements XMLEncrypter.DecryptedXMLConverter {


        public Document convert(Document doc) throws MessageContentException {
            NodeList nodeList = doc.getElementsByTagNameNS(BaseSAMLMessageParser.ASSERTION_NAMESPACE, "Assertion");
            for(int i =0; i < nodeList.getLength(); i++){
                Element attribute= (Element) nodeList.item(i);
                Element parent = (Element) attribute.getParentNode();
                if(parent.getLocalName().equals("EncryptedAssertion") && parent.getNamespaceURI().equals(BaseSAMLMessageParser.ASSERTION_NAMESPACE)){
                    parent.getParentNode().replaceChild(attribute, parent);
                }

            }

            return doc;
        }

    }
}
