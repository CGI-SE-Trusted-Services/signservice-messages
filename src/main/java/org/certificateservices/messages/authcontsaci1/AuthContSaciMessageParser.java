/************************************************************************
 *                                                                       *
 *  Certificate Service - Messages                                       *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3 of the License, or any later version.                      *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.certificateservices.messages.authcontsaci1;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.authcontsaci1.jaxb.*;
import org.certificateservices.messages.csmessages.DefaultCSMessageParser;
import org.certificateservices.messages.csmessages.XSDLSInput;
import org.certificateservices.messages.saml2.assertion.SAMLAssertionMessageParser;
import org.certificateservices.messages.sweeid2.dssextenstions1_1.jaxb.ContextInfoType;
import org.certificateservices.messages.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.bind.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

/**
 * MessageParser for generating generate AuthCont 1.0 SACI message according to RFC 7773.
 *
 * Created by philip on 02/01/17.
 */
public class AuthContSaciMessageParser {

    private static final String BASE_JAXB_CONTEXT = "org.certificateservices.messages.saml2.assertion.jaxb:org.certificateservices.messages.authcontsaci1.jaxb";

    public static final String NAMESPACE = "http://id.elegnamnden.se/auth-cont/1.0/saci";

    private static final String SCHEMA_LOCATION = "/auth-cont-1_0-saci.xsd";

    org.certificateservices.messages.authcontsaci1.jaxb.ObjectFactory of = new org.certificateservices.messages.authcontsaci1.jaxb.ObjectFactory();


    /**
     * Method to parse a unencrypted hard token data.
     *
     * @param data a serialized hard token data XML structure.
     * @return a unmarshalled HardTokenData.
     * @throws MessageContentException if xml data was invalid
     * @throws MessageProcessingException if internal problems occurred unmarshalling the data.
     */
    public SAMLAuthContextType parse(byte[] data) throws MessageContentException, MessageProcessingException{
        Document doc;
        try {
            doc = getDocumentBuilder().parse(new ByteArrayInputStream(data));
            return (SAMLAuthContextType) ((JAXBElement) getUnmarshaller().unmarshal(doc)).getValue();
        } catch (SAXException e) {
            throw new MessageContentException("Message content error when parsing auth cont saci data: " + e.getMessage(), e);
        } catch (IOException e) {
            throw new MessageContentException("Message content error when parsing auth cont saci data: " + e.getMessage(), e);
        }catch (JAXBException e) {
            throw new MessageContentException("Message content error when parsing auth cont saci data: " + e.getMessage(), e);
        } catch (ParserConfigurationException e) {
            throw new MessageProcessingException("Internal error when parsing auth cont saci data: " + e.getMessage(), e);
        }
    }


    /**
     * Method to create a marshalled SAML Auth Context XML, according to RFC 7773
     *
     * @param contextInfo the sweeid context info that will be converted into saci context info.
     * @param attributeMappings a list of attribute mappings.
     * @return marshalled SAML AuthContextInfo
     * @throws MessageProcessingException if internal problems occurred generating the message.
     */
    public byte[] genSAMLAuthContext(ContextInfoType contextInfo, List<AttributeMappingType> attributeMappings) throws MessageProcessingException {
        try{
          SAMLAuthContextType samlAuthContext = of.createSAMLAuthContextType();
          samlAuthContext.setAuthContextInfo(convertContextInfoType(contextInfo));
          samlAuthContext.setIdAttributes(of.createIdAttributesType());
          samlAuthContext.getIdAttributes().getAttributeMapping().addAll(attributeMappings);
          ByteArrayOutputStream baos = new ByteArrayOutputStream();
          getMarshaller().marshal(of.createSAMLAuthContext(samlAuthContext), baos);
          return baos.toByteArray();
        }catch(Exception e) {
            throw new MessageProcessingException("Error generating genSAMLAuthContext message: " + e.getMessage(),e);
        }
    }

    /**
     * Help method to convert a sweeid context info into saci context info
     */
    private AuthContextInfoType convertContextInfoType(ContextInfoType contextInfo){
        AuthContextInfoType authContextInfo = of.createAuthContextInfoType();
        authContextInfo.setAssertionRef(contextInfo.getAssertionRef());
        authContextInfo.setAuthenticationInstant(contextInfo.getAuthenticationInstant());
        authContextInfo.setAuthnContextClassRef(contextInfo.getAuthnContextClassRef());
        authContextInfo.setIdentityProvider(contextInfo.getIdentityProvider().getValue());
        authContextInfo.setServiceID(contextInfo.getServiceID());
        return authContextInfo;
    }


    private DocumentBuilder getDocumentBuilder() throws ParserConfigurationException {
        return XMLUtils.createDocumentBuilderFactory().newDocumentBuilder();
    }

    Marshaller getMarshaller() throws JAXBException{
        Marshaller marshaller = getJAXBContext().createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
        return marshaller;
    }

    Unmarshaller getUnmarshaller() throws JAXBException, SAXException{
        Unmarshaller unmarshaller = getJAXBContext().createUnmarshaller();
        unmarshaller.setSchema(getSchema());
        return unmarshaller;
    }

    private JAXBContext jaxbContext = null;

    /**
     * Help method maintaining the Assertion JAXB Context.
     */
    private JAXBContext getJAXBContext() throws JAXBException{
        if(jaxbContext== null){
            jaxbContext = JAXBContext.newInstance(BASE_JAXB_CONTEXT);

        }
        return jaxbContext;
    }

    private Schema schema = null;
    private Schema getSchema() throws SAXException {
        if(schema == null){
            schema = generateSchema();
        }
        return schema;
    }

    private Schema generateSchema() throws SAXException{
        SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);

        schemaFactory.setResourceResolver(new AuthContentSaciLSResourceResolver());

        Source[] sources = new Source[4];
        sources[0] = new StreamSource(getClass().getResourceAsStream(DefaultCSMessageParser.XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION));
        sources[1] = new StreamSource(getClass().getResourceAsStream(DefaultCSMessageParser.XMLENC_XSD_SCHEMA_RESOURCE_LOCATION));
        sources[2] = new StreamSource(getClass().getResourceAsStream(SAMLAssertionMessageParser.ASSERTION_XSD_SCHEMA_2_0_RESOURCE_LOCATION));
        sources[3] = new StreamSource(getClass().getResourceAsStream(SCHEMA_LOCATION));

        Schema schema = schemaFactory.newSchema(sources);

        return schema;
    }


    private Transformer transformer = null;
    private Transformer getTransformer() throws MessageProcessingException{
        if(transformer == null){
            try {
                TransformerFactory tf = TransformerFactory.newInstance();
                transformer = tf.newTransformer();
            } catch (TransformerConfigurationException e) {
                throw new MessageProcessingException("Error instanciating Transformer for XMLSigner: " + e.getMessage(),e);
            }
        }
        return transformer;
    }

    public class AuthContentSaciLSResourceResolver implements LSResourceResolver {

        public LSInput resolveResource(String type, String namespaceURI,
                                       String publicId, String systemId, String baseURI) {
            try {
                if(systemId != null && systemId.equals("http://www.w3.org/2001/XMLSchema.dtd")){
                    return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream("/XMLSchema.dtd"));
                }
                if(systemId != null && systemId.equals("datatypes.dtd")){
                    return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream("/datatypes.dtd"));
                }
                if(namespaceURI != null){
                    if(namespaceURI.equals(SAMLAssertionMessageParser.ASSERTION_NAMESPACE)){
                        return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream(SAMLAssertionMessageParser.ASSERTION_XSD_SCHEMA_2_0_RESOURCE_LOCATION));
                    }
                    if(namespaceURI.equals(NAMESPACE)){
                        return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream(SCHEMA_LOCATION));
                    }
                }
            } catch (MessageProcessingException e) {
                throw new IllegalStateException("Error couldn't read XSD from class path: " + e.getMessage(), e);
            }
            return null;
        }
    }
}
