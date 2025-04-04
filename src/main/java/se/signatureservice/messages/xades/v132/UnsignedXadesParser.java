package se.signatureservice.messages.xades.v132;


import se.signatureservice.messages.MessageContentException;
import se.signatureservice.messages.MessageProcessingException;
import se.signatureservice.messages.csmessages.DefaultCSMessageParser;
import se.signatureservice.messages.csmessages.XSDLSInput;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import jakarta.xml.bind.*;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

/**
 * Parser to marshall and unmashall unsigned Xades structures.
 * Created by philip on 2017-04-05.
 */
public class UnsignedXadesParser {

    public static String NAMESPACE = "http://uri.etsi.org/01903/v1.3.2#";

    public static final String XADES_V132_XSD_SCHEMA_RESOURCE_LOCATION = "/XAdESv132.xsd";


    /**
     * Method to parse an unsigned Xades Structure.
     *
     * @param message unsigned xades message data to parse
     * @return parsed Xades structure.
     * @throws MessageContentException if message data was invalid.
     * @throws MessageProcessingException if internal problems occurred generated the message.
     */
    public Object parseUnsignedMessage(byte[] message) throws MessageContentException, MessageProcessingException{
        try {
            Object object = getUnmarshaller().unmarshal(new ByteArrayInputStream(message));
            if (object instanceof JAXBElement) {
                return ((JAXBElement<?>) object).getValue();
            }
            return object;
        }catch(SAXException e){
            throw new MessageContentException("Error occurred during SAML unmarshaller: " + e.getMessage(),e);
        }catch(JAXBException e){
            throw new MessageContentException("Error occurred during SAML unmarshaller: " + e.getMessage(),e);
        }
    }

    /**
     * Method to marshall a XADES Jaxb object to byte[]
     *
     * @param object the object to marsall
     * @return byte array encoded xml version.
     * @throws MessageContentException if parameter was invalid
     * @throws MessageProcessingException if internal problems occurred marshalling the message.
     */
    public byte[] marshallUnsignedMessage(Object object) throws MessageContentException, MessageProcessingException{
        try{
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            getMarshaller().marshal(object, baos);
            return baos.toByteArray();
        }catch(Exception e){
            throw new MessageProcessingException("Error occurred marshalling object: " + e.getMessage(),e );
        }
    }

    protected Marshaller getMarshaller() throws JAXBException{
        Marshaller marshaller = getJAXBContext().createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
        return marshaller;
    }

    protected Unmarshaller getUnmarshaller() throws JAXBException, SAXException{
        Unmarshaller unmarshaller = getJAXBContext().createUnmarshaller();
        unmarshaller.setSchema(getSchema());
        return unmarshaller;
    }


    private JAXBContext jaxbContext = null;
    /**
     * Help method maintaining the JAXB Context.
     */
    protected JAXBContext getJAXBContext() throws JAXBException{
        if(jaxbContext== null){
            jaxbContext = JAXBContext.newInstance("se.signatureservice.messages.xades.v132.jaxb:se.signatureservice.messages.xmldsig.jaxb");

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

        schemaFactory.setResourceResolver(new UnsignedXadesParserLSResourceResolver());

        Source[] sources = new Source[2];
        sources[0] = new StreamSource(getClass().getResourceAsStream(DefaultCSMessageParser.XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION));
        sources[1] = new StreamSource(getClass().getResourceAsStream(XADES_V132_XSD_SCHEMA_RESOURCE_LOCATION));

        return schemaFactory.newSchema(sources);
    }

    public class UnsignedXadesParserLSResourceResolver implements LSResourceResolver {

        public LSInput resolveResource(String type, String namespaceURI,
                                       String publicId, String systemId, String baseURI) {
            try {
                if(systemId != null && systemId.equals("datatypes.dtd")){
                    return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream("/datatypes.dtd"));
                }
                if(systemId != null && systemId.equals("http://www.w3.org/2001/XMLSchema.dtd")){
                    return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream("/XMLSchema.dtd"));
                }
                if(namespaceURI != null){
                    if(namespaceURI.equals(DefaultCSMessageParser.XMLDSIG_NAMESPACE)){
                        return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream(DefaultCSMessageParser.XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION));
                    }
                    if(namespaceURI.equals(NAMESPACE)){
                        return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream(XADES_V132_XSD_SCHEMA_RESOURCE_LOCATION));
                    }
                }
            } catch (MessageProcessingException e) {
                throw new IllegalStateException("Error couldn't read XSD from class path: " + e.getMessage(), e);
            }
            return null;
        }
    }
}
