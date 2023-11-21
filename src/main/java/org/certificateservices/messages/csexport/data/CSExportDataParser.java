/************************************************************************
*                                                                       *
*  Certificate Service - Messages                                       *
*                                                                       *
*  This software is free software; you can redistribute it and/or       *
*  modify it under the terms of the GNU Lesser General Public License   *
*  License as published by the Free Software Foundation; either         *
*  version 3   of the License, or any later version.                    *
*                                                                       *
*  See terms of license at gnu.org.                                     *
*                                                                       *
*************************************************************************/
package org.certificateservices.messages.csexport.data;

import org.certificateservices.messages.ContextMessageSecurityProvider;
import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.MessageSecurityProvider;
import org.certificateservices.messages.csexport.data.jaxb.CSExport;
import org.certificateservices.messages.csexport.data.jaxb.ObjectFactory;
import org.certificateservices.messages.csexport.data.jaxb.Organisation;
import org.certificateservices.messages.csexport.data.jaxb.TokenType;
import org.certificateservices.messages.csmessages.DefaultCSMessageParser;
import org.certificateservices.messages.csmessages.XSDLSInput;
import org.certificateservices.messages.utils.DefaultSystemTime;
import org.certificateservices.messages.utils.MessageGenerateUtils;
import org.certificateservices.messages.utils.SystemTime;
import org.certificateservices.messages.utils.XMLSigner;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Class to generate and parse Hard Token Data Structures.
 * <b>
 * It has also methods to create encrypted binary data defined in
 * the credential managment protocol 2.0 specification.
 * 
 * @author Philip Vendil
 *
 */
public class CSExportDataParser {

	public static String NAMESPACE = "http://certificateservices.org/xsd/csexport_data_1_0";

	public static String DEFAULT_VERSION = "1.4";
	public static String VERSION_1_0 = "1.0";
	public static String VERSION_1_1 = "1.1";
	public static String VERSION_1_2 = "1.2";
	public static String VERSION_1_3 = "1.3";
	public static String VERSION_1_4 = "1.4";

	private static final String CSEXPORT_XSD_SCHEMA_RESOURCE_LOCATION_1_0 = "/cs-export-data_1_0.xsd";
	private static final String CSEXPORT_XSD_SCHEMA_RESOURCE_LOCATION_1_1 = "/cs-export-data_1_1.xsd";
	private static final String CSEXPORT_XSD_SCHEMA_RESOURCE_LOCATION_1_2 = "/cs-export-data_1_2.xsd";
	private static final String CSEXPORT_XSD_SCHEMA_RESOURCE_LOCATION_1_3 = "/cs-export-data_1_3.xsd";
	private static final String CSEXPORT_XSD_SCHEMA_RESOURCE_LOCATION_1_4 = "/cs-export-data_1_4.xsd";

	private static final Map<String, String> versionToSchemaMap;
	static{
		versionToSchemaMap = new HashMap<String,String>();
		versionToSchemaMap.put(VERSION_1_0, CSEXPORT_XSD_SCHEMA_RESOURCE_LOCATION_1_0);
		versionToSchemaMap.put(VERSION_1_1, CSEXPORT_XSD_SCHEMA_RESOURCE_LOCATION_1_1);
		versionToSchemaMap.put(VERSION_1_2, CSEXPORT_XSD_SCHEMA_RESOURCE_LOCATION_1_2);
		versionToSchemaMap.put(VERSION_1_3, CSEXPORT_XSD_SCHEMA_RESOURCE_LOCATION_1_3);
		versionToSchemaMap.put(VERSION_1_4, CSEXPORT_XSD_SCHEMA_RESOURCE_LOCATION_1_4);
	}

	private ObjectFactory of = new ObjectFactory();

	private XMLSigner xmlSigner;

	private SystemTime systemTime = new DefaultSystemTime();

	private CSExportDataSignatureLocationFinder csExportDataSignatureLocationFinder = new CSExportDataSignatureLocationFinder();

	private boolean requireSignature = false;

	/**
	 * Constructor for CSExportDataParser, this is the default method to create a parser, it should
	 * not be fetched by the PayloadParserRegistry since this is not a CSMessagePayload.
	 *
	 * @param securityProvider the security provider to use for encrypting and decrypting messages.
	 * @param requireSignature if signatures should be expected and verified in export data.
	 * @throws MessageProcessingException if internal problems occurred initializing the parser.
	 */
	public CSExportDataParser(MessageSecurityProvider securityProvider,boolean requireSignature) throws MessageProcessingException{
		this.requireSignature = requireSignature;
		try {
			xmlSigner = new XMLSigner(securityProvider, true, new CSExportDataSignatureLocationFinder(), null);
		} catch (Exception e) {
			throw new MessageProcessingException("Error initializing HardTokenDataParser: " + e.getMessage(),e);
		}
	}

	/**
	 * Method to parse a CSExport.
	 * 
	 * @param data a serialized hard token data XML structure.
	 * @return a unmarshalled HardTokenData.
	 * @throws MessageContentException if xml data was invalid
	 * @throws MessageProcessingException if internal problems occurred unmarshalling the data.
	 */
	public CSExport parse(byte[] data) throws MessageContentException, MessageProcessingException{
		Document doc;
		try {
			doc = getDocumentBuilder().parse(new ByteArrayInputStream(data));

			String version = doc.getDocumentElement().getAttribute("version");
			if(version == null || versionToSchemaMap.get(version) == null){
				throw new MessageContentException("Invalid CSExport XML, bad version attribute found");
			}

			Object retval = getUnmarshaller(version).unmarshal(doc);
			validateCSExportData(retval,doc);

			return (CSExport)  retval;
		} catch (SAXException e) {
			throw new MessageContentException("Message content error when parsing cs export data: " + e.getMessage(), e);
		} catch (IOException e) {
			throw new MessageContentException("Message content error when parsing cs export data: " + e.getMessage(), e);
		}catch (JAXBException e) {
			throw new MessageContentException("Message content error when parsing cs export data: " + e.getMessage(), e);
		} catch (ParserConfigurationException e) {
			throw new MessageProcessingException("Internal error when parsing cs export data: " + e.getMessage(), e);
		} 
	}

	/**
	 * Method that validates the fields of the cs export data that isn't already validated by the schema
	 * and the digital signature of the message.
	 *
	 * @param object the message to validate.
	 * @param doc the document of the message data.
	 * @throws MessageContentException if the message contained bad format.
	 * @throws MessageProcessingException if internal problems occurred validating the message.
	 */
	private void validateCSExportData(Object object, Document doc) throws MessageContentException, MessageProcessingException {

		if(!(object instanceof CSExport)){
			throw new MessageContentException("Error: parsed object not a CS Export data.");
		}

		validateSignature(doc);
	}

	/**
	 * Help method to verify a message signature.
	 */
	private void validateSignature(Document doc) throws MessageContentException, MessageProcessingException {
		if(requireSignature){
			xmlSigner.verifyEnvelopedSignature(doc, false);
		}
	}


	/**
	 * Method to create a signed CSExport data structure returned as CSExport JAXB object.
	 * <p>
	 * This method isn't very efficient, and should be used for high performance processing.
	 * <p>
	 * All parameters must be set.
	 *
	 * @param version the export data schema version to use.
	 * @param organisations the list of organisations to include in export
	 * @param tokenTypes the list of token types to include in export
	 * @return a newly generated cs export data.
	 * @throws MessageProcessingException if internal errors occurred processing the message.
	 * @throws MessageContentException if parameter contained data that didn't fullfill schema.
	 */
	public CSExport genCSExport_1_xAsObject(String version, List<Organisation> organisations, List<TokenType> tokenTypes) throws MessageProcessingException, MessageContentException {
		return parse(genCSExport_1_x(version, organisations,tokenTypes));
	}

	/**
	 * Method to create a signed CSExport data structure returned as byte[].
	 * <p>
	 * All parameters must be set.
	 *
	 * @param version the export data schema version to use.
	 * @param organisations the list of organisations to include in export
	 * @param tokenTypes the list of token types to include in export
	 * @return a newly generated cs export data.
	 * @throws MessageProcessingException if internal errors occurred processing the message.
	 * @throws MessageContentException if parameter contained data that didn't fullfill schema.
	 */
	public byte[] genCSExport_1_x(String version, List<Organisation> organisations, List<TokenType> tokenTypes) throws MessageProcessingException, MessageContentException {
		CSExport csexp = of.createCSExport();
		csexp.setVersion(version);
		csexp.setID(MessageGenerateUtils.generateRandomUUID());
		csexp.setTimeStamp(MessageGenerateUtils.dateToXMLGregorianCalendar(systemTime.getSystemTime()));

		if(organisations != null && organisations.size() > 0) {
			CSExport.Organisations orgs = of.createCSExportOrganisations();
			orgs.getOrganisation().addAll(organisations);
			csexp.setOrganisations(orgs);
		}
		if(tokenTypes != null && tokenTypes.size() > 0) {
			CSExport.TokenTypes tts = of.createCSExportTokenTypes();
			tts.getTokenType().addAll(tokenTypes);
			csexp.setTokenTypes(tts);
		}

		return marshallAndSign(csexp);
	}
	/**
	 * Method to marshall an CSExport method to an byte array. This method doesn't do any signing only
	 * converts from JAXB to byte[]
	 *
	 * @param csExport the CSExport object to convert, never null
	 * @return byte array representation of the object.
	 * @throws MessageContentException
     */
	public byte[] marshallCSExportData(CSExport csExport) throws MessageContentException{
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			getMarshaller().marshal(csExport, baos);
			return baos.toByteArray();
		}catch(JAXBException e){
			throw new MessageContentException("Error marshalling CSExport Data to byte array: " + e.getMessage(),e);
		}
	}


	/**
	 * Help method to marshall and sign an CSExport
	 *
	 * Method that generates the signature and marshalls the message to byte array in UTF-8 format.
	 * @param csExport a CS Export structure.
	 * @return a marshalled and signed message.
	 * @throws MessageProcessingException if problems occurred when processing the message.
	 * @throws MessageContentException if unsupported version is detected in message.
	 */
	private byte[] marshallAndSign(CSExport csExport) throws MessageProcessingException, MessageContentException{
		if(csExport == null){
			throw new MessageProcessingException("Error marshalling cs export data, message cannot be null.");
		}

		try {
			Document doc = getDocumentBuilder().newDocument();
			getMarshaller().marshal(csExport, doc);
			return xmlSigner.marshallAndSign(ContextMessageSecurityProvider.DEFAULT_CONTEXT,doc, csExportDataSignatureLocationFinder);
		} catch (JAXBException e) {
			throw new MessageProcessingException("Error marshalling message " + e.getMessage(), e);
		} catch (ParserConfigurationException e) {
			throw new MessageProcessingException("Error generating document builder " + e.getMessage(), e);
		}
	}

	private DocumentBuilder getDocumentBuilder() throws ParserConfigurationException {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);

		return dbf.newDocumentBuilder();
	}

	/**
	 * Help method to get marshaller for a given version. Marshaller are
	 * NOT thread safe and should be created for each operation.
	 *
	 * @return Marshaller for given version
	 * @throws JAXBException If error related to JAXB context
	 */
	Marshaller getMarshaller() throws JAXBException{
		Marshaller marshaller = getJAXBContext().createMarshaller();
		marshaller.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
		return marshaller;
	}

	/**
	 * Help method to get unmarshaller for a given version. Unmarshaller are
	 * NOT thread safe and should be created for each operation.
	 *
	 * @param version Schema version to get unmarshaller for
	 * @return Unmarshaller for given version
	 * @throws JAXBException If error related to JAXB context
	 * @throws SAXException If error related to schema
	 */
	Unmarshaller getUnmarshaller(String version) throws JAXBException, SAXException{
		Unmarshaller retval = getJAXBContext().createUnmarshaller();
		retval.setSchema(getSchema(version));
		return retval;
	}

	private JAXBContext jaxbContext = null;

	/**
	 * Help method to get the Assertion JAXB Context. JAXB Context is thread safe
	 * and is cached and can be shared across threads for improved performance.
	 *
	 * @return JAXBContext to use when marshalling/unmarshalling CS Export Data
	 * @throws JAXBException If JAXBContext could not be created
	 */
    private JAXBContext getJAXBContext() throws JAXBException{
    	if(jaxbContext== null){
    		String jaxbClassPath = "org.certificateservices.messages.csexport.data.jaxb:org.certificateservices.messages.xmldsig.jaxb";
    		jaxbContext = JAXBContext.newInstance(jaxbClassPath);
    	}
    	return jaxbContext;
    }

	private Map<String,Schema> schemas = new HashMap<String,Schema>();

	/**
	 * Help method to get the validation schema instance. Schema is thread safe
	 * and is cached and can be shared across threads for improved performance.
	 *
	 * @param version Version if schema to get.
	 * @return Schema instance for given version.
	 * @throws SAXException If schema could not be created for given version.
	 */
    private Schema getSchema(String version) throws SAXException{
		Schema retval = schemas.get(version);
		if(retval == null) {
			SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
			schemaFactory.setResourceResolver(new CSExportLSResourceResolver(version));

			Source[] sources = new Source[2];
			sources[0] = new StreamSource(getClass().getResourceAsStream(DefaultCSMessageParser.XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION));
			sources[1] = new StreamSource(getClass().getResourceAsStream(versionToSchemaMap.get(version)));

			retval = schemaFactory.newSchema(sources);
			schemas.put(version, retval);
		}
        
        return retval;
    }

    
    public class CSExportLSResourceResolver implements  LSResourceResolver {

		private String version;

		public CSExportLSResourceResolver(String version){
			this.version = version;
		}

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
					if(namespaceURI.equals(DefaultCSMessageParser.XMLDSIG_NAMESPACE)){
						return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream(DefaultCSMessageParser.XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION));
					}
					if(namespaceURI.equals(NAMESPACE)){
						return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream(versionToSchemaMap.get(version)));
					}
				}
			} catch (MessageProcessingException e) {
				throw new IllegalStateException("Error couldn't read XSD from class path: " + e.getMessage(), e);
			}
			return null;
		}
	}

	public class CSExportDataSignatureLocationFinder implements XMLSigner.SignatureLocationFinder {

		@Override
		public Element[] getSignatureLocations(Document doc) throws MessageContentException {
			try{
				if(doc.getDocumentElement().getLocalName().equals("CSExport") && doc.getDocumentElement().getNamespaceURI().equals(NAMESPACE)){
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
			return null;
		}

	}
}
