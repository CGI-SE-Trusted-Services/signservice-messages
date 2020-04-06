package org.certificateservices.messages.saml2;

/**
 * Interface for extending the XML schemas and namespaces used when parsing and generating SAML XML.
 *
 * Created by philip on 07/01/17.
 */
public interface SAMLParserCustomisations {

    /**
     *
     * @return a ":" separated JAXB classpath for all custom schemas that should be marshalled using JAXB.
     */
    String getCustomJAXBClasspath();

    /**
     *
     * @return the resource as stream path to related custom schema XSD
     */
    String[] getCustomSchemaLocations();

    /**
     * Method to find Schema for a specific customized element related to the custom schema locations.
     *
     * @param type The type of the resource being resolved. For XML [XML 1.0] resources (i.e. entities),
     *             applications must use the value "http://www.w3.org/TR/REC-xml". For XML Schema [XML Schema Part 1],
     *             applications must use the value "http://www.w3.org/2001/XMLSchema". Other types of resources are
     *             outside the scope of this specification and therefore should recommend an absolute URI in order
     *             to use this method.
     * @param namespaceURI The namespace of the resource being resolved, e.g. the target namespace of the XML Schema
     *                     [XML Schema Part 1] when resolving XML Schema resources.
     * @param publicId The public identifier of the external entity being referenced, or null if no public identifier
     *                 was supplied or if the resource is not an entity.
     * @param systemId The system identifier, a URI reference [IETF RFC 2396], of the external resource being
     *                 referenced, or null if no system identifier was supplied.
     * @param baseURI The absolute base URI of the resource being parsed, or null if there is no base URI.
     * @return the resource as stream path to related schema XSD, or null if no matching found.
     */
    String lookupSchemaForElement(String type, String namespaceURI,
                                  String publicId, String systemId, String baseURI);
}
