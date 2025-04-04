//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2017.07.28 at 10:12:09 AM MSK 
//


package se.signatureservice.messages.saml2.metadata.attr.jaxb;

import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.annotation.XmlElementDecl;
import jakarta.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;


/**
 * This object contains factory methods for each 
 * Java content interface and Java element interface 
 * generated in the org.certificateservices.messages.saml2.metadata.attr.jaxb package. 
 * <p>An ObjectFactory allows you to programatically 
 * construct new instances of the Java representation 
 * for XML content. The Java representation of XML 
 * content can consist of schema derived interfaces 
 * and classes representing the binding of schema 
 * type definitions, element declarations and model 
 * groups.  Factory methods for each of these are 
 * provided in this class.
 * 
 */
@XmlRegistry
public class ObjectFactory {


    private final static QName _EntityAttributes_QNAME = new QName("urn:oasis:names:tc:SAML:metadata:attribute", "EntityAttributes");


    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: org.certificateservices.messages.saml2.metadata.attr.jaxb
     * 
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link EntityAttributesType }
     * 
     */
    public EntityAttributesType createEntityAttributesType() {
        return new EntityAttributesType();
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link EntityAttributesType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "urn:oasis:names:tc:SAML:metadata:attribute", name = "EntityAttributes")
    public JAXBElement<EntityAttributesType> createEntityAttributes(EntityAttributesType value) {
        return new JAXBElement<EntityAttributesType>(_EntityAttributes_QNAME, EntityAttributesType.class, null, value);
    }


}
