//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2017.10.30 at 02:11:53 PM CET 
//


package org.signatureservice.messages.xades.v132.jaxb;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlType;


/**
 * <p>Java class for CertifiedRoleTypeV2 complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CertifiedRoleTypeV2">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;choice>
 *         &lt;element ref="{http://uri.etsi.org/01903/v1.3.2#}X509AttributeCertificate"/>
 *         &lt;element ref="{http://uri.etsi.org/01903/v1.3.2#}OtherAttributeCertificate"/>
 *       &lt;/choice>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CertifiedRoleTypeV2", propOrder = {
    "x509AttributeCertificate",
    "otherAttributeCertificate"
})
public class CertifiedRoleTypeV2 {

    @XmlElement(name = "X509AttributeCertificate")
    protected EncapsulatedPKIDataType x509AttributeCertificate;
    @XmlElement(name = "OtherAttributeCertificate")
    protected AnyType otherAttributeCertificate;

    /**
     * Gets the value of the x509AttributeCertificate property.
     * 
     * @return
     *     possible object is
     *     {@link EncapsulatedPKIDataType }
     *     
     */
    public EncapsulatedPKIDataType getX509AttributeCertificate() {
        return x509AttributeCertificate;
    }

    /**
     * Sets the value of the x509AttributeCertificate property.
     * 
     * @param value
     *     allowed object is
     *     {@link EncapsulatedPKIDataType }
     *     
     */
    public void setX509AttributeCertificate(EncapsulatedPKIDataType value) {
        this.x509AttributeCertificate = value;
    }

    /**
     * Gets the value of the otherAttributeCertificate property.
     * 
     * @return
     *     possible object is
     *     {@link AnyType }
     *     
     */
    public AnyType getOtherAttributeCertificate() {
        return otherAttributeCertificate;
    }

    /**
     * Sets the value of the otherAttributeCertificate property.
     * 
     * @param value
     *     allowed object is
     *     {@link AnyType }
     *     
     */
    public void setOtherAttributeCertificate(AnyType value) {
        this.otherAttributeCertificate = value;
    }

}
