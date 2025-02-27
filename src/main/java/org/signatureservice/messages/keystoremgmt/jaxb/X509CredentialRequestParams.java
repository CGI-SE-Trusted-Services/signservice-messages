//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2015.06.02 at 10:40:08 AM CEST 
//


package org.signatureservice.messages.keystoremgmt.jaxb;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlType;


/**
 * <p>Java class for X509CredentialRequestParams complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="X509CredentialRequestParams">
 *   &lt;complexContent>
 *     &lt;extension base="{http://certificateservices.org/xsd/keystoremgmt2_0}CredentialRequestParams">
 *       &lt;sequence>
 *         &lt;element name="subjectDN" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "X509CredentialRequestParams", namespace = "http://certificateservices.org/xsd/keystoremgmt2_0", propOrder = {
    "subjectDN"
})
public class X509CredentialRequestParams
    extends CredentialRequestParams
{

    @XmlElement(required = true)
    protected String subjectDN;

    /**
     * Gets the value of the subjectDN property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSubjectDN() {
        return subjectDN;
    }

    /**
     * Sets the value of the subjectDN property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSubjectDN(String value) {
        this.subjectDN = value;
    }

}
