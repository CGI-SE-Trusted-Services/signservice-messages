//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2017.03.02 at 02:49:19 PM CET 
//


package org.signatureservice.messages.credmanagement.jaxb;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlType;
import org.signatureservice.messages.csmessages.jaxb.CSRequest;
import org.signatureservice.messages.csmessages.jaxb.Credential;


/**
 * <p>Java class for FetchHardTokenDataRequest complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="FetchHardTokenDataRequest">
 *   &lt;complexContent>
 *     &lt;extension base="{http://certificateservices.org/xsd/csmessages2_0}CSRequest">
 *       &lt;sequence>
 *         &lt;element name="tokenSerial" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring"/>
 *         &lt;element name="relatedCredentialIssuerId" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="adminCredential" type="{http://certificateservices.org/xsd/csmessages2_0}Credential"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "FetchHardTokenDataRequest", propOrder = {
    "tokenSerial",
    "relatedCredentialIssuerId",
    "adminCredential"
})
public class FetchHardTokenDataRequest
    extends CSRequest
{

    @XmlElement(required = true)
    protected String tokenSerial;
    @XmlElement(required = true)
    protected String relatedCredentialIssuerId;
    @XmlElement(required = true)
    protected Credential adminCredential;

    /**
     * Gets the value of the tokenSerial property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getTokenSerial() {
        return tokenSerial;
    }

    /**
     * Sets the value of the tokenSerial property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setTokenSerial(String value) {
        this.tokenSerial = value;
    }

    /**
     * Gets the value of the relatedCredentialIssuerId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getRelatedCredentialIssuerId() {
        return relatedCredentialIssuerId;
    }

    /**
     * Sets the value of the relatedCredentialIssuerId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setRelatedCredentialIssuerId(String value) {
        this.relatedCredentialIssuerId = value;
    }

    /**
     * Gets the value of the adminCredential property.
     * 
     * @return
     *     possible object is
     *     {@link Credential }
     *     
     */
    public Credential getAdminCredential() {
        return adminCredential;
    }

    /**
     * Sets the value of the adminCredential property.
     * 
     * @param value
     *     allowed object is
     *     {@link Credential }
     *     
     */
    public void setAdminCredential(Credential value) {
        this.adminCredential = value;
    }

}
