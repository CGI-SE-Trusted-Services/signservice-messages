//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2012.09.23 at 02:26:35 PM CEST 
//


package org.signatureservice.messages.pkimessages.jaxb;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlType;


/**
 * <p>Java class for ChangeCredentialStatusRequest complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ChangeCredentialStatusRequest">
 *   &lt;complexContent>
 *     &lt;extension base="{http://certificateservices.org/xsd/pkimessages1_0}PKIRequest">
 *       &lt;sequence>
 *         &lt;element name="issuerId" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="serialNumber" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="newCredentialStatus" type="{http://www.w3.org/2001/XMLSchema}int"/>
 *         &lt;element name="reasonInformation" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ChangeCredentialStatusRequest", propOrder = {
    "issuerId",
    "serialNumber",
    "newCredentialStatus",
    "reasonInformation"
})
public class ChangeCredentialStatusRequest
    extends PKIRequest
{

    @XmlElement(required = true)
    protected String issuerId;
    @XmlElement(required = true)
    protected String serialNumber;
    protected int newCredentialStatus;
    @XmlElement(required = true)
    protected String reasonInformation;

    /**
     * Gets the value of the issuerId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getIssuerId() {
        return issuerId;
    }

    /**
     * Sets the value of the issuerId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setIssuerId(String value) {
        this.issuerId = value;
    }

    /**
     * Gets the value of the serialNumber property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSerialNumber() {
        return serialNumber;
    }

    /**
     * Sets the value of the serialNumber property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSerialNumber(String value) {
        this.serialNumber = value;
    }

    /**
     * Gets the value of the newCredentialStatus property.
     * 
     */
    public int getNewCredentialStatus() {
        return newCredentialStatus;
    }

    /**
     * Sets the value of the newCredentialStatus property.
     * 
     */
    public void setNewCredentialStatus(int value) {
        this.newCredentialStatus = value;
    }

    /**
     * Gets the value of the reasonInformation property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getReasonInformation() {
        return reasonInformation;
    }

    /**
     * Sets the value of the reasonInformation property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setReasonInformation(String value) {
        this.reasonInformation = value;
    }

}
