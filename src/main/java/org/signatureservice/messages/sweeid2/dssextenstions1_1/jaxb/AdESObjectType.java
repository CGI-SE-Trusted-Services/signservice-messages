//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2025.02.26 at 09:40:10 AM CET 
//


package org.signatureservice.messages.sweeid2.dssextenstions1_1.jaxb;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlType;


/**
 * <p>Java class for AdESObjectType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="AdESObjectType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="SignatureId" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="AdESObjectBytes" type="{http://www.w3.org/2001/XMLSchema}base64Binary" minOccurs="0"/>
 *         &lt;element name="OtherAdESData" type="{http://id.elegnamnden.se/csig/1.1/dss-ext/ns}AnyType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "AdESObjectType", propOrder = {
    "signatureId",
    "adESObjectBytes",
    "otherAdESData"
})
public class AdESObjectType {

    @XmlElement(name = "SignatureId")
    protected String signatureId;
    @XmlElement(name = "AdESObjectBytes")
    protected byte[] adESObjectBytes;
    @XmlElement(name = "OtherAdESData")
    protected AnyType otherAdESData;

    /**
     * Gets the value of the signatureId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSignatureId() {
        return signatureId;
    }

    /**
     * Sets the value of the signatureId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSignatureId(String value) {
        this.signatureId = value;
    }

    /**
     * Gets the value of the adESObjectBytes property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getAdESObjectBytes() {
        return adESObjectBytes;
    }

    /**
     * Sets the value of the adESObjectBytes property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setAdESObjectBytes(byte[] value) {
        this.adESObjectBytes = value;
    }

    /**
     * Gets the value of the otherAdESData property.
     * 
     * @return
     *     possible object is
     *     {@link AnyType }
     *     
     */
    public AnyType getOtherAdESData() {
        return otherAdESData;
    }

    /**
     * Sets the value of the otherAdESData property.
     * 
     * @param value
     *     allowed object is
     *     {@link AnyType }
     *     
     */
    public void setOtherAdESData(AnyType value) {
        this.otherAdESData = value;
    }

}
