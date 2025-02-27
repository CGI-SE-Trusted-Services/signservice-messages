//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2020.05.30 at 07:57:06 AM CEST 
//


package org.signatureservice.messages.v2x.registration.jaxb;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlSchemaType;
import jakarta.xml.bind.annotation.XmlSeeAlso;
import jakarta.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;
import org.signatureservice.messages.csmessages.jaxb.CSRequest;


/**
 * <p>Java class for BaseRegisterRequestType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="BaseRegisterRequestType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://certificateservices.org/xsd/csmessages2_0}CSRequest">
 *       &lt;sequence>
 *         &lt;element name="canonicalId" type="{http://certificateservices.org/xsd/v2x_registration_2_0}CanonicalIdType"/>
 *         &lt;element name="ecProfile" type="{http://certificateservices.org/xsd/v2x_registration_2_0}ProfileNameType" minOccurs="0"/>
 *         &lt;element name="atProfile" type="{http://certificateservices.org/xsd/v2x_registration_2_0}ProfileNameType" minOccurs="0"/>
 *         &lt;element name="itssValidFrom" type="{http://www.w3.org/2001/XMLSchema}dateTime" minOccurs="0"/>
 *         &lt;element name="itssValidTo" type="{http://www.w3.org/2001/XMLSchema}dateTime" minOccurs="0"/>
 *         &lt;element name="regions" type="{http://certificateservices.org/xsd/v2x_registration_2_0}RegionsType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "BaseRegisterRequestType", propOrder = {
    "canonicalId",
    "ecProfile",
    "atProfile",
    "itssValidFrom",
    "itssValidTo",
    "regions"
})
@XmlSeeAlso({
    UpdateITSSRequest.class,
    RegisterITSSRequest.class
})
public class BaseRegisterRequestType
    extends CSRequest
{

    @XmlElement(required = true)
    protected String canonicalId;
    protected String ecProfile;
    protected String atProfile;
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar itssValidFrom;
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar itssValidTo;
    protected RegionsType regions;

    /**
     * Gets the value of the canonicalId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCanonicalId() {
        return canonicalId;
    }

    /**
     * Sets the value of the canonicalId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCanonicalId(String value) {
        this.canonicalId = value;
    }

    /**
     * Gets the value of the ecProfile property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getEcProfile() {
        return ecProfile;
    }

    /**
     * Sets the value of the ecProfile property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setEcProfile(String value) {
        this.ecProfile = value;
    }

    /**
     * Gets the value of the atProfile property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getAtProfile() {
        return atProfile;
    }

    /**
     * Sets the value of the atProfile property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setAtProfile(String value) {
        this.atProfile = value;
    }

    /**
     * Gets the value of the itssValidFrom property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getItssValidFrom() {
        return itssValidFrom;
    }

    /**
     * Sets the value of the itssValidFrom property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setItssValidFrom(XMLGregorianCalendar value) {
        this.itssValidFrom = value;
    }

    /**
     * Gets the value of the itssValidTo property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getItssValidTo() {
        return itssValidTo;
    }

    /**
     * Sets the value of the itssValidTo property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setItssValidTo(XMLGregorianCalendar value) {
        this.itssValidTo = value;
    }

    /**
     * Gets the value of the regions property.
     * 
     * @return
     *     possible object is
     *     {@link RegionsType }
     *     
     */
    public RegionsType getRegions() {
        return regions;
    }

    /**
     * Sets the value of the regions property.
     * 
     * @param value
     *     allowed object is
     *     {@link RegionsType }
     *     
     */
    public void setRegions(RegionsType value) {
        this.regions = value;
    }

}
