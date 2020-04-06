//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2015.05.21 at 02:30:00 PM CEST 
//


package org.certificateservices.messages.csmessages.jaxb;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;


/**
 * <p>Java class for Credential complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="Credential">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="credentialRequestId" type="{http://www.w3.org/2001/XMLSchema}int" minOccurs="0"/>
 *         &lt;element name="uniqueId" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring"/>
 *         &lt;element name="displayName" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring"/>
 *         &lt;element name="serialNumber" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring"/>
 *         &lt;element name="issuerId" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="status" type="{http://www.w3.org/2001/XMLSchema}int"/>
 *         &lt;element name="credentialType" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring"/>
 *         &lt;element name="credentialSubType" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring"/>
 *         &lt;element name="attributes" minOccurs="0">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="attribute" type="{http://certificateservices.org/xsd/csmessages2_0}Attribute" maxOccurs="unbounded" minOccurs="0"/>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *         &lt;element name="usages" minOccurs="0">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="usage" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring" maxOccurs="unbounded" minOccurs="0"/>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *         &lt;element name="credentialData" type="{http://www.w3.org/2001/XMLSchema}base64Binary"/>
 *         &lt;element name="description" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="issueDate" type="{http://www.w3.org/2001/XMLSchema}dateTime"/>
 *         &lt;element name="expireDate" type="{http://www.w3.org/2001/XMLSchema}dateTime"/>
 *         &lt;element name="validFromDate" type="{http://www.w3.org/2001/XMLSchema}dateTime"/>
 *         &lt;element name="revocationDate" type="{http://www.w3.org/2001/XMLSchema}dateTime" minOccurs="0"/>
 *         &lt;element name="revocationInformation" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="issuerCredential" type="{http://certificateservices.org/xsd/csmessages2_0}Credential" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "Credential", namespace = "http://certificateservices.org/xsd/csmessages2_0", propOrder = {
    "credentialRequestId",
    "uniqueId",
    "displayName",
    "serialNumber",
    "issuerId",
    "status",
    "credentialType",
    "credentialSubType",
    "attributes",
    "usages",
    "credentialData",
    "description",
    "issueDate",
    "expireDate",
    "validFromDate",
    "revocationDate",
    "revocationInformation",
    "issuerCredential"
})
public class Credential {

    protected Integer credentialRequestId;
    @XmlElement(required = true)
    protected String uniqueId;
    @XmlElement(required = true)
    protected String displayName;
    @XmlElement(required = true)
    protected String serialNumber;
    @XmlElement(required = true)
    protected String issuerId;
    protected int status;
    @XmlElement(required = true)
    protected String credentialType;
    @XmlElement(required = true)
    protected String credentialSubType;
    protected Credential.Attributes attributes;
    protected Credential.Usages usages;
    @XmlElement(required = true)
    protected byte[] credentialData;
    protected String description;
    @XmlElement(required = true)
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar issueDate;
    @XmlElement(required = true)
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar expireDate;
    @XmlElement(required = true)
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar validFromDate;
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar revocationDate;
    protected String revocationInformation;
    protected Credential issuerCredential;

    /**
     * Gets the value of the credentialRequestId property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getCredentialRequestId() {
        return credentialRequestId;
    }

    /**
     * Sets the value of the credentialRequestId property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setCredentialRequestId(Integer value) {
        this.credentialRequestId = value;
    }

    /**
     * Gets the value of the uniqueId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getUniqueId() {
        return uniqueId;
    }

    /**
     * Sets the value of the uniqueId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setUniqueId(String value) {
        this.uniqueId = value;
    }

    /**
     * Gets the value of the displayName property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getDisplayName() {
        return displayName;
    }

    /**
     * Sets the value of the displayName property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDisplayName(String value) {
        this.displayName = value;
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
     * Gets the value of the status property.
     * 
     */
    public int getStatus() {
        return status;
    }

    /**
     * Sets the value of the status property.
     * 
     */
    public void setStatus(int value) {
        this.status = value;
    }

    /**
     * Gets the value of the credentialType property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCredentialType() {
        return credentialType;
    }

    /**
     * Sets the value of the credentialType property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCredentialType(String value) {
        this.credentialType = value;
    }

    /**
     * Gets the value of the credentialSubType property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCredentialSubType() {
        return credentialSubType;
    }

    /**
     * Sets the value of the credentialSubType property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCredentialSubType(String value) {
        this.credentialSubType = value;
    }

    /**
     * Gets the value of the attributes property.
     * 
     * @return
     *     possible object is
     *     {@link Credential.Attributes }
     *     
     */
    public Credential.Attributes getAttributes() {
        return attributes;
    }

    /**
     * Sets the value of the attributes property.
     * 
     * @param value
     *     allowed object is
     *     {@link Credential.Attributes }
     *     
     */
    public void setAttributes(Credential.Attributes value) {
        this.attributes = value;
    }

    /**
     * Gets the value of the usages property.
     * 
     * @return
     *     possible object is
     *     {@link Credential.Usages }
     *     
     */
    public Credential.Usages getUsages() {
        return usages;
    }

    /**
     * Sets the value of the usages property.
     * 
     * @param value
     *     allowed object is
     *     {@link Credential.Usages }
     *     
     */
    public void setUsages(Credential.Usages value) {
        this.usages = value;
    }

    /**
     * Gets the value of the credentialData property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getCredentialData() {
        return credentialData;
    }

    /**
     * Sets the value of the credentialData property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setCredentialData(byte[] value) {
        this.credentialData = value;
    }

    /**
     * Gets the value of the description property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getDescription() {
        return description;
    }

    /**
     * Sets the value of the description property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDescription(String value) {
        this.description = value;
    }

    /**
     * Gets the value of the issueDate property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getIssueDate() {
        return issueDate;
    }

    /**
     * Sets the value of the issueDate property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setIssueDate(XMLGregorianCalendar value) {
        this.issueDate = value;
    }

    /**
     * Gets the value of the expireDate property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getExpireDate() {
        return expireDate;
    }

    /**
     * Sets the value of the expireDate property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setExpireDate(XMLGregorianCalendar value) {
        this.expireDate = value;
    }

    /**
     * Gets the value of the validFromDate property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getValidFromDate() {
        return validFromDate;
    }

    /**
     * Sets the value of the validFromDate property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setValidFromDate(XMLGregorianCalendar value) {
        this.validFromDate = value;
    }

    /**
     * Gets the value of the revocationDate property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getRevocationDate() {
        return revocationDate;
    }

    /**
     * Sets the value of the revocationDate property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setRevocationDate(XMLGregorianCalendar value) {
        this.revocationDate = value;
    }

    /**
     * Gets the value of the revocationInformation property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getRevocationInformation() {
        return revocationInformation;
    }

    /**
     * Sets the value of the revocationInformation property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setRevocationInformation(String value) {
        this.revocationInformation = value;
    }

    /**
     * Gets the value of the issuerCredential property.
     * 
     * @return
     *     possible object is
     *     {@link Credential }
     *     
     */
    public Credential getIssuerCredential() {
        return issuerCredential;
    }

    /**
     * Sets the value of the issuerCredential property.
     * 
     * @param value
     *     allowed object is
     *     {@link Credential }
     *     
     */
    public void setIssuerCredential(Credential value) {
        this.issuerCredential = value;
    }


    /**
     * <p>Java class for anonymous complex type.
     * 
     * <p>The following schema fragment specifies the expected content contained within this class.
     * 
     * <pre>
     * &lt;complexType>
     *   &lt;complexContent>
     *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
     *       &lt;sequence>
     *         &lt;element name="attribute" type="{http://certificateservices.org/xsd/csmessages2_0}Attribute" maxOccurs="unbounded" minOccurs="0"/>
     *       &lt;/sequence>
     *     &lt;/restriction>
     *   &lt;/complexContent>
     * &lt;/complexType>
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "attribute"
    })
    public static class Attributes {

        @XmlElement(namespace = "http://certificateservices.org/xsd/csmessages2_0")
        protected List<Attribute> attribute;

        /**
         * Gets the value of the attribute property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the attribute property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getAttribute().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link Attribute }
         * 
         * 
         */
        public List<Attribute> getAttribute() {
            if (attribute == null) {
                attribute = new ArrayList<Attribute>();
            }
            return this.attribute;
        }

    }


    /**
     * <p>Java class for anonymous complex type.
     * 
     * <p>The following schema fragment specifies the expected content contained within this class.
     * 
     * <pre>
     * &lt;complexType>
     *   &lt;complexContent>
     *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
     *       &lt;sequence>
     *         &lt;element name="usage" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring" maxOccurs="unbounded" minOccurs="0"/>
     *       &lt;/sequence>
     *     &lt;/restriction>
     *   &lt;/complexContent>
     * &lt;/complexType>
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "usage"
    })
    public static class Usages {

        @XmlElement(namespace = "http://certificateservices.org/xsd/csmessages2_0")
        protected List<String> usage;

        /**
         * Gets the value of the usage property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the usage property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getUsage().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link String }
         * 
         * 
         */
        public List<String> getUsage() {
            if (usage == null) {
                usage = new ArrayList<String>();
            }
            return this.usage;
        }

    }

}
