//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2018.02.15 at 10:07:17 AM CET 
//


package se.signatureservice.messages.csmessages.jaxb;

import java.util.ArrayList;
import java.util.List;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlSchemaType;
import jakarta.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;


/**
 * <p>Java class for CredentialRequest complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CredentialRequest">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="credentialRequestId" type="{http://www.w3.org/2001/XMLSchema}int"/>
 *         &lt;element name="credentialType" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring"/>
 *         &lt;element name="credentialSubType" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring"/>
 *         &lt;element name="x509RequestType" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring"/>
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
 *         &lt;element name="credentialRequestData" type="{http://www.w3.org/2001/XMLSchema}base64Binary"/>
 *         &lt;element name="description" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="requestedExpireDate" type="{http://www.w3.org/2001/XMLSchema}dateTime" minOccurs="0"/>
 *         &lt;element name="requestedValidFromDate" type="{http://www.w3.org/2001/XMLSchema}dateTime" minOccurs="0"/>
 *         &lt;element name="includeIssuerCredentials" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CredentialRequest", propOrder = {
    "credentialRequestId",
    "credentialType",
    "credentialSubType",
    "x509RequestType",
    "attributes",
    "credentialRequestData",
    "description",
    "requestedExpireDate",
    "requestedValidFromDate",
    "includeIssuerCredentials"
})
public class CredentialRequest {

    protected int credentialRequestId;
    @XmlElement(required = true)
    protected String credentialType;
    @XmlElement(required = true)
    protected String credentialSubType;
    @XmlElement(required = true)
    protected String x509RequestType;
    protected CredentialRequest.Attributes attributes;
    @XmlElement(required = true)
    protected byte[] credentialRequestData;
    protected String description;
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar requestedExpireDate;
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar requestedValidFromDate;
    @XmlElement(defaultValue = "false")
    protected Boolean includeIssuerCredentials;

    /**
     * Gets the value of the credentialRequestId property.
     * 
     */
    public int getCredentialRequestId() {
        return credentialRequestId;
    }

    /**
     * Sets the value of the credentialRequestId property.
     * 
     */
    public void setCredentialRequestId(int value) {
        this.credentialRequestId = value;
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
     * Gets the value of the x509RequestType property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getX509RequestType() {
        return x509RequestType;
    }

    /**
     * Sets the value of the x509RequestType property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setX509RequestType(String value) {
        this.x509RequestType = value;
    }

    /**
     * Gets the value of the attributes property.
     * 
     * @return
     *     possible object is
     *     {@link CredentialRequest.Attributes }
     *     
     */
    public CredentialRequest.Attributes getAttributes() {
        return attributes;
    }

    /**
     * Sets the value of the attributes property.
     * 
     * @param value
     *     allowed object is
     *     {@link CredentialRequest.Attributes }
     *     
     */
    public void setAttributes(CredentialRequest.Attributes value) {
        this.attributes = value;
    }

    /**
     * Gets the value of the credentialRequestData property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getCredentialRequestData() {
        return credentialRequestData;
    }

    /**
     * Sets the value of the credentialRequestData property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setCredentialRequestData(byte[] value) {
        this.credentialRequestData = value;
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
     * Gets the value of the requestedExpireDate property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getRequestedExpireDate() {
        return requestedExpireDate;
    }

    /**
     * Sets the value of the requestedExpireDate property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setRequestedExpireDate(XMLGregorianCalendar value) {
        this.requestedExpireDate = value;
    }

    /**
     * Gets the value of the requestedValidFromDate property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getRequestedValidFromDate() {
        return requestedValidFromDate;
    }

    /**
     * Sets the value of the requestedValidFromDate property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setRequestedValidFromDate(XMLGregorianCalendar value) {
        this.requestedValidFromDate = value;
    }

    /**
     * Gets the value of the includeIssuerCredentials property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isIncludeIssuerCredentials() {
        return includeIssuerCredentials;
    }

    /**
     * Sets the value of the includeIssuerCredentials property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setIncludeIssuerCredentials(Boolean value) {
        this.includeIssuerCredentials = value;
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

}
