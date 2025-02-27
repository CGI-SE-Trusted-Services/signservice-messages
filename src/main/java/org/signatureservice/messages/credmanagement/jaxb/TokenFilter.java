//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2019.04.03 at 10:28:03 AM CEST 
//


package org.signatureservice.messages.credmanagement.jaxb;

import java.util.ArrayList;
import java.util.List;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlType;


/**
 * <p>Java class for TokenFilter complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="TokenFilter">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;choice>
 *         &lt;element name="tokenTypes" minOccurs="0">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="tokenType" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring" maxOccurs="unbounded" minOccurs="0"/>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *         &lt;element name="tokenSerialNumbers" minOccurs="0">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="serialNumber" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring" maxOccurs="unbounded" minOccurs="0"/>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *       &lt;/choice>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "TokenFilter", propOrder = {
    "tokenTypes",
    "tokenSerialNumbers"
})
public class TokenFilter {

    protected TokenFilter.TokenTypes tokenTypes;
    protected TokenFilter.TokenSerialNumbers tokenSerialNumbers;

    /**
     * Gets the value of the tokenTypes property.
     * 
     * @return
     *     possible object is
     *     {@link TokenFilter.TokenTypes }
     *     
     */
    public TokenFilter.TokenTypes getTokenTypes() {
        return tokenTypes;
    }

    /**
     * Sets the value of the tokenTypes property.
     * 
     * @param value
     *     allowed object is
     *     {@link TokenFilter.TokenTypes }
     *     
     */
    public void setTokenTypes(TokenFilter.TokenTypes value) {
        this.tokenTypes = value;
    }

    /**
     * Gets the value of the tokenSerialNumbers property.
     * 
     * @return
     *     possible object is
     *     {@link TokenFilter.TokenSerialNumbers }
     *     
     */
    public TokenFilter.TokenSerialNumbers getTokenSerialNumbers() {
        return tokenSerialNumbers;
    }

    /**
     * Sets the value of the tokenSerialNumbers property.
     * 
     * @param value
     *     allowed object is
     *     {@link TokenFilter.TokenSerialNumbers }
     *     
     */
    public void setTokenSerialNumbers(TokenFilter.TokenSerialNumbers value) {
        this.tokenSerialNumbers = value;
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
     *         &lt;element name="serialNumber" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring" maxOccurs="unbounded" minOccurs="0"/>
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
        "serialNumber"
    })
    public static class TokenSerialNumbers {

        protected List<String> serialNumber;

        /**
         * Gets the value of the serialNumber property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the serialNumber property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getSerialNumber().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link String }
         * 
         * 
         */
        public List<String> getSerialNumber() {
            if (serialNumber == null) {
                serialNumber = new ArrayList<String>();
            }
            return this.serialNumber;
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
     *         &lt;element name="tokenType" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring" maxOccurs="unbounded" minOccurs="0"/>
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
        "tokenType"
    })
    public static class TokenTypes {

        protected List<String> tokenType;

        /**
         * Gets the value of the tokenType property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the tokenType property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getTokenType().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link String }
         * 
         * 
         */
        public List<String> getTokenType() {
            if (tokenType == null) {
                tokenType = new ArrayList<String>();
            }
            return this.tokenType;
        }

    }

}
