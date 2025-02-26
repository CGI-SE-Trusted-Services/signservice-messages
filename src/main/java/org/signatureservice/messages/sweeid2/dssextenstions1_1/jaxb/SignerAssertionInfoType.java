//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2025.02.26 at 09:40:10 AM CET 
//


package org.signatureservice.messages.sweeid2.dssextenstions1_1.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import org.signatureservice.messages.saml2.assertion.jaxb.AttributeStatementType;


/**
 * <p>Java class for SignerAssertionInfoType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="SignerAssertionInfoType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{http://id.elegnamnden.se/csig/1.1/dss-ext/ns}ContextInfo"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement"/>
 *         &lt;element ref="{http://id.elegnamnden.se/csig/1.1/dss-ext/ns}SamlAssertions" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "SignerAssertionInfoType", propOrder = {
    "contextInfo",
    "attributeStatement",
    "samlAssertions"
})
public class SignerAssertionInfoType {

    @XmlElement(name = "ContextInfo", required = true)
    protected ContextInfoType contextInfo;
    @XmlElement(name = "AttributeStatement", namespace = "urn:oasis:names:tc:SAML:2.0:assertion", required = true)
    protected AttributeStatementType attributeStatement;
    @XmlElement(name = "SamlAssertions")
    protected SAMLAssertionsType samlAssertions;

    /**
     * Gets the value of the contextInfo property.
     * 
     * @return
     *     possible object is
     *     {@link ContextInfoType }
     *     
     */
    public ContextInfoType getContextInfo() {
        return contextInfo;
    }

    /**
     * Sets the value of the contextInfo property.
     * 
     * @param value
     *     allowed object is
     *     {@link ContextInfoType }
     *     
     */
    public void setContextInfo(ContextInfoType value) {
        this.contextInfo = value;
    }

    /**
     * Gets the value of the attributeStatement property.
     * 
     * @return
     *     possible object is
     *     {@link AttributeStatementType }
     *     
     */
    public AttributeStatementType getAttributeStatement() {
        return attributeStatement;
    }

    /**
     * Sets the value of the attributeStatement property.
     * 
     * @param value
     *     allowed object is
     *     {@link AttributeStatementType }
     *     
     */
    public void setAttributeStatement(AttributeStatementType value) {
        this.attributeStatement = value;
    }

    /**
     * Gets the value of the samlAssertions property.
     * 
     * @return
     *     possible object is
     *     {@link SAMLAssertionsType }
     *     
     */
    public SAMLAssertionsType getSamlAssertions() {
        return samlAssertions;
    }

    /**
     * Sets the value of the samlAssertions property.
     * 
     * @param value
     *     allowed object is
     *     {@link SAMLAssertionsType }
     *     
     */
    public void setSamlAssertions(SAMLAssertionsType value) {
        this.samlAssertions = value;
    }

}
