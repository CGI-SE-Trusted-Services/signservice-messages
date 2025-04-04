//
// This file was generated by the Eclipse Implementation of JAXB, v4.0.5 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
//


package se.signatureservice.messages.sweeid2.dssextenstions1_1.jaxb;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlType;
import se.signatureservice.messages.saml2.assertion.jaxb.AttributeStatementType;


/**
 * <p>Java class for SignerAssertionInfoType complex type</p>.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.</p>
 * 
 * <pre>{@code
 * <complexType name="SignerAssertionInfoType">
 *   <complexContent>
 *     <restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       <sequence>
 *         <element ref="{http://id.elegnamnden.se/csig/1.1/dss-ext/ns}ContextInfo"/>
 *         <element ref="{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement"/>
 *         <element ref="{http://id.elegnamnden.se/csig/1.1/dss-ext/ns}SamlAssertions" minOccurs="0"/>
 *       </sequence>
 *     </restriction>
 *   </complexContent>
 * </complexType>
 * }</pre>
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
