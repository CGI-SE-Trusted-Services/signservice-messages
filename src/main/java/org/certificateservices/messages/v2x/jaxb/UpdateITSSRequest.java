//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2020.03.19 at 03:55:20 PM CET 
//


package org.certificateservices.messages.v2x.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for anonymous complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;extension base="{http://certificateservices.org/xsd/v2x_2_0}BaseRegisterRequestType">
 *       &lt;sequence>
 *         &lt;element name="canonicalPublicKey" type="{http://certificateservices.org/xsd/v2x_2_0}CanonicalKeyType" minOccurs="0"/>
 *         &lt;element name="eaName" type="{http://certificateservices.org/xsd/v2x_2_0}ProfileNameType" minOccurs="0"/>
 *         &lt;element name="atPermissions" type="{http://certificateservices.org/xsd/v2x_2_0}ATAppPermissionsType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "canonicalPublicKey",
    "eaName",
    "atPermissions"
})
@XmlRootElement(name = "UpdateITSSRequest")
public class UpdateITSSRequest
    extends BaseRegisterRequestType
{

    protected CanonicalKeyType canonicalPublicKey;
    protected String eaName;
    protected ATAppPermissionsType atPermissions;

    /**
     * Gets the value of the canonicalPublicKey property.
     * 
     * @return
     *     possible object is
     *     {@link CanonicalKeyType }
     *     
     */
    public CanonicalKeyType getCanonicalPublicKey() {
        return canonicalPublicKey;
    }

    /**
     * Sets the value of the canonicalPublicKey property.
     * 
     * @param value
     *     allowed object is
     *     {@link CanonicalKeyType }
     *     
     */
    public void setCanonicalPublicKey(CanonicalKeyType value) {
        this.canonicalPublicKey = value;
    }

    /**
     * Gets the value of the eaName property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getEaName() {
        return eaName;
    }

    /**
     * Sets the value of the eaName property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setEaName(String value) {
        this.eaName = value;
    }

    /**
     * Gets the value of the atPermissions property.
     * 
     * @return
     *     possible object is
     *     {@link ATAppPermissionsType }
     *     
     */
    public ATAppPermissionsType getAtPermissions() {
        return atPermissions;
    }

    /**
     * Sets the value of the atPermissions property.
     * 
     * @param value
     *     allowed object is
     *     {@link ATAppPermissionsType }
     *     
     */
    public void setAtPermissions(ATAppPermissionsType value) {
        this.atPermissions = value;
    }

}
