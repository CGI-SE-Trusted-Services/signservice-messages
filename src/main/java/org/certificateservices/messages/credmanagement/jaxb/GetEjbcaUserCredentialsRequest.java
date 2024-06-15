//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2024.06.15 at 08:25:10 AM CEST 
//


package org.certificateservices.messages.credmanagement.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import org.certificateservices.messages.csmessages.jaxb.CSRequest;


/**
 * <p>Java class for anonymous complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;extension base="{http://certificateservices.org/xsd/csmessages2_0}CSRequest">
 *       &lt;sequence>
 *         &lt;element name="ejbcaUsername" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring"/>
 *         &lt;element name="startIndex" type="{http://www.w3.org/2001/XMLSchema}int" minOccurs="0"/>
 *         &lt;element name="resultSize" type="{http://www.w3.org/2001/XMLSchema}int" minOccurs="0"/>
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
    "ejbcaUsername",
    "startIndex",
    "resultSize"
})
@XmlRootElement(name = "GetEjbcaUserCredentialsRequest")
public class GetEjbcaUserCredentialsRequest
    extends CSRequest
{

    @XmlElement(required = true)
    protected String ejbcaUsername;
    protected Integer startIndex;
    protected Integer resultSize;

    /**
     * Gets the value of the ejbcaUsername property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getEjbcaUsername() {
        return ejbcaUsername;
    }

    /**
     * Sets the value of the ejbcaUsername property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setEjbcaUsername(String value) {
        this.ejbcaUsername = value;
    }

    /**
     * Gets the value of the startIndex property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getStartIndex() {
        return startIndex;
    }

    /**
     * Sets the value of the startIndex property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setStartIndex(Integer value) {
        this.startIndex = value;
    }

    /**
     * Gets the value of the resultSize property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getResultSize() {
        return resultSize;
    }

    /**
     * Sets the value of the resultSize property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setResultSize(Integer value) {
        this.resultSize = value;
    }

}
