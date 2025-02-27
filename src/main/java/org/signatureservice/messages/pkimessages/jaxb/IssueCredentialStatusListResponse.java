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
 * <p>Java class for IssueCredentialStatusListResponse complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="IssueCredentialStatusListResponse">
 *   &lt;complexContent>
 *     &lt;extension base="{http://certificateservices.org/xsd/pkimessages1_0}PKIResponse">
 *       &lt;sequence>
 *         &lt;element name="credentialStatusList" type="{http://certificateservices.org/xsd/pkimessages1_0}CredentialStatusList"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "IssueCredentialStatusListResponse", propOrder = {
    "credentialStatusList"
})
public class IssueCredentialStatusListResponse
    extends PKIResponse
{

    @XmlElement(required = true)
    protected CredentialStatusList credentialStatusList;

    /**
     * Gets the value of the credentialStatusList property.
     * 
     * @return
     *     possible object is
     *     {@link CredentialStatusList }
     *     
     */
    public CredentialStatusList getCredentialStatusList() {
        return credentialStatusList;
    }

    /**
     * Sets the value of the credentialStatusList property.
     * 
     * @param value
     *     allowed object is
     *     {@link CredentialStatusList }
     *     
     */
    public void setCredentialStatusList(CredentialStatusList value) {
        this.credentialStatusList = value;
    }

}
