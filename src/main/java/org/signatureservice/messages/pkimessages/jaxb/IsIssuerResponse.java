//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2012.09.23 at 02:26:35 PM CEST 
//


package org.signatureservice.messages.pkimessages.jaxb;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlType;


/**
 * <p>Java class for IsIssuerResponse complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="IsIssuerResponse">
 *   &lt;complexContent>
 *     &lt;extension base="{http://certificateservices.org/xsd/pkimessages1_0}PKIResponse">
 *       &lt;sequence>
 *         &lt;element name="isIssuer" type="{http://www.w3.org/2001/XMLSchema}boolean"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "IsIssuerResponse", propOrder = {
    "isIssuer"
})
public class IsIssuerResponse
    extends PKIResponse
{

    protected boolean isIssuer;

    /**
     * Gets the value of the isIssuer property.
     * 
     */
    public boolean isIsIssuer() {
        return isIssuer;
    }

    /**
     * Sets the value of the isIssuer property.
     * 
     */
    public void setIsIssuer(boolean value) {
        this.isIssuer = value;
    }

}
