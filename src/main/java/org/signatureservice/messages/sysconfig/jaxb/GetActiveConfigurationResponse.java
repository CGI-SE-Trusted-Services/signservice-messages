//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2015.05.22 at 12:49:39 PM CEST 
//


package org.signatureservice.messages.sysconfig.jaxb;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlType;

import org.signatureservice.messages.csmessages.jaxb.CSResponse;


/**
 * <p>Java class for anonymous complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;extension base="{http://certificateservices.org/xsd/csmessages2_0}CSResponse">
 *       &lt;sequence>
 *         &lt;element name="systemConfiguration" type="{http://certificateservices.org/xsd/sysconfig2_0}SystemConfiguration"/>
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
    "systemConfiguration"
})
@XmlRootElement(name = "GetActiveConfigurationResponse", namespace = "http://certificateservices.org/xsd/sysconfig2_0")
public class GetActiveConfigurationResponse
    extends CSResponse
{

    @XmlElement(namespace = "http://certificateservices.org/xsd/sysconfig2_0", required = true)
    protected SystemConfiguration systemConfiguration;

    /**
     * Gets the value of the systemConfiguration property.
     * 
     * @return
     *     possible object is
     *     {@link SystemConfiguration }
     *     
     */
    public SystemConfiguration getSystemConfiguration() {
        return systemConfiguration;
    }

    /**
     * Sets the value of the systemConfiguration property.
     * 
     * @param value
     *     allowed object is
     *     {@link SystemConfiguration }
     *     
     */
    public void setSystemConfiguration(SystemConfiguration value) {
        this.systemConfiguration = value;
    }

}
