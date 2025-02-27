//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2018.03.13 at 01:30:37 PM CET 
//


package org.signatureservice.messages.credmanagement.jaxb;

import java.util.ArrayList;
import java.util.List;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlSchemaType;
import jakarta.xml.bind.annotation.XmlType;
import org.signatureservice.messages.csmessages.jaxb.AutomationLevel;
import org.signatureservice.messages.csmessages.jaxb.CSRequest;


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
 *         &lt;element name="automationLevel" type="{http://certificateservices.org/xsd/csmessages2_0}AutomationLevel" minOccurs="0"/>
 *         &lt;element name="renewalRequestData" type="{http://www.w3.org/2001/XMLSchema}base64Binary" maxOccurs="100"/>
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
    "automationLevel",
    "renewalRequestData"
})
@XmlRootElement(name = "AutomaticRenewCredentialRequest")
public class AutomaticRenewCredentialRequest
    extends CSRequest
{

    @XmlElement(defaultValue = "MANUAL")
    @XmlSchemaType(name = "string")
    protected AutomationLevel automationLevel;
    @XmlElement(required = true)
    protected List<byte[]> renewalRequestData;

    /**
     * Gets the value of the automationLevel property.
     * 
     * @return
     *     possible object is
     *     {@link AutomationLevel }
     *     
     */
    public AutomationLevel getAutomationLevel() {
        return automationLevel;
    }

    /**
     * Sets the value of the automationLevel property.
     * 
     * @param value
     *     allowed object is
     *     {@link AutomationLevel }
     *     
     */
    public void setAutomationLevel(AutomationLevel value) {
        this.automationLevel = value;
    }

    /**
     * Gets the value of the renewalRequestData property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the renewalRequestData property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getRenewalRequestData().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * byte[]
     * 
     */
    public List<byte[]> getRenewalRequestData() {
        if (renewalRequestData == null) {
            renewalRequestData = new ArrayList<byte[]>();
        }
        return this.renewalRequestData;
    }

}
