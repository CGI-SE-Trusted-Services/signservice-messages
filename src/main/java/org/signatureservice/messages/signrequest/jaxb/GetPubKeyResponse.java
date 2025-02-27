//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.02.20 at 10:25:51 AM CET 
//


package org.signatureservice.messages.signrequest.jaxb;

import java.util.ArrayList;
import java.util.List;
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
 *         &lt;element name="getPubKeyResponseTasks">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="getPubKeyResponseTask" type="{http://certificateservices.org/xsd/signrequest2_0}GetPubKeyResponseTask" maxOccurs="100"/>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
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
    "getPubKeyResponseTasks"
})
@XmlRootElement(name = "GetPubKeyResponse")
public class GetPubKeyResponse
    extends CSResponse
{

    @XmlElement(required = true)
    protected GetPubKeyResponse.GetPubKeyResponseTasks getPubKeyResponseTasks;

    /**
     * Gets the value of the getPubKeyResponseTasks property.
     * 
     * @return
     *     possible object is
     *     {@link GetPubKeyResponse.GetPubKeyResponseTasks }
     *     
     */
    public GetPubKeyResponse.GetPubKeyResponseTasks getGetPubKeyResponseTasks() {
        return getPubKeyResponseTasks;
    }

    /**
     * Sets the value of the getPubKeyResponseTasks property.
     * 
     * @param value
     *     allowed object is
     *     {@link GetPubKeyResponse.GetPubKeyResponseTasks }
     *     
     */
    public void setGetPubKeyResponseTasks(GetPubKeyResponse.GetPubKeyResponseTasks value) {
        this.getPubKeyResponseTasks = value;
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
     *         &lt;element name="getPubKeyResponseTask" type="{http://certificateservices.org/xsd/signrequest2_0}GetPubKeyResponseTask" maxOccurs="100"/>
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
        "getPubKeyResponseTask"
    })
    public static class GetPubKeyResponseTasks {

        @XmlElement(required = true)
        protected List<GetPubKeyResponseTask> getPubKeyResponseTask;

        /**
         * Gets the value of the getPubKeyResponseTask property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the getPubKeyResponseTask property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getGetPubKeyResponseTask().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link GetPubKeyResponseTask }
         * 
         * 
         */
        public List<GetPubKeyResponseTask> getGetPubKeyResponseTask() {
            if (getPubKeyResponseTask == null) {
                getPubKeyResponseTask = new ArrayList<GetPubKeyResponseTask>();
            }
            return this.getPubKeyResponseTask;
        }

    }

}
