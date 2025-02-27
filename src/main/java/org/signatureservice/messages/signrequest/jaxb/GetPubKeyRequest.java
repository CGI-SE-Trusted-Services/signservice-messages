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
 *         &lt;element name="getPubKeyRequestTasks">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="getPubKeyRequestTask" type="{http://certificateservices.org/xsd/signrequest2_0}GetPubKeyRequestTask" maxOccurs="100"/>
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
    "getPubKeyRequestTasks"
})
@XmlRootElement(name = "GetPubKeyRequest")
public class GetPubKeyRequest
    extends CSRequest
{

    @XmlElement(required = true)
    protected GetPubKeyRequest.GetPubKeyRequestTasks getPubKeyRequestTasks;

    /**
     * Gets the value of the getPubKeyRequestTasks property.
     * 
     * @return
     *     possible object is
     *     {@link GetPubKeyRequest.GetPubKeyRequestTasks }
     *     
     */
    public GetPubKeyRequest.GetPubKeyRequestTasks getGetPubKeyRequestTasks() {
        return getPubKeyRequestTasks;
    }

    /**
     * Sets the value of the getPubKeyRequestTasks property.
     * 
     * @param value
     *     allowed object is
     *     {@link GetPubKeyRequest.GetPubKeyRequestTasks }
     *     
     */
    public void setGetPubKeyRequestTasks(GetPubKeyRequest.GetPubKeyRequestTasks value) {
        this.getPubKeyRequestTasks = value;
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
     *         &lt;element name="getPubKeyRequestTask" type="{http://certificateservices.org/xsd/signrequest2_0}GetPubKeyRequestTask" maxOccurs="100"/>
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
        "getPubKeyRequestTask"
    })
    public static class GetPubKeyRequestTasks {

        @XmlElement(required = true)
        protected List<GetPubKeyRequestTask> getPubKeyRequestTask;

        /**
         * Gets the value of the getPubKeyRequestTask property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the getPubKeyRequestTask property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getGetPubKeyRequestTask().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link GetPubKeyRequestTask }
         * 
         * 
         */
        public List<GetPubKeyRequestTask> getGetPubKeyRequestTask() {
            if (getPubKeyRequestTask == null) {
                getPubKeyRequestTask = new ArrayList<GetPubKeyRequestTask>();
            }
            return this.getPubKeyRequestTask;
        }

    }

}
