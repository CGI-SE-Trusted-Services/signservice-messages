//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2025.02.26 at 09:40:10 AM CET 
//


package org.signatureservice.messages.sweeid2.dssextenstions1_1.jaxb;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for SignTasksType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="SignTasksType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{http://id.elegnamnden.se/csig/1.1/dss-ext/ns}SignTaskData" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "SignTasksType", propOrder = {
    "signTaskData"
})
public class SignTasksType {

    @XmlElement(name = "SignTaskData", required = true)
    protected List<SignTaskDataType> signTaskData;

    /**
     * Gets the value of the signTaskData property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the signTaskData property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getSignTaskData().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link SignTaskDataType }
     * 
     * 
     */
    public List<SignTaskDataType> getSignTaskData() {
        if (signTaskData == null) {
            signTaskData = new ArrayList<SignTaskDataType>();
        }
        return this.signTaskData;
    }

}
