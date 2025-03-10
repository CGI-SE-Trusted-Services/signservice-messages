//
// This file was generated by the Eclipse Implementation of JAXB, v4.0.5 
// See https://eclipse-ee4j.github.io/jaxb-ri 
// Any modifications to this file will be lost upon recompilation of the source schema. 
//


package org.signatureservice.messages.sweeid2.dssextenstions1_1.jaxb;

import java.util.ArrayList;
import java.util.List;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlType;


/**
 * <p>Java class for RequestedAttributesType complex type</p>.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.</p>
 * 
 * <pre>{@code
 * <complexType name="RequestedAttributesType">
 *   <complexContent>
 *     <restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       <sequence>
 *         <element name="RequestedCertAttribute" type="{http://id.elegnamnden.se/csig/1.1/dss-ext/ns}MappedAttributeType" maxOccurs="unbounded"/>
 *       </sequence>
 *     </restriction>
 *   </complexContent>
 * </complexType>
 * }</pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "RequestedAttributesType", propOrder = {
    "requestedCertAttribute"
})
public class RequestedAttributesType {

    @XmlElement(name = "RequestedCertAttribute", required = true)
    protected List<MappedAttributeType> requestedCertAttribute;

    /**
     * Gets the value of the requestedCertAttribute property.
     * 
     * <p>This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the requestedCertAttribute property.</p>
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * </p>
     * <pre>
     * getRequestedCertAttribute().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link MappedAttributeType }
     * </p>
     * 
     * 
     * @return
     *     The value of the requestedCertAttribute property.
     */
    public List<MappedAttributeType> getRequestedCertAttribute() {
        if (requestedCertAttribute == null) {
            requestedCertAttribute = new ArrayList<>();
        }
        return this.requestedCertAttribute;
    }

}
