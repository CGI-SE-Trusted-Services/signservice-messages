//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.07.08 at 07:14:04 AM CEST 
//


package org.certificateservices.messages.authorization.jaxb;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import org.certificateservices.messages.csmessages.jaxb.CSRequest;


/**
 * Java class for anonymous complex type.
 *
 * The following schema fragment specifies the expected content contained within this class.
 *
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;extension base="{http://certificateservices.org/xsd/csmessages2_0}CSRequest">
 *       &lt;sequence>
 *         &lt;element name="tokenTypePermissionQuery" minOccurs="0">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="tokenType" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring" maxOccurs="unbounded" minOccurs="0"/>
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
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "tokenTypePermissionQuery"
})
@XmlRootElement(name = "GetRequesterRolesRequest")
public class GetRequesterRolesRequest
    extends CSRequest
{

    protected GetRequesterRolesRequest.TokenTypePermissionQuery tokenTypePermissionQuery;

    /**
     * Gets the value of the tokenTypePermissionQuery property.
     * 
     * @return
     *     possible object is
     *     {@link GetRequesterRolesRequest.TokenTypePermissionQuery }
     *     
     */
    public GetRequesterRolesRequest.TokenTypePermissionQuery getTokenTypePermissionQuery() {
        return tokenTypePermissionQuery;
    }

    /**
     * Sets the value of the tokenTypePermissionQuery property.
     * 
     * @param value
     *     allowed object is
     *     {@link GetRequesterRolesRequest.TokenTypePermissionQuery }
     *     
     */
    public void setTokenTypePermissionQuery(GetRequesterRolesRequest.TokenTypePermissionQuery value) {
        this.tokenTypePermissionQuery = value;
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
     *         &lt;element name="tokenType" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring" maxOccurs="unbounded" minOccurs="0"/>
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
        "tokenType"
    })
    public static class TokenTypePermissionQuery {

        protected List<String> tokenType;

        /**
         * Gets the value of the tokenType property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the tokenType property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getTokenType().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link String }
         * 
         * 
         */
        public List<String> getTokenType() {
            if (tokenType == null) {
                tokenType = new ArrayList<String>();
            }
            return this.tokenType;
        }

    }

}
