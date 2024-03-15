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
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;
import org.certificateservices.messages.csmessages.jaxb.CSResponse;


/**
 * <p>Java class for GetRolesType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="GetRolesType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;extension base="{http://certificateservices.org/xsd/csmessages2_0}CSResponse"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="roles"&gt;
 *           &lt;complexType&gt;
 *             &lt;complexContent&gt;
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                 &lt;sequence&gt;
 *                   &lt;element name="role" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring" maxOccurs="unbounded" minOccurs="0"/&gt;
 *                 &lt;/sequence&gt;
 *               &lt;/restriction&gt;
 *             &lt;/complexContent&gt;
 *           &lt;/complexType&gt;
 *         &lt;/element&gt;
 *         &lt;element name="tokenTypePermissions" minOccurs="0"&gt;
 *           &lt;complexType&gt;
 *             &lt;complexContent&gt;
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                 &lt;sequence&gt;
 *                   &lt;element name="tokenTypePermission" type="{http://certificateservices.org/xsd/authorization2_0}TokenTypePermission" maxOccurs="unbounded" minOccurs="0"/&gt;
 *                 &lt;/sequence&gt;
 *               &lt;/restriction&gt;
 *             &lt;/complexContent&gt;
 *           &lt;/complexType&gt;
 *         &lt;/element&gt;
 *       &lt;/sequence&gt;
 *     &lt;/extension&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "GetRolesType", propOrder = {
    "roles",
    "tokenTypePermissions"
})
@XmlSeeAlso({
    GetRequesterRolesResponse.class
})
public class GetRolesType
    extends CSResponse
{

    @XmlElement(required = true)
    protected GetRolesType.Roles roles;
    protected GetRolesType.TokenTypePermissions tokenTypePermissions;

    /**
     * Gets the value of the roles property.
     * 
     * @return
     *     possible object is
     *     {@link GetRolesType.Roles }
     *     
     */
    public GetRolesType.Roles getRoles() {
        return roles;
    }

    /**
     * Sets the value of the roles property.
     * 
     * @param value
     *     allowed object is
     *     {@link GetRolesType.Roles }
     *     
     */
    public void setRoles(GetRolesType.Roles value) {
        this.roles = value;
    }

    /**
     * Gets the value of the tokenTypePermissions property.
     * 
     * @return
     *     possible object is
     *     {@link GetRolesType.TokenTypePermissions }
     *     
     */
    public GetRolesType.TokenTypePermissions getTokenTypePermissions() {
        return tokenTypePermissions;
    }

    /**
     * Sets the value of the tokenTypePermissions property.
     * 
     * @param value
     *     allowed object is
     *     {@link GetRolesType.TokenTypePermissions }
     *     
     */
    public void setTokenTypePermissions(GetRolesType.TokenTypePermissions value) {
        this.tokenTypePermissions = value;
    }


    /**
     * <p>Java class for anonymous complex type.
     * 
     * <p>The following schema fragment specifies the expected content contained within this class.
     * 
     * <pre>
     * &lt;complexType&gt;
     *   &lt;complexContent&gt;
     *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
     *       &lt;sequence&gt;
     *         &lt;element name="role" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring" maxOccurs="unbounded" minOccurs="0"/&gt;
     *       &lt;/sequence&gt;
     *     &lt;/restriction&gt;
     *   &lt;/complexContent&gt;
     * &lt;/complexType&gt;
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "role"
    })
    public static class Roles {

        protected List<String> role;

        /**
         * Gets the value of the role property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the role property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getRole().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link String }
         * 
         * 
         */
        public List<String> getRole() {
            if (role == null) {
                role = new ArrayList<String>();
            }
            return this.role;
        }

    }


    /**
     * <p>Java class for anonymous complex type.
     * 
     * <p>The following schema fragment specifies the expected content contained within this class.
     * 
     * <pre>
     * &lt;complexType&gt;
     *   &lt;complexContent&gt;
     *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
     *       &lt;sequence&gt;
     *         &lt;element name="tokenTypePermission" type="{http://certificateservices.org/xsd/authorization2_0}TokenTypePermission" maxOccurs="unbounded" minOccurs="0"/&gt;
     *       &lt;/sequence&gt;
     *     &lt;/restriction&gt;
     *   &lt;/complexContent&gt;
     * &lt;/complexType&gt;
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "tokenTypePermission"
    })
    public static class TokenTypePermissions {

        protected List<TokenTypePermission> tokenTypePermission;

        /**
         * Gets the value of the tokenTypePermission property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the tokenTypePermission property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getTokenTypePermission().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link TokenTypePermission }
         * 
         * 
         */
        public List<TokenTypePermission> getTokenTypePermission() {
            if (tokenTypePermission == null) {
                tokenTypePermission = new ArrayList<TokenTypePermission>();
            }
            return this.tokenTypePermission;
        }

    }

}
