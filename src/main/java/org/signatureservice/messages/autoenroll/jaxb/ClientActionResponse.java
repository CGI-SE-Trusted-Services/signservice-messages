//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2017.03.02 at 11:08:13 AM CET 
//


package org.signatureservice.messages.autoenroll.jaxb;

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
 *         &lt;element name="type" maxOccurs="unbounded">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="autoEnrollmentProfile" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring"/>
 *                   &lt;element name="tokenDatas" minOccurs="0">
 *                     &lt;complexType>
 *                       &lt;complexContent>
 *                         &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                           &lt;sequence>
 *                             &lt;element name="tokenData" type="{http://certificateservices.org/xsd/autoenroll2_x}TokenData" maxOccurs="unbounded"/>
 *                           &lt;/sequence>
 *                         &lt;/restriction>
 *                       &lt;/complexContent>
 *                     &lt;/complexType>
 *                   &lt;/element>
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
    "type"
})
@XmlRootElement(name = "ClientActionResponse")
public class ClientActionResponse
    extends CSResponse
{

    @XmlElement(required = true)
    protected List<ClientActionResponse.Type> type;

    /**
     * Gets the value of the type property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the type property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getType().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link ClientActionResponse.Type }
     * 
     * 
     */
    public List<ClientActionResponse.Type> getType() {
        if (type == null) {
            type = new ArrayList<ClientActionResponse.Type>();
        }
        return this.type;
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
     *         &lt;element name="autoEnrollmentProfile" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring"/>
     *         &lt;element name="tokenDatas" minOccurs="0">
     *           &lt;complexType>
     *             &lt;complexContent>
     *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
     *                 &lt;sequence>
     *                   &lt;element name="tokenData" type="{http://certificateservices.org/xsd/autoenroll2_x}TokenData" maxOccurs="unbounded"/>
     *                 &lt;/sequence>
     *               &lt;/restriction>
     *             &lt;/complexContent>
     *           &lt;/complexType>
     *         &lt;/element>
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
        "autoEnrollmentProfile",
        "tokenDatas"
    })
    public static class Type {

        @XmlElement(required = true)
        protected String autoEnrollmentProfile;
        protected ClientActionResponse.Type.TokenDatas tokenDatas;

        /**
         * Gets the value of the autoEnrollmentProfile property.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getAutoEnrollmentProfile() {
            return autoEnrollmentProfile;
        }

        /**
         * Sets the value of the autoEnrollmentProfile property.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setAutoEnrollmentProfile(String value) {
            this.autoEnrollmentProfile = value;
        }

        /**
         * Gets the value of the tokenDatas property.
         * 
         * @return
         *     possible object is
         *     {@link ClientActionResponse.Type.TokenDatas }
         *     
         */
        public ClientActionResponse.Type.TokenDatas getTokenDatas() {
            return tokenDatas;
        }

        /**
         * Sets the value of the tokenDatas property.
         * 
         * @param value
         *     allowed object is
         *     {@link ClientActionResponse.Type.TokenDatas }
         *     
         */
        public void setTokenDatas(ClientActionResponse.Type.TokenDatas value) {
            this.tokenDatas = value;
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
         *         &lt;element name="tokenData" type="{http://certificateservices.org/xsd/autoenroll2_x}TokenData" maxOccurs="unbounded"/>
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
            "tokenData"
        })
        public static class TokenDatas {

            @XmlElement(required = true)
            protected List<TokenData> tokenData;

            /**
             * Gets the value of the tokenData property.
             * 
             * <p>
             * This accessor method returns a reference to the live list,
             * not a snapshot. Therefore any modification you make to the
             * returned list will be present inside the JAXB object.
             * This is why there is not a <CODE>set</CODE> method for the tokenData property.
             * 
             * <p>
             * For example, to add a new item, do as follows:
             * <pre>
             *    getTokenData().add(newItem);
             * </pre>
             * 
             * 
             * <p>
             * Objects of the following type(s) are allowed in the list
             * {@link TokenData }
             * 
             * 
             */
            public List<TokenData> getTokenData() {
                if (tokenData == null) {
                    tokenData = new ArrayList<TokenData>();
                }
                return this.tokenData;
            }

        }

    }

}
