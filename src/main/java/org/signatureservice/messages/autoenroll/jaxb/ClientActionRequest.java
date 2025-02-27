//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2017.03.17 at 10:16:18 AM CET 
//


package org.signatureservice.messages.autoenroll.jaxb;

import java.util.ArrayList;
import java.util.List;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlType;
import org.signatureservice.messages.csmessages.jaxb.CSRequest;
import org.signatureservice.messages.csmessages.jaxb.Credential;


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
 *         &lt;element name="type" maxOccurs="unbounded">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="autoEnrollmentProfile" type="{http://certificateservices.org/xsd/csmessages2_0}notemptystring"/>
 *                   &lt;element name="currentCredentials" minOccurs="0">
 *                     &lt;complexType>
 *                       &lt;complexContent>
 *                         &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                           &lt;sequence>
 *                             &lt;element name="credential" type="{http://certificateservices.org/xsd/csmessages2_0}Credential" maxOccurs="unbounded" minOccurs="0"/>
 *                           &lt;/sequence>
 *                         &lt;/restriction>
 *                       &lt;/complexContent>
 *                     &lt;/complexType>
 *                   &lt;/element>
 *                   &lt;element name="actions">
 *                     &lt;complexType>
 *                       &lt;complexContent>
 *                         &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                           &lt;sequence>
 *                             &lt;element name="generateCredentialRequest" type="{http://certificateservices.org/xsd/autoenroll2_x}PerformedGenerateCredentialRequestAction" maxOccurs="unbounded" minOccurs="0"/>
 *                             &lt;element name="fetchExistingTokens" type="{http://certificateservices.org/xsd/autoenroll2_x}PerformedFetchExistingTokensAction" minOccurs="0"/>
 *                             &lt;element name="removeCredentials" type="{http://certificateservices.org/xsd/autoenroll2_x}PerformedRemoveCredentialsAction" minOccurs="0"/>
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
@XmlRootElement(name = "ClientActionRequest")
public class ClientActionRequest
    extends CSRequest
{

    @XmlElement(required = true)
    protected List<ClientActionRequest.Type> type;

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
     * {@link ClientActionRequest.Type }
     * 
     * 
     */
    public List<ClientActionRequest.Type> getType() {
        if (type == null) {
            type = new ArrayList<ClientActionRequest.Type>();
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
     *         &lt;element name="currentCredentials" minOccurs="0">
     *           &lt;complexType>
     *             &lt;complexContent>
     *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
     *                 &lt;sequence>
     *                   &lt;element name="credential" type="{http://certificateservices.org/xsd/csmessages2_0}Credential" maxOccurs="unbounded" minOccurs="0"/>
     *                 &lt;/sequence>
     *               &lt;/restriction>
     *             &lt;/complexContent>
     *           &lt;/complexType>
     *         &lt;/element>
     *         &lt;element name="actions">
     *           &lt;complexType>
     *             &lt;complexContent>
     *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
     *                 &lt;sequence>
     *                   &lt;element name="generateCredentialRequest" type="{http://certificateservices.org/xsd/autoenroll2_x}PerformedGenerateCredentialRequestAction" maxOccurs="unbounded" minOccurs="0"/>
     *                   &lt;element name="fetchExistingTokens" type="{http://certificateservices.org/xsd/autoenroll2_x}PerformedFetchExistingTokensAction" minOccurs="0"/>
     *                   &lt;element name="removeCredentials" type="{http://certificateservices.org/xsd/autoenroll2_x}PerformedRemoveCredentialsAction" minOccurs="0"/>
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
        "currentCredentials",
        "actions"
    })
    public static class Type {

        @XmlElement(required = true)
        protected String autoEnrollmentProfile;
        protected ClientActionRequest.Type.CurrentCredentials currentCredentials;
        @XmlElement(required = true)
        protected ClientActionRequest.Type.Actions actions;

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
         * Gets the value of the currentCredentials property.
         * 
         * @return
         *     possible object is
         *     {@link ClientActionRequest.Type.CurrentCredentials }
         *     
         */
        public ClientActionRequest.Type.CurrentCredentials getCurrentCredentials() {
            return currentCredentials;
        }

        /**
         * Sets the value of the currentCredentials property.
         * 
         * @param value
         *     allowed object is
         *     {@link ClientActionRequest.Type.CurrentCredentials }
         *     
         */
        public void setCurrentCredentials(ClientActionRequest.Type.CurrentCredentials value) {
            this.currentCredentials = value;
        }

        /**
         * Gets the value of the actions property.
         * 
         * @return
         *     possible object is
         *     {@link ClientActionRequest.Type.Actions }
         *     
         */
        public ClientActionRequest.Type.Actions getActions() {
            return actions;
        }

        /**
         * Sets the value of the actions property.
         * 
         * @param value
         *     allowed object is
         *     {@link ClientActionRequest.Type.Actions }
         *     
         */
        public void setActions(ClientActionRequest.Type.Actions value) {
            this.actions = value;
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
         *         &lt;element name="generateCredentialRequest" type="{http://certificateservices.org/xsd/autoenroll2_x}PerformedGenerateCredentialRequestAction" maxOccurs="unbounded" minOccurs="0"/>
         *         &lt;element name="fetchExistingTokens" type="{http://certificateservices.org/xsd/autoenroll2_x}PerformedFetchExistingTokensAction" minOccurs="0"/>
         *         &lt;element name="removeCredentials" type="{http://certificateservices.org/xsd/autoenroll2_x}PerformedRemoveCredentialsAction" minOccurs="0"/>
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
            "generateCredentialRequest",
            "fetchExistingTokens",
            "removeCredentials"
        })
        public static class Actions {

            protected List<PerformedGenerateCredentialRequestAction> generateCredentialRequest;
            protected PerformedFetchExistingTokensAction fetchExistingTokens;
            protected PerformedRemoveCredentialsAction removeCredentials;

            /**
             * Gets the value of the generateCredentialRequest property.
             * 
             * <p>
             * This accessor method returns a reference to the live list,
             * not a snapshot. Therefore any modification you make to the
             * returned list will be present inside the JAXB object.
             * This is why there is not a <CODE>set</CODE> method for the generateCredentialRequest property.
             * 
             * <p>
             * For example, to add a new item, do as follows:
             * <pre>
             *    getGenerateCredentialRequest().add(newItem);
             * </pre>
             * 
             * 
             * <p>
             * Objects of the following type(s) are allowed in the list
             * {@link PerformedGenerateCredentialRequestAction }
             * 
             * 
             */
            public List<PerformedGenerateCredentialRequestAction> getGenerateCredentialRequest() {
                if (generateCredentialRequest == null) {
                    generateCredentialRequest = new ArrayList<PerformedGenerateCredentialRequestAction>();
                }
                return this.generateCredentialRequest;
            }

            /**
             * Gets the value of the fetchExistingTokens property.
             * 
             * @return
             *     possible object is
             *     {@link PerformedFetchExistingTokensAction }
             *     
             */
            public PerformedFetchExistingTokensAction getFetchExistingTokens() {
                return fetchExistingTokens;
            }

            /**
             * Sets the value of the fetchExistingTokens property.
             * 
             * @param value
             *     allowed object is
             *     {@link PerformedFetchExistingTokensAction }
             *     
             */
            public void setFetchExistingTokens(PerformedFetchExistingTokensAction value) {
                this.fetchExistingTokens = value;
            }

            /**
             * Gets the value of the removeCredentials property.
             * 
             * @return
             *     possible object is
             *     {@link PerformedRemoveCredentialsAction }
             *     
             */
            public PerformedRemoveCredentialsAction getRemoveCredentials() {
                return removeCredentials;
            }

            /**
             * Sets the value of the removeCredentials property.
             * 
             * @param value
             *     allowed object is
             *     {@link PerformedRemoveCredentialsAction }
             *     
             */
            public void setRemoveCredentials(PerformedRemoveCredentialsAction value) {
                this.removeCredentials = value;
            }

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
         *         &lt;element name="credential" type="{http://certificateservices.org/xsd/csmessages2_0}Credential" maxOccurs="unbounded" minOccurs="0"/>
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
            "credential"
        })
        public static class CurrentCredentials {

            protected List<Credential> credential;

            /**
             * Gets the value of the credential property.
             * 
             * <p>
             * This accessor method returns a reference to the live list,
             * not a snapshot. Therefore any modification you make to the
             * returned list will be present inside the JAXB object.
             * This is why there is not a <CODE>set</CODE> method for the credential property.
             * 
             * <p>
             * For example, to add a new item, do as follows:
             * <pre>
             *    getCredential().add(newItem);
             * </pre>
             * 
             * 
             * <p>
             * Objects of the following type(s) are allowed in the list
             * {@link Credential }
             * 
             * 
             */
            public List<Credential> getCredential() {
                if (credential == null) {
                    credential = new ArrayList<Credential>();
                }
                return this.credential;
            }

        }

    }

}
