//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2017.01.10 at 07:01:27 AM MSK 
//


package org.certificateservices.messages.sweeid2.dssextenstions1_1.jaxb;

import java.util.HashMap;
import java.util.Map;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAnyAttribute;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.namespace.QName;
import org.certificateservices.messages.saml2.assertion.jaxb.EncryptedElementType;


/**
 * <p>Java class for SignMessageType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="SignMessageType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;choice>
 *         &lt;element ref="{http://id.elegnamnden.se/csig/1.1/dss-ext/ns}Message"/>
 *         &lt;element ref="{http://id.elegnamnden.se/csig/1.1/dss-ext/ns}EncryptedMessage"/>
 *       &lt;/choice>
 *       &lt;attribute name="MustShow" type="{http://www.w3.org/2001/XMLSchema}boolean" default="false" />
 *       &lt;attribute name="DisplayEntity" type="{http://www.w3.org/2001/XMLSchema}anyURI" />
 *       &lt;attribute name="MimeType" default="text">
 *         &lt;simpleType>
 *           &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *             &lt;enumeration value="text/html"/>
 *             &lt;enumeration value="text"/>
 *             &lt;enumeration value="text/markdown"/>
 *           &lt;/restriction>
 *         &lt;/simpleType>
 *       &lt;/attribute>
 *       &lt;anyAttribute processContents='lax' namespace='##other'/>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "SignMessageType", propOrder = {
    "message",
    "encryptedMessage"
})
public class SignMessageType {

    @XmlElement(name = "Message")
    protected byte[] message;
    @XmlElement(name = "EncryptedMessage")
    protected EncryptedElementType encryptedMessage;
    @XmlAttribute(name = "MustShow")
    protected Boolean mustShow;
    @XmlAttribute(name = "DisplayEntity")
    @XmlSchemaType(name = "anyURI")
    protected String displayEntity;
    @XmlAttribute(name = "MimeType")
    protected String mimeType;
    @XmlAnyAttribute
    private Map<QName, String> otherAttributes = new HashMap<QName, String>();

    /**
     * Gets the value of the message property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getMessage() {
        return message;
    }

    /**
     * Sets the value of the message property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setMessage(byte[] value) {
        this.message = value;
    }

    /**
     * Gets the value of the encryptedMessage property.
     * 
     * @return
     *     possible object is
     *     {@link EncryptedElementType }
     *     
     */
    public EncryptedElementType getEncryptedMessage() {
        return encryptedMessage;
    }

    /**
     * Sets the value of the encryptedMessage property.
     * 
     * @param value
     *     allowed object is
     *     {@link EncryptedElementType }
     *     
     */
    public void setEncryptedMessage(EncryptedElementType value) {
        this.encryptedMessage = value;
    }

    /**
     * Gets the value of the mustShow property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public boolean isMustShow() {
        if (mustShow == null) {
            return false;
        } else {
            return mustShow;
        }
    }

    /**
     * Sets the value of the mustShow property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setMustShow(Boolean value) {
        this.mustShow = value;
    }

    /**
     * Gets the value of the displayEntity property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getDisplayEntity() {
        return displayEntity;
    }

    /**
     * Sets the value of the displayEntity property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDisplayEntity(String value) {
        this.displayEntity = value;
    }

    /**
     * Gets the value of the mimeType property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getMimeType() {
        if (mimeType == null) {
            return "text";
        } else {
            return mimeType;
        }
    }

    /**
     * Sets the value of the mimeType property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setMimeType(String value) {
        this.mimeType = value;
    }

    /**
     * Gets a map that contains attributes that aren't bound to any typed property on this class.
     * 
     * <p>
     * the map is keyed by the name of the attribute and 
     * the value is the string value of the attribute.
     * 
     * the map returned by this method is live, and you can add new attribute
     * by updating the map directly. Because of this design, there's no setter.
     * 
     * 
     * @return
     *     always non-null
     */
    public Map<QName, String> getOtherAttributes() {
        return otherAttributes;
    }

}
