//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2015.07.22 at 09:07:39 AM CEST 
//


package org.signatureservice.messages.csmessages.jaxb;

import jakarta.xml.bind.annotation.XmlEnum;
import jakarta.xml.bind.annotation.XmlType;


/**
 * <p>Java class for ApproverType.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="ApproverType">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="MANUAL"/>
 *     &lt;enumeration value="AUTOMATIC"/>
 *     &lt;enumeration value="FORWARDED"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "ApproverType", namespace = "http://certificateservices.org/xsd/csmessages2_0")
@XmlEnum
public enum ApproverType {

    MANUAL,
    AUTOMATIC,
    FORWARDED;

    public String value() {
        return name();
    }

    public static ApproverType fromValue(String v) {
        return valueOf(v);
    }

}
