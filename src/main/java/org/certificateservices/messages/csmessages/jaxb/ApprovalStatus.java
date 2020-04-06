//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2015.05.21 at 02:30:00 PM CEST 
//


package org.certificateservices.messages.csmessages.jaxb;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for ApprovalStatus.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="ApprovalStatus">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="WAITING"/>
 *     &lt;enumeration value="APPROVED"/>
 *     &lt;enumeration value="DENIED"/>
 *     &lt;enumeration value="EXPIRED"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "ApprovalStatus", namespace = "http://certificateservices.org/xsd/csmessages2_0")
@XmlEnum
public enum ApprovalStatus {

    WAITING,
    INPROCESS,
    PROCESSED,
    APPROVED,
    DENIED,
    EXPIRED;

    public String value() {
        return name();
    }

    public static ApprovalStatus fromValue(String v) {
        return valueOf(v);
    }

}
