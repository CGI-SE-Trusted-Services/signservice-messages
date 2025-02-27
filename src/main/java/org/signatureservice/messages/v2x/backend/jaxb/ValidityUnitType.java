//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2020.06.02 at 09:13:09 AM CEST 
//


package org.signatureservice.messages.v2x.backend.jaxb;

import jakarta.xml.bind.annotation.XmlEnum;
import jakarta.xml.bind.annotation.XmlEnumValue;
import jakarta.xml.bind.annotation.XmlType;


/**
 * <p>Java class for ValidityUnitType.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="ValidityUnitType">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="microseconds"/>
 *     &lt;enumeration value="milliseconds"/>
 *     &lt;enumeration value="seconds"/>
 *     &lt;enumeration value="minutes"/>
 *     &lt;enumeration value="hours"/>
 *     &lt;enumeration value="sixtyHours"/>
 *     &lt;enumeration value="years"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "ValidityUnitType")
@XmlEnum
public enum ValidityUnitType {

    @XmlEnumValue("microseconds")
    MICROSECONDS("microseconds"),
    @XmlEnumValue("milliseconds")
    MILLISECONDS("milliseconds"),
    @XmlEnumValue("seconds")
    SECONDS("seconds"),
    @XmlEnumValue("minutes")
    MINUTES("minutes"),
    @XmlEnumValue("hours")
    HOURS("hours"),
    @XmlEnumValue("sixtyHours")
    SIXTY_HOURS("sixtyHours"),
    @XmlEnumValue("years")
    YEARS("years");
    private final String value;

    ValidityUnitType(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static ValidityUnitType fromValue(String v) {
        for (ValidityUnitType c: ValidityUnitType.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
