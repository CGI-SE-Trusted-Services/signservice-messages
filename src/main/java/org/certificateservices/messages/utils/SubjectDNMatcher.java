package org.certificateservices.messages.utils;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.style.BCStyle;

import java.security.cert.X509Certificate;

/**
 * Help class used to match a DN field for a specific value
 * Created by philip on 2017-08-07.
 */
public class SubjectDNMatcher  {
    /**
     * Help method to verify if a certificate matches the subject DN of a certificate.
     *
     * @param cert           the certificate to check if subject dn matches.
     * @param subjectDNField the subject dn field to match, ex OU
     * @param subjectDNValue the value to match, ex backend
     * @return true if subject matches otherwise false.
     */
    public boolean subjectMatch(X509Certificate cert, String subjectDNField, String subjectDNValue) {
        String certFieldValue = CertUtils.getSubjectDNField(cert, getIdentifier(subjectDNField));
        return certFieldValue != null && certFieldValue.equals(subjectDNValue.trim());
    }

    /**
     * Help method to verify if a certificate matches the subject DN of a certificate.
     *
     * @param cert           the certificate to check if subject dn matches.
     * @param subjectDNField the ASN1ObjectIdentifier subject dn field to match, ex OU
     * @param subjectDNValue the value to match, ex backend
     * @return true if subject matches otherwise false.
     */
    public boolean subjectMatch(X509Certificate cert, ASN1ObjectIdentifier subjectDNField, String subjectDNValue) {
        String certFieldValue = CertUtils.getSubjectDNField(cert, subjectDNField);
        return certFieldValue.equals(subjectDNValue.trim());
    }

    /**
     * Returns the symbols related ASN1 identifier.
     *
     * @param dnSymbol the dn symbol
     * @return the related asn1 identifier or null if symbol was not found.
     */
    public ASN1ObjectIdentifier getIdentifier(String dnSymbol) {
        try {
            return availableDNFields.getIdentifier(dnSymbol.trim().toLowerCase());
        } catch (IllegalArgumentException e) {
            return null;
        }

    }

    private AvailableDNFields availableDNFields = new AvailableDNFields();

    public static class AvailableDNFields extends BCStyle {
        public ASN1ObjectIdentifier getIdentifier(String dnSymbol) {
            return attrNameToOID(dnSymbol);
        }

    }
}
