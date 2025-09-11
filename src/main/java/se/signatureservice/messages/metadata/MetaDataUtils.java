package se.signatureservice.messages.metadata;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.Optional;

/**
 * Utility methods used when parsing data from XML MetaData.
 *
 * @author Filip Wessman 2023-06-10
 */
class MetaDataUtils {
    static Logger msgLog = LoggerFactory.getLogger(MetaDataUtils.class);

    /**
     * Receive the CommonName ("CN") from a X.509 Certificate.
     *
     * @param cert to receive the CommonName ("CN") from.
     * @return if found, the CommonName ("CN"), otherwise null.
     */
    static String getCommonNameFromX509Certificate(X509Certificate cert) {
        if (cert == null) {
            msgLog.debug("Certificate cannot be null when extracting Common Name (CN) from getCommonNameFromX509Certificate method");
            return null;
        }

        try {
            X500Name x500name = new JcaX509CertificateHolder(cert).getSubject();

            RDN cn = Optional.ofNullable(x500name.getRDNs(BCStyle.CN)).map(a -> a.length > 0 ? a[0] : null).orElse(null);
            if (cn == null) {
                msgLog.debug("No Common Name (CN) attribute found for X509 Certificate with serial number '${cert.serialNumber}'");
                return null;
            }

            var s = IETFUtils.valueToString(cn.getFirst().getValue()).trim();
            if (s.isBlank()) {
                return null;
            }

            return s;

        } catch (Exception e) {
            msgLog.error("Error extracting Common Name (CN) from X509 certificate with serial number '${cert.serialNumber}': ${e.message}");
            return null;
        }
    }
}
