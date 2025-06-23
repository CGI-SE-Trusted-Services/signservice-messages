/************************************************************************
 *                                                                       *
 *  Signature Service - Messages                                         *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package se.signatureservice.messages.utils;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509NameTokenizer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Certificate related utilities. Most of the method is copied from EJBCA 3.5 branch
 * since 3.9 and up is dependent of cvs libs that isn't necessary.
 *
 * @author Philip Vendil 22 Jan 2010
 * @version $Id$
 */
@SuppressWarnings("deprecation")
public class CertUtils {
    private static final Logger log = LoggerFactory.getLogger(CertUtils.class);

    public static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERTIFICATE = "-----END CERTIFICATE-----";

    private static MessageDigest sha256MessageDigest = null;

    private static CertificateFactory certFact = null;

    public static CertificateFactory getCertificateFactory() throws NoSuchProviderException {
        if (certFact == null) {
            certFact = new BCCertificateFactory();
        }
        return certFact;
    }

    public static MessageDigest getSHA256MessageDigest() throws NoSuchAlgorithmException {
        if (sha256MessageDigest == null) {
            sha256MessageDigest = MessageDigest.getInstance("SHA-256");
        }
        return sha256MessageDigest;
    }

    /**
     * Help method to find BC Provider
     *
     * @return the BouncyCastle provider
     * @throws NoSuchProviderException if "BC" provider couldn't be found among installed providers.
     */
    public static Provider getBCProvider() throws NoSuchProviderException {
        Provider bc = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (bc == null) {
            throw new NoSuchProviderException();
        }
        return bc;
    }

    /**
     * Creates X509Certificate from byte[].
     *
     * @param cert byte array containing certificate in DER-format
     * @return X509Certificate
     * @throws CertificateException if the byte array does not contain a proper certificate.
     * @throws DecoderException     if the byte array cannot be read.
     */
    public static X509Certificate getCertfromByteArray(byte[] cert) throws CertificateException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(cert)) {
            CertificateFactory cf = getCertificateFactory();
            X509Certificate x509cert = (X509Certificate) cf.generateCertificate(bais);
            if (x509cert == null) {
                throw new CertificateException("Error invalid certificate data");
            }
            return x509cert;
        } catch (Exception e) {
            throw new CertificateException("Error creating certificate: " + e.getMessage(), e);
        }
    }

    /**
     * Creates X509CRL from byte[].
     *
     * @param crl byte array containing the encoded crl
     * @return X509CRL
     * @throws CRLException if parsing of CRL failed.
     */
    public static X509CRL getCRLfromByteArray(byte[] crl) throws CRLException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(crl)) {
            CertificateFactory cf = getCertificateFactory();
            X509CRL x509crl = (X509CRL) cf.generateCRL(bais);
            if (x509crl == null) {
                throw new CRLException("Error invalid crl data");
            }
            return x509crl;
        } catch (Exception e) {
            throw new CRLException("Error creating CRL: " + e.getMessage(), e);
        }
    }

    /**
     * Reads binary bytes from a PEM-file. The PEM-file may contain other stuff, the first item
     * between beginKey and endKey is read. Example: <code>-----BEGIN CERTIFICATE REQUEST-----
     * base64 encoded PKCS10 certification request -----END CERTIFICATE REQUEST----- </code>
     *
     * @param inbuf    input buffer containing PEM-formatted stuff.
     * @param beginKey begin line of PEM message
     * @param endKey   end line of PEM message
     * @return byte[] containing binary Base64 decoded bytes.
     * @throws IOException if the PEM file does not contain the correct data.
     */
    public static byte[] getBytesFromPEM(byte[] inbuf, String beginKey, String endKey)
            throws IOException {

        log.debug(">getBytesFromPEM");

        final String TRIM_REGEXP = "[\\t\\r\\n]";

        if (inbuf == null) {
            throw new IOException("Error, data was null in input buffer");
        }

        try (BufferedReader bufRdr = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(inbuf)));
             ByteArrayOutputStream ostr = new ByteArrayOutputStream();
             PrintStream opstr = new PrintStream(ostr, true)) {

            String temp;
            boolean inKeySection = false;

            while ((temp = bufRdr.readLine()) != null) {
                temp = temp.replaceAll(TRIM_REGEXP, "").trim();
                if (!inKeySection && temp.equals(beginKey)) {
                    inKeySection = true;
                    continue;
                }
                if (inKeySection) {
                    if (temp.equals(endKey)) {
                        break;
                    }
                    opstr.print(temp);
                }
            }

            if (!inKeySection) {
                throw new IOException("Error in input buffer, missing " + beginKey + " boundary");
            }
            if (temp == null) {
                throw new IOException("Error in input buffer, missing " + endKey + " boundary");
            }

            log.debug("<getBytesFromPEM");

            return Base64.decode(ostr.toByteArray());
        }
    }

    /**
     * Method used to get the certificate for binary data and try different encodings to parse the certificate.
     *
     * @param certData the certificate data.
     * @return the certificate or null of no certificate could be parsed.
     */
    public static X509Certificate getX509CertificateFromPEMorDER(byte[] certData) {
        if (certData == null) {
            return null;
        }
        X509Certificate retval = null;
        try {
            retval = getCertfromByteArray(certData);
        } catch (CertificateException ignored) {
        }

        if (retval == null) {
            try {
                retval = getCertfromByteArray(getBytesFromPEM(certData, BEGIN_CERTIFICATE, END_CERTIFICATE));
            } catch (IOException | CertificateException ignored) {
            }
        }
        return retval;
    }

    /**
     * Method that installs the BC provider into java. Should be called
     * once in the initialisation phase of the application.
     */
    public static synchronized void installBCProvider() {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Help method used to normalise a subject string to a standard BC style X500Name
     *
     * @param subject the subject name to normalise
     * @return the strict comparable X500 format format of the issuer.
     */
    public static String getNormalizedSubject(String subject) {
        if (subject == null) {
            return null;
        }
        return new X500Name(BCStyle.INSTANCE, subject).toString();
    }

    /**
     * Help method used to convert a DN string to a standard BC style X500Name
     *
     * @param dNName the DN name to convert
     * @return the strict comparable X500 format format of the name
     */
    public static X500Name toX500Name(String dNName) {
        if (dNName == null) {
            return null;
        }
        return new X500Name(BCStyle.INSTANCE, dNName);
    }

    /**
     * Returns the issuer distinguished name in a strict, comparable X500 format format.
     *
     * @param certificate the certificate to fetch the issuer DN for
     * @return the strict comparable X500 format format of the issuer.
     */
    public static String getIssuer(X509Certificate certificate) {
        return new X500Name(BCStyle.INSTANCE, certificate.getIssuerDN().toString()).toString();
    }

    /**
     * Returns the subject distinguished name in a strict, comparable X500 format format.
     *
     * @param certificate the certificate to fetch the subject DN for
     * @return the strict comparable X500 format format of the subject.
     */
    public static String getSubject(X509Certificate certificate) {
        return new X500Name(BCStyle.INSTANCE, certificate.getSubjectDN().toString()).toString();
    }

    /**
     * Returns first field value of a X500 name given the asn1 oid.
     * <p>
     * Example: getSubjectDNField("CN=Test User,O=TestOrt", BSStyle.CN) == "Test User"
     *
     * @param subject   the X500 name to parse a given field value of
     * @param fieldName Should be one of BCStyle field constants
     * @return the first found field value in the X500 name or null if no field value was found.
     */
    public static String getSubjectDNField(String subject, ASN1ObjectIdentifier fieldName) {
        if (subject == null) {
            return null;
        }
        for (RDN rDN : new X500Name(BCStyle.INSTANCE, subject).getRDNs(fieldName)) {
            AttributeTypeAndValue first = rDN.getFirst();
            return first.getValue().toString();
        }

        return null;
    }

    /**
     * Returns all field value of a X500 name given the asn1 oid.
     * <p>
     * Example: getSubjectDNField("CN=Test User,O=TestOrt", BSStyle.CN) == "Test User"
     *
     * @param subject   the X500 name to parse a given field value of
     * @param fieldName Should be one of BCStyle field constants
     * @return the all found field value in the X500 name or empty list if no field value was found.
     */
    public static List<String> getSubjectDNFields(String subject, ASN1ObjectIdentifier fieldName) {
        ArrayList<String> retval = new ArrayList<String>();

        if (subject == null) {
            return retval;
        }

        for (RDN rDN : new X500Name(BCStyle.INSTANCE, subject).getRDNs(fieldName)) {
            if (rDN.isMultiValued()) {
                AttributeTypeAndValue[] values = rDN.getTypesAndValues();
                for (AttributeTypeAndValue value : values) {
                    retval.add(value.getValue().toString());
                }
            } else {
                retval.add(rDN.getFirst().getValue().toString());
            }

        }

        return retval;
    }

    /**
     * Returns first field value of a X500 name given the asn1 oid.
     *
     * @param cert      having the subject X500 name to parse a given field value of
     * @param fieldName Should be one of BCStyle field constants
     * @return the first found field value in the X500 name or null if no field value was found.
     */
    public static String getSubjectDNField(X509Certificate cert, ASN1ObjectIdentifier fieldName) {
        if (cert == null) {
            return null;
        }
        return getSubjectDNField(getSubject(cert), fieldName);
    }

    /**
     * Gets a specified part of a DN. Specifically the first occurrence it the DN contains several
     * instances of a part (i.e. cn=x, cn=y returns x).
     *
     * @param dn     String containing DN, The DN string has the format "C=SE, O=xx, OU=yy, CN=zz".
     * @param dnpart String specifying which part of the DN to get, should be "CN" or "OU" etc.
     * @return String containing dnpart or null if dnpart is not present
     */
    public static String getPartFromDN(String dn, String dnpart) {
        log.info(">getPartFromDN: dn:'{}', dnpart={}", dn, dnpart);
        String part = null;
        if ((dn != null) && (dnpart != null)) {
            String o;
            dnpart += "="; // we search for 'CN=' etc.
            X509NameTokenizer xt = new X509NameTokenizer(dn);
            while (xt.hasMoreTokens()) {
                o = xt.nextToken();
                //log.debug("checking: "+o.substring(0,dnpart.length()));
                if ((o.length() > dnpart.length()) &&
                        o.substring(0, dnpart.length()).equalsIgnoreCase(dnpart)) {
                    part = o.substring(dnpart.length());

                    break;
                }
            }
        }
        log.info("<getpartFromDN: resulting DN part={}", part);
        return part;
    } //getPartFromDN

    /**
     * Returns true if the given CRL is a delta CRL, i.e have and extension Extensions.DeltaCRLIndicator
     *
     * @param crl the CRL to check
     * @return true if CRL is a delta CRL.
     */
    public static boolean isDeltaCRL(X509CRL crl) {
        if (crl == null) {
            return false;
        }
        return crl.getExtensionValue(Extension.deltaCRLIndicator.getId()) != null;
    }

    /**
     * Help method that reads the CRL number extension from an CRL, or returns null
     * if no CRL number extension could be found.
     *
     * @param crl the CRL to read the CRL number from
     * @return the CRL number or null if no CRL number could be found.
     * @throws CRLException if parsing of CRL failed.
     */
    public static Long readCRLNumberFromCRL(X509CRL crl) throws CRLException {
        if (crl == null) {
            return null;
        }

        try {
            byte[] extentionData = crl.getExtensionValue(Extension.cRLNumber.getId());
            if (extentionData != null) {
                ASN1Integer crlNumber = (ASN1Integer) X509ExtensionUtil.fromExtensionValue(extentionData);
                return crlNumber.getValue().longValue();
            }
            return null;
        } catch (Exception e) {
            throw new CRLException("bad encoding of CRL number in CRL.");
        }
    }

    /**
     * Help method to generate a Base64 encoded SHA-256 hash of a given certificate as a string to uniquely identify a certificate
     * in short.
     *
     * @param cert the certificate to generate fingerprint for.
     * @return a Base64 encoded SHA-256 hash of the certificate.
     * @throws NoSuchAlgorithmException     if hash algorithm wasn't found
     * @throws CertificateEncodingException if problems occurred encoding the certificate
     */
    public static String getCertFingerprint(X509Certificate cert) throws NoSuchAlgorithmException, CertificateEncodingException, UnsupportedEncodingException {
        MessageDigest md = getSHA256MessageDigest();
        md.reset();
        md.update(cert.getEncoded());
        return new String(Base64.encode(md.digest()), StandardCharsets.UTF_8);
    }
}
