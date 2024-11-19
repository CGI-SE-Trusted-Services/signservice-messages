/************************************************************************
 *                                                                       *
 *  Certificate Service - Administration Console                         *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.certificateservices.messages.utils;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * Certificate related utilities. Most of the method is copied from EJBCA 3.5 branch
 * since 3.9 and up is dependent of cvs libs that isn't necessary.
 *
 * @author Philip Vendil 22 Jan 2010
 * @version $Id$
 */

@SuppressWarnings( "deprecation" )
public class CertUtils {
    private static final Logger log = Logger.getLogger(CertUtils.class.getName());

	public static final  String BEGIN_CERTIFICATE_REQUEST  = "-----BEGIN CERTIFICATE REQUEST-----";
	public static final  String END_CERTIFICATE_REQUEST     = "-----END CERTIFICATE REQUEST-----";
	public static final String BEGIN_CERTIFICATE                = "-----BEGIN CERTIFICATE-----";
	public static final String END_CERTIFICATE                    = "-----END CERTIFICATE-----";
	public static final String BEGIN_PKCS7 = "-----BEGIN PKCS7-----";
	public static final String END_PKCS7 = "-----END PKCS7-----";

	// Line length must be below 76 characters according to RFC2045
	// http://www.ietf.org/rfc/rfc2045.txt
	public static final int BASE64_LINE_LENGTH = 64;

	public static final String GUID_OBJECTID = "1.3.6.1.4.1.311.25.1";
	public static final String KRB5PRINCIPAL_OBJECTID = "1.3.6.1.5.2.2";
	public static final String UPN_OBJECTID = "1.3.6.1.4.1.311.20.2.3";


	private static CertificateFactory certFact = null;
	public static CertificateFactory getCertificateFactory() throws NoSuchProviderException {
		if(certFact == null){
			certFact = new BCCertificateFactory();
		}
		return certFact;
	}

	/**
	 * Help method to find BC Provider
	 * @return the BouncyCastle provider
	 * @throws NoSuchProviderException if "BC" provider couldn't be found among installed providers.
	 */
	public static Provider getBCProvider() throws NoSuchProviderException{
		Provider bc = Security.getProvider("BC");
		if(bc == null){
			throw new NoSuchProviderException();
		}
		return bc;
	}




	/**
	 * Creates X509Certificate from byte[].
	 *
	 * @param cert byte array containing certificate in DER-format
	 *
	 * @return X509Certificate
	 *
	 * @throws CertificateException if the byte array does not contain a proper certificate.
	 * @throws IOException if the byte array cannot be read.
	 */
	public static X509Certificate getCertfromByteArray(byte[] cert)
			throws CertificateException {
		try{
			CertificateFactory cf = getCertificateFactory();
			X509Certificate x509cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(cert));
			if(x509cert == null){
				throw new CertificateException("Error invalid certificate data");
			}
			return x509cert;
		}catch(NoSuchProviderException e){
			throw new CertificateException("No such provider BC when creating certificate: " + e.getMessage());
		}
	}

	/**
	 * Converts certificate from binary DER-format into a PEM-encoded
	 * string that is safe to view in a text editor / send as an email.
	 * @param cert byte array containing certificate in DER-format
	 * @return Certificate in PEM-format (UTF8).
	 */
	public static String getPEMCertFromByteArray(byte[] cert){
		String pem = null;
		byte[] bytes = Base64.encode(cert);
		byte[] buf;
		pem = BEGIN_CERTIFICATE + "\n";
		for(int i=0,l=0;i<bytes.length;i++){
			if(l<BASE64_LINE_LENGTH){
				buf = new byte[]{bytes[i]};
				l++;
			} else{
				buf = new byte[]{'\n', bytes[i]};
				l=1;
			}
			pem += new String(buf, Charset.forName("UTF-8"));
		}
		pem = pem + "\n" + END_CERTIFICATE;

		return pem;
	}

	/**
	 * Converts certificate request from binary DER-format into a PEM-encoded
	 *
	 * @param certificateRequest related certificate request.
	 * @return pem formatted certificate request.
	 */
	public static String getPemCertificateRequestFromByteArray(byte[] certificateRequest){
		String pem = null;
		byte[] bytes = Base64.encode(certificateRequest);
		byte[] buf;
		pem = BEGIN_CERTIFICATE_REQUEST + "\n";
		for(int i=0,l=0;i<bytes.length;i++){
			if(l<BASE64_LINE_LENGTH){
				buf = new byte[]{bytes[i]};
				l++;
			} else{
				buf = new byte[]{'\n', bytes[i]};
				l=1;
			}
			pem += new String(buf, Charset.forName("UTF-8"));
		}
		pem = pem + "\n" + END_CERTIFICATE_REQUEST;

		return pem;
	}

	/**
	 * Creates X509CRL from byte[].
	 *
	 * @param crl byte array containing the encoded crl
	 *
	 * @return X509CRL
	 *
	 * @throws CertificateException if the byte array does not contain a proper crl.
	 * @throws IOException if the byte array cannot be read.
	 */
	public static X509CRL getCRLfromByteArray(byte[] crl)
			throws CRLException {
		try{
			CertificateFactory cf = getCertificateFactory();
			X509CRL x509crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(crl));
			if(x509crl == null){
				throw new CRLException("Error invalid crl data");
			}
			return x509crl;
		}catch(NoSuchProviderException e){
			throw new CRLException("No such provider BC when creating certificate: " + e.getMessage());
		}
	}


	/**
	 * Reads binary bytes from a PEM-file. The PEM-file may contain other stuff, the first item
	 * between beginKey and endKey is read. Example: <code>-----BEGIN CERTIFICATE REQUEST-----
	 * base64 encoded PKCS10 certification request -----END CERTIFICATE REQUEST----- </code>
	 *
	 * @param inbuf input buffer containing PEM-formatted stuff.
	 * @param beginKey begin line of PEM message
	 * @param endKey end line of PEM message
	 *
	 * @return byte[] containing binary Base64 decoded bytes.
	 *
	 * @throws IOException if the PEM file does not contain the correct data.
	 */
	public static byte[] getBytesFromPEM(byte[] inbuf, String beginKey, String endKey)
			throws IOException {

		if(inbuf == null){
			throw new IOException("Error, data was null in input buffer");
		}

		ByteArrayInputStream instream = new ByteArrayInputStream(inbuf);
		BufferedReader bufRdr = new BufferedReader(new InputStreamReader(instream));
		ByteArrayOutputStream ostr = new ByteArrayOutputStream();
		PrintStream opstr = new PrintStream(ostr);
		String temp;

		while (((temp = bufRdr.readLine()) != null) && !temp.equals(beginKey)) {
			continue;
		}

		if (temp == null) {
			throw new IOException("Error in input buffer, missing " + beginKey + " boundary");
		}

		while (((temp = bufRdr.readLine()) != null) && !temp.equals(endKey)) {
			opstr.print(temp);
		}

		if (temp == null) {
			throw new IOException("Error in input buffer, missing " + endKey + " boundary");
		}

		opstr.close();

		return Base64.decode(ostr.toByteArray());
	}

	/**
	 * Generates a pkcs10 of the given data or returns null if no valid p10 request could be found in the data.
	 * @param b64Encoded the data to parse
	 * @return the pkcs10 object or null if no valid pkcs10 could be found in the PEM data.
	 */
	public static PKCS10CertificationRequest genPKCS10RequestMessageFromPEM(byte[] b64Encoded){
		byte[] buffer = null;
		try {
			// A real PKCS10 PEM request
			String beginKey = BEGIN_CERTIFICATE_REQUEST;
			String endKey = END_CERTIFICATE_REQUEST;
			buffer = getBytesFromPEM(b64Encoded, beginKey, endKey);
		} catch (IOException e) {
			try {
				// Keytool PKCS10 PEM request
				String beginKey = "-----BEGIN NEW CERTIFICATE REQUEST-----";
				String endKey = "-----END NEW CERTIFICATE REQUEST-----";
				buffer = getBytesFromPEM(b64Encoded, beginKey, endKey);
			} catch (IOException ioe) {
				// IE PKCS10 Base64 coded request
				try{
					buffer = Base64.decode(b64Encoded);
				}catch(Exception ignored){}
			}
		}
		if (buffer == null) {
			return null;
		}

		PKCS10CertificationRequest retval = null;
		try{
			retval = new PKCS10CertificationRequest(buffer);
		}catch(IllegalArgumentException e){}

		return retval;
	}

	/**
	 * Method used to get the certificate for binary data and try different encodings to parse the certificate.
	 * @param certData the certificate data.
	 * @return the certificate or null of no certificate could be parsed.
	 */
	public static X509Certificate getX509CertificateFromPEMorDER(byte[] certData){
		if(certData == null){
			return null;
		}
		X509Certificate retval = null;
		try{
			retval = getCertfromByteArray(certData);
		}catch(CertificateException ignored){}

		if(retval == null){
			try{
				retval = getCertfromByteArray(getBytesFromPEM(certData, BEGIN_CERTIFICATE, END_CERTIFICATE));
			}catch(IOException | CertificateException ignored){
			}
		}
		return retval;
	}

	/**
	 * Method that installs the BC provider into java. Should be called
	 * once in the initialisation phase of the application.
	 */
	public static synchronized void installBCProvider() {
		Security.removeProvider("BC");
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Help method used to normalise a subject string to a standard BC style X500Name
	 * @param subject the subject name to normalise
	 * @return the strict comparable X500 format format of the issuer.
	 */
	public static String getNormalizedSubject(String subject){
		if(subject == null){
			return null;
		}
		return new X500Name(BCStyle.INSTANCE, subject).toString();
	}

	/**
	 * Help method used to convert a DN string to a standard BC style X500Name
	 * @param dNName the DN name to convert
	 * @return the strict comparable X500 format format of the name
	 */
	public static X500Name toX500Name(String dNName){
		if(dNName == null){
			return null;
		}
		return new X500Name(BCStyle.INSTANCE, dNName);
	}

	/**
	 * Returns the issuer distinguished name in a strict, comparable X500 format format.
	 * @param certificate the certificate to fetch the issuer DN for
	 * @return the strict comparable X500 format format of the issuer.
	 */
	public static String getIssuer(X509Certificate certificate){
		return new X500Name(BCStyle.INSTANCE, certificate.getIssuerDN().toString()).toString();
	}

	/**
	 * Returns the issuer distinguished name in a strict, comparable X500 format format.
	 * @param crl the CRL to fetch the issuer DN for
	 * @return the strict comparable X500 format format of the issuer.
	 */
	public static String getIssuer(X509CRL crl){
		return new X500Name(BCStyle.INSTANCE, crl.getIssuerDN().toString()).toString();
	}

	/**
	 * Returns the subject distinguished name in a strict, comparable X500 format format.
	 * @param certificate the certificate to fetch the subject DN for
	 * @return the strict comparable X500 format format of the subject.
	 */
	public static String getSubject(X509Certificate certificate){
		return new X500Name(BCStyle.INSTANCE, certificate.getSubjectDN().toString()).toString();
	}


	/**
	 * Returns the subject distinguished name in a strict, comparable X500 format format.
	 * @param certRequest the DER encoded certificate request to fetch the subject DN for.
	 * @return the strict comparable X500 format format of the subject.
	 */
	public static String getSubjectDNFromCSR(byte[] certRequest){
		PKCS10CertificationRequest pkcs10CertificationRequest = new PKCS10CertificationRequest(certRequest);
		return pkcs10CertificationRequest.getCertificationRequestInfo().getSubject().toString();
	}

	/**
	 * Method that converts a certificate to a BC certificate if needed.
	 */
	public static X509Certificate normalizeCertificate(X509Certificate certificate){
		if(!(certificate.getClass().getName().contains("bouncycastle"))){
			try {
				certificate = (X509Certificate) getCertificateFactory().generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
			} catch (CertificateException e) {
				log.log(Level.SEVERE,"Error parsing certificate when extracting issuer dn: " + e.getMessage(),e);
			} catch (NoSuchProviderException e) {
				log.log(Level.SEVERE,"Error BC Provider not found when extracting issuer dn: " + e.getMessage(),e);
			}
		}

		return certificate;
	}

	/**
	 * Method used to check if two x500 name are equal.
	 *
	 * @param x500Name1 the subject or issuer to compare.
	 * @param x500Name2 the subject or issuer to compare.
	 */
	public static boolean isDNsEqual(String x500Name1, String x500Name2){
		return BCStyle.INSTANCE.areEqual(new X500Name(BCStyle.INSTANCE,x500Name1), new X500Name(BCStyle.INSTANCE,x500Name2));
	}

	/**
	 * Method to strictly calculate a hashcode of a X500 Name
	 *
	 * @param x500Name the subject or issuer distinguished name to calculate hashcode for.
	 * @return the hashcode or 0 if X500Name is null.
	 */
	public static int getDNHashCode(String x500Name){
		if(x500Name == null){
			return 0;
		}

		return BCStyle.INSTANCE.calculateHashCode(new X500Name(BCStyle.INSTANCE,x500Name));
	}




	/**
	 * Returns first field value of a X500 name given the asn1 oid.
	 *
	 * Example: getSubjectDNField("CN=Test User,O=TestOrt", BSStyle.CN) == "Test User"
	 *
	 * @param subject the X500 name to parse a given field value of
	 * @param fieldName Should be one of BCStyle field constants
	 * @return the first found field value in the X500 name or null if no field value was found.
	 */
	public static String getSubjectDNField(String subject, ASN1ObjectIdentifier fieldName){
		if(subject == null){
			return null;
		}
		for(RDN rDN : new X500Name(BCStyle.INSTANCE,subject).getRDNs(fieldName)){
			AttributeTypeAndValue first = rDN.getFirst();
			return first.getValue().toString();
		}

		return null;
	}

	/**
	 * Returns all field value of a X500 name given the asn1 oid.
	 *
	 * Example: getSubjectDNField("CN=Test User,O=TestOrt", BSStyle.CN) == "Test User"
	 *
	 * @param subject the X500 name to parse a given field value of
	 * @param fieldName Should be one of BCStyle field constants
	 * @return the all found field value in the X500 name or empty list if no field value was found.
	 */
	public static List<String> getSubjectDNFields(String subject, ASN1ObjectIdentifier fieldName){


		ArrayList<String> retval = new ArrayList<String>();

		if(subject == null){
			return retval;
		}

		for(RDN rDN : new X500Name(BCStyle.INSTANCE,subject).getRDNs(fieldName)){
			if(rDN.isMultiValued()){
				AttributeTypeAndValue[] values = rDN.getTypesAndValues();
				for(int i=0;i<values.length; i++){
					retval.add(values[i].getValue().toString());
				}
			}else{
				retval.add(rDN.getFirst().getValue().toString());
			}

		}

		return retval;
	}

	/**
	 * Returns first field value of a X500 name given the asn1 oid.
	 *
	 *
	 * @param cert having the subject X500 name to parse a given field value of
	 * @param fieldName Should be one of BCStyle field constants
	 * @return the first found field value in the X500 name or null if no field value was found.
	 */
	public static String getSubjectDNField(X509Certificate cert, ASN1ObjectIdentifier fieldName){
		if(cert == null){
			return null;
		}
		return getSubjectDNField(getSubject(cert), fieldName);
	}

	/**
	 * Help method used to fetch the unique identity of a certificate. i.e '<cert serialnumber in hex>;<issuerdn>'
	 * @param cert the certificate to fetch unique identity of.
	 * @return a uniqu string of the certificate or null if cert was null.
	 */
	public static String getCertificateUniqueId(X509Certificate cert){
		if(cert == null){
			return null;
		}

		return cert.getSerialNumber().toString(16) + ";" + getIssuer(cert);
	}


	/**
	 * Returns the first subject dnField of the specified type from a subject DN
	 * @param dnField the subject dn field to use.
	 * @param subjectDN the dn to lookup.
	 * @return the dn field of subject or null if no value is found.
	 */
	public static String getFirstSubjectField(ASN1ObjectIdentifier dnField, String subjectDN){
		if(dnField == null || subjectDN == null || subjectDN.trim().equals("")){
			return null;
		}

		String retval = null;
		for(RDN rDN : new X500Name(BCStyle.INSTANCE,subjectDN).getRDNs(dnField)){
			AttributeTypeAndValue first = rDN.getFirst();
			retval=  first.getValue().toString();
			break;
		}
		return retval;
	}


	/**
	 * @param cert the certificate to fetch certificate serial number from.
	 * @return the serial number of a certificate is Hex encoded string, lower-case.
	 * @throws IllegalArgumentException if unsupported Certificate or parameter was null.
	 */
	public static String getCertSerialnumberAsString(Certificate cert) throws IllegalArgumentException{
		if(cert != null && cert instanceof X509Certificate){
			return ((X509Certificate) cert).getSerialNumber().toString(16).toLowerCase();
		}
		throw new IllegalArgumentException("Illegal certificate type or 'null' certificate specified when parsing serial number.");
	}



	/**
	 * Help method that fetches the first email address subject alternative name from
	 * the certificate or null of no email address could be found.
	 * @param certificate the certificate to find email address from subject alternative name.
	 * @return the email address or null if no found.
	 */
    public static String getEmailFromAlternativeName(X509Certificate certificate) throws CertificateParsingException {
        if (certificate != null) {
            if (certificate.getSubjectAlternativeNames() != null) {

                for (List<?> objects : certificate.getSubjectAlternativeNames()) {
                    Integer type = (Integer) objects.get(0);
                    if (type == 1) {
                        return (String) objects.get(1);
                    }
                }
            }
        }
        return null;
    }

	/**
	 * Returns true if the given CRL is a delta CRL, i.e have and extension  X509Extensions.DeltaCRLIndicator
	 * @param crl the CRL to check
	 * @return true if CRL is a delta CRL.
	 */
	public static boolean isDeltaCRL(X509CRL crl){	
		if(crl == null){
			return false;
		}
		return crl.getExtensionValue(X509Extension.deltaCRLIndicator.getId()) != null;		
	}

	/**
	 * Help method that reads the CRL number extension from an CRL, or returns null
	 * if no CRL number extension could be found.
	 * @param crl the CRL to read the CRL number from
	 * @return the CRL number or null if no CRL number could be found.
	 * @throws CRLException if parsing of CRL failed.
	 */
	public static Long readCRLNumberFromCRL(X509CRL crl) throws CRLException{
		if(crl == null){
			return null;
		}

		try {
			byte[] extentionData = crl.getExtensionValue(X509Extension.cRLNumber.getId());
			if(extentionData != null){
				ASN1Integer crlNumber = (ASN1Integer) X509ExtensionUtil.fromExtensionValue(extentionData);
				return crlNumber.getValue().longValue();
			}
			return null;
		} catch (Exception e) {
			throw new CRLException("bad encoding of CRL number in CRL.");
		}
	}


	/**
	 * Returns the Microsoft specific GUID altName, that is encoded as an octect string.
	 *
	 * @param cert certificate containing the extension
	 * @return String with the hex-encoded GUID byte array or null if the altName does not exist
	 */
	public static String getGUIDFromAlternativeName(X509Certificate cert)
			throws IOException, CertificateParsingException {
		if (cert != null) {
			Collection<?> altNames = cert.getSubjectAlternativeNames();
			if (altNames != null) {
				for (Object altName : altNames) {
					ASN1Sequence seq = getAltnameSequence((List<?>) altName);
					String retval = getGUIDStringFromSequence(seq);
					if (retval != null) {
						return retval;
					}
				}
			}
		}
		return null;
	}

	/** 
	 * Helper method for fetching the GUID alternative name.
	 * @param seq the OtherName sequence
	 */
	private static String getGUIDStringFromSequence(ASN1Sequence seq) {
		if (seq != null) {
			// First in sequence is the object identifier, that we must check
			ASN1ObjectIdentifier id = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
			if (id.getId().equals(GUID_OBJECTID)) {
				ASN1TaggedObject obj = (ASN1TaggedObject) seq.getObjectAt(1);
				ASN1OctetString str = ASN1OctetString.getInstance(obj.getBaseObject());
				return new String(Hex.encode(str.getOctets()));
			}
		}
		return null;
	}

	/** 
	 * Help method for fetching alternative name from an ASN1Sequence
	 */
	private static ASN1Sequence getAltnameSequence(List<?> listitem) throws IOException {
		Integer no = (Integer) listitem.get(0);
		if (no == 0) {
			byte[] altName = (byte[]) listitem.get(1);
			return getAltnameSequence(altName);
		}
		return null;
	}

	/**
	 * Help method for fetching alternative name from an ASN1Sequence
	 */
	private static ASN1Sequence getAltnameSequence(byte[] value) throws IOException {
		ASN1Object oct = null;
		try (ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(value))) {
			oct = ais.readObject();
		} catch (IOException e) {
			throw new RuntimeException("Could not read ASN1InputStream", e);
		}

		if (oct instanceof ASN1TaggedObject) {
			oct = ((ASN1TaggedObject)oct).getBaseObject();
		}
		return ASN1Sequence.getInstance(oct);
	}

	/**
	 * Gets a specified part of a DN. Specifically the first occurrence it the DN contains several
	 * instances of a part (i.e. cn=x, cn=y returns x).
	 *
	 * @param dn String containing DN, The DN string has the format "C=SE, O=xx, OU=yy, CN=zz".
	 * @param dnpart String specifying which part of the DN to get, should be "CN" or "OU" etc.
	 *
	 * @return String containing dnpart or null if dnpart is not present
	 */
	public static String getPartFromDN(String dn, String dnpart) {
		log.fine(">getPartFromDN: dn:'" + dn + "', dnpart=" + dnpart);
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
		log.fine("<getpartFromDN: resulting DN part=" + part);
		return part;
	} //getPartFromDN


	/**
	 * Checks if a certificate is self signed by verifying if subject and issuer are the same.
	 *
	 * @param cert the certificate that shall be checked.
	 *
	 * @return boolean true if the certificate has the same issuer and subject, false otherwise.
	 */
	public static boolean isSelfSigned(X509Certificate cert) {
		log.fine(">isSelfSigned: cert: " + CertUtils.getIssuer(cert) + "\n" +
				CertUtils.getSubject(cert));

		boolean ret = CertUtils.getSubject(cert).equals(CertUtils.getIssuer(cert));
		log.fine("<isSelfSigned:" + ret);

		return ret;
	} // isSelfSigned

	/**
	 * Builds a certificate chain for given certificate set
	 *
	 * @param certificates - list of certificates from end to root CA to build a chain.
	 *
	 * @return the certificate chain if it is built successfully.
	 * @throws GeneralSecurityException- if certification path cannot be built.
	 */
	public static List<X509Certificate> buildCertificateChain(Collection<X509Certificate> certificates) throws GeneralSecurityException{


		List< X509Certificate> resultChain = new ArrayList<>();
		List<X509Certificate> certificateList = new ArrayList<>(certificates);
		if(certificateList.size()==1){
			if(isSelfSigned(certificateList.get(0))){
				resultChain.add(certificateList.get(0));
				return resultChain;
			}else {
				throw new GeneralSecurityException("Bad Certificate chain: certificate chain in not complete");

			}
        } else if (certificateList.isEmpty()) {
			throw new GeneralSecurityException("Bad Certificate chain: certificate chain in empty");
		}
		Set<X509Certificate> rootCAs = new HashSet<>();
		Set<X509Certificate> subCAs= new HashSet<>();
		X509Certificate cert =null;
		boolean certExists = false;
		for(X509Certificate certificate : certificates){
			if(isSelfSigned(certificate)){
				rootCAs.add(certificate);

			}else{

				boolean isSubCa = false;
				for(X509Certificate c : certificates){
					if((CertUtils.getIssuer(c)).equalsIgnoreCase(CertUtils.getSubject(certificate))){
						isSubCa= true;
						subCAs.add(certificate);

						break;
					}
				}


				if(!isSubCa && !certExists){
					cert = certificate;
					certExists=true;

                } else if (!isSubCa) {

					throw new GeneralSecurityException("Bad Certificate chain: more than one end certificates exist in the chain.");
				}

			}
		}
		if(rootCAs.isEmpty() && (!subCAs.isEmpty() || cert!=null )){
			throw new GeneralSecurityException("Bad Certificate chain: Root CA does not exist in the chain.");
		}
		// Selector for starting certificate
		X509CertSelector selector = new X509CertSelector();
		selector.setCertificate(cert);
		Set<TrustAnchor> trustAnchors = new HashSet<>();
		//Trust Anchors
		for(X509Certificate trustCertificate : rootCAs){
			trustAnchors.add(new TrustAnchor(trustCertificate, null));
		}

		subCAs.add(cert);
		//Certificate stores for intermediary sub Cas
		CertStore subCAStore =  CertStore.getInstance("Collection",new CollectionCertStoreParameters(subCAs),"BC");

		PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustAnchors, selector);
		pkixParams.addCertStore(subCAStore);
		pkixParams.setRevocationEnabled(false);



		CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
		PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder.build(pkixParams);
		for(Certificate c :result.getCertPath().getCertificates()){
			resultChain.add((X509Certificate)c);

		}
		int subCAChainlength=resultChain.size();

		for(X509Certificate rootCA : rootCAs){
			if((CertUtils.getIssuer(resultChain.get(subCAChainlength-1))).equalsIgnoreCase(CertUtils.getSubject(rootCA))){
				resultChain.add(rootCA);
				break;
			}
		}


		return resultChain;


	}

	/**
	 * Creates List of X509Certificate from byte[].
	 *
	 * @param certChain array containing certificate chain in PEM-format
	 *
	 * @return List<X509Certificate>
	 *
	 * @throws CertificateException if the byte array does not contain proper certificate chain.
	 * @throws IOException if the byte array cannot be read.
	 */
	public static List<X509Certificate> getCertificateChainfromPem(byte[] certChain) throws CertificateException, IOException {
		List<X509Certificate> ret = new ArrayList<>();

		try (BufferedReader bufRdr = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(certChain)))) {
			String temp;
			while ((temp = bufRdr.readLine()) != null) {
				while (temp != null && !temp.equals(BEGIN_CERTIFICATE)) {
					temp = bufRdr.readLine();
				}

				if (temp == null) {
					if (ret.isEmpty()) {
						throw new IOException("Error in input buffer, missing " + BEGIN_CERTIFICATE + " boundary");
					} else {
						break; // End of file reached after processing some certificates
					}
				}

				try (ByteArrayOutputStream ostr = new ByteArrayOutputStream();
					 PrintStream opstr = new PrintStream(ostr, true)) {

					while ((temp = bufRdr.readLine()) != null && !temp.equals(END_CERTIFICATE)) {
						opstr.print(temp);
					}

					if (temp == null) {
						throw new IOException("Error in input buffer, missing " + END_CERTIFICATE + " boundary");
					}

					byte[] certbuf = Base64.decode(ostr.toByteArray());
					X509Certificate certificate = getCertfromByteArray(certbuf);
					ret.add(certificate);
				}
			}
		}
		return ret;
	}

	/**
	 * Helper method to read public key length from certificate.
	 *
	 * @param certificate Certificate
	 * @return public key length
	 * @throws CertificateException if problem occurs when getting public key length from certificate.
	 */
	public static int getPublicKeyLengthFromCertificate(Certificate certificate) throws CertificateException {
		int bitLength = -1;

		if (certificate == null) {
			throw new NullPointerException("Certificate is null");
		}

		try {
			if (certificate.getPublicKey() instanceof RSAPublicKey) {
				bitLength = ((RSAPublicKey) certificate.getPublicKey()).getModulus().bitLength();
			} else if (certificate.getPublicKey() instanceof ECPublicKey) {
				bitLength = ((ECPublicKey) certificate.getPublicKey()).getParams().getCurve().getField().getFieldSize();
			} else if (certificate.getPublicKey() instanceof DSAPublicKey) {
				bitLength = ((DSAPublicKey) certificate.getPublicKey()).getParams().getP().bitLength();
			}
		} catch (Exception e) {
			throw new CertificateException(e);
		}

        return bitLength;
    }

    /**
     * Helper method to create a certFingerprint as a Base64 encoded SHA-256 string.
     * This method maintains backward compatibility and uses SHA-256 by default.
     *
     * @param certificate the certificate to generate fingerprint of.
     * @return Base64 encoded SHA-256 fingerprint as a string.
     * @throws CertificateException if an encoding error occurs.
     */
    public static String genCertFingerprint(X509Certificate certificate) throws CertificateException {
        return genCertFingerprint(certificate, "SHA-256");
    }

    /**
     * Helper method to create a certFingerprint as a Base64 encoded string using the specified algorithm.
     *
     * @param certificate the certificate to generate fingerprint of.
     * @param algorithm   the hash algorithm to use ("SHA-1", "SHA-256", etc.).
     * @return Base64 encoded fingerprint as a string.
     * @throws CertificateException if an encoding error occurs.
     */
    public static String genCertFingerprint(X509Certificate certificate, String algorithm) throws CertificateException {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] digest = md.digest(certificate.getEncoded());
            return new String(org.bouncycastle.util.encoders.Base64.encode(digest));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Internal Error constructing " + algorithm + " Digest: " + e.getMessage(), e);
        }
    }

    /**
     * Generates a certificate fingerprint (thumbprint) as an uppercase hexadecimal string using the specified hash algorithm.
     *
     * @param certificateData the certificate data as a byte array
     * @param algorithm       the hash algorithm to use (e.g., "SHA-1", "SHA-256")
     * @return the certificate fingerprint as an uppercase hexadecimal string
     * @throws RuntimeException if the specified algorithm is not available
     */
    public static String genCertFingerprint(byte[] certificateData, String algorithm) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] digest = md.digest(certificateData);
            return new String(Hex.encode(digest)).toUpperCase();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Internal error constructing " + algorithm + " digest: " + e.getMessage(), e);
        }
    }

    /**
     * Method returning true if related certificate is a CA Certificate.
     *
     * @param certificate the certificate to check
     * @return true if related certificate is a CA certificate.
     */
    public static boolean isCACert(X509Certificate certificate) {
        return certificate.getBasicConstraints() != -1;
    }

	/**
	 * Generates a key pair using the specified algorithm and key size.
	 *
	 * @param algorithm the name of the algorithm (e.g., "RSA").
	 * @param keySize   the key size in bits.
	 * @return a KeyPair containing the generated public and private keys.
	 * @throws NoSuchAlgorithmException if the specified algorithm is not available.
	 */
	public static KeyPair generateKeyPair(String algorithm, int keySize) throws NoSuchAlgorithmException {
		if (algorithm == null || algorithm.isEmpty()) {
			throw new IllegalArgumentException("Algorithm must not be null or empty.");
		}
		if (keySize <= 0) {
			throw new IllegalArgumentException("Key size must be a positive integer.");
		}

		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
			keyPairGenerator.initialize(keySize, new SecureRandom());
			return keyPairGenerator.generateKeyPair();
		} catch(Exception e){
			log.log(Level.SEVERE, "ERROR when generating keypair: " + e.getMessage());
		}

		return null;
	}

	/**
	 * Generates a PKCS#10 certification request.
	 *
	 * @param dn          the distinguished name for the certificate subject.
	 * @param publicKey   the public key to include in the request.
	 * @param privateKey  the private key used to sign the request.
	 * @param namesList   a list of GeneralName objects for Subject Alternative Names.
	 * @return a PKCS10CertificationRequest object representing the CSR.
	 * @throws Exception if an error occurs during request generation.
	 */
	public static org.bouncycastle.pkcs.PKCS10CertificationRequest generatePKCS10(
			String dn,
			PublicKey publicKey,
			PrivateKey privateKey,
			List<GeneralName> namesList) throws Exception {

		if (dn == null || publicKey == null || privateKey == null) {
			throw new IllegalArgumentException("Distinguished Name, Public Key, and Private Key must not be null.");
		}

		PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
				new X500Principal(dn), publicKey);

		JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		ContentSigner signer = csBuilder.build(privateKey);

		if (namesList != null && !namesList.isEmpty()) {
			ExtensionsGenerator extGen = new ExtensionsGenerator();
			GeneralNames subjectAltNames = new GeneralNames(namesList.toArray(new GeneralName[0]));
			extGen.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
			p10Builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
		}

		return p10Builder.build(signer);
	}
}
