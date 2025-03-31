/************************************************************************
*                                                                       *
*  Certificate Service - Common                                         *
*                                                                       *
*  This software is free software; you can redistribute it and/or       *
*  modify it under the terms of the GNU Lesser General Public License   *
*  License as published by the Free Software Foundation; either         *
*  version 3   of the License, or any later version.                    *
*                                                                       *
*  See terms of license at gnu.org.                                     *
*                                                                       *
*************************************************************************/
package se.signatureservice.messages.utils

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.jce.PKCS10CertificationRequest
import org.bouncycastle.util.encoders.Base64
import spock.lang.Specification

import java.security.cert.CertificateFactory
import java.security.cert.X509CRL
import java.security.cert.X509Certificate

@SuppressWarnings("deprecation")
class CertUtilsSpec extends Specification{

	def setup(){
		CertUtils.installBCProvider()

		certWithManyExtenstions = CertUtils.getCertfromByteArray(Base64.decode(base64LotOfExtensitonsCert))
		certWithFewExtenstions = CertUtils.getCertfromByteArray(Base64.decode(base64Cert))
	}


	def "test GetCertificateFactory"(){
		expect:
		CertUtils.getCertificateFactory() != null
		CertUtils.getCertificateFactory() instanceof CertificateFactory
	}


	def "test GetCertfromByteArray"(){
		expect:

		CertUtils.getCertfromByteArray(Base64.decode(base64Cert)) != null
		CertUtils.getCertfromByteArray(Base64.decode(base64Cert)) instanceof X509Certificate

	}


	def "test GetCRLfromByteArray"(){
		expect:
		CertUtils.getCRLfromByteArray(Base64.decode(base64CrlData)) != null
		CertUtils.getCRLfromByteArray(Base64.decode(base64CrlData)) instanceof X509CRL
	}

	def "test GetBytesFromPEM"(){
		when:
		byte[] data = CertUtils.getBytesFromPEM(pEMCert, CertUtils.BEGIN_CERTIFICATE, CertUtils.END_CERTIFICATE)
		then:
		data != null
		data instanceof byte[]
		CertUtils.getCertfromByteArray(data) instanceof X509Certificate

		when:
		CertUtils.getBytesFromPEM(base64Cert, CertUtils.BEGIN_CERTIFICATE, CertUtils.END_CERTIFICATE)
		then:
		thrown IOException
	}

	def "test GenPKCS10RequestMessageFromPEM"() {
		when:
		PKCS10CertificationRequest p10 = CertUtils.genPKCS10RequestMessageFromPEM(pEMPKCS10)
		then:
		p10 != null

		CertUtils.genPKCS10RequestMessageFromPEM(null) == null
		CertUtils.genPKCS10RequestMessageFromPEM(pEMCert) == null
	}

	def "test GetX509CertificateFromPEMorDER"() {
		expect:
		CertUtils.getX509CertificateFromPEMorDER(pEMCert) != null
		CertUtils.getX509CertificateFromPEMorDER(pEMCert)  instanceof X509Certificate
		when:
		byte[] certData = Base64.decode(base64Cert)
		then:
		CertUtils.getX509CertificateFromPEMorDER(certData) != null
		CertUtils.getX509CertificateFromPEMorDER(certData)  instanceof X509Certificate

		CertUtils.getX509CertificateFromPEMorDER(pEMPKCS10) == null
		CertUtils.getX509CertificateFromPEMorDER(null) == null
	}

	def "test GetIssuer for certificate"() {
		when:
		X509Certificate cert = CertUtils.getX509CertificateFromPEMorDER(Base64.decode(base64Cert))
		String issuerDN = CertUtils.getIssuer(cert)
		then:
		issuerDN.equals("CN=Test eIDCA,O=Test")
	}

	def "test GetIssuer for crl"() {
		when:
		def crl = CertUtils.getCRLfromByteArray(cRLData)
		String issuerDN = CertUtils.getIssuer(crl)
		then:
		issuerDN.equals("CN=Logica SE IM Certificate Service ST ServerCA,O=Logica SE IM Certificate Service ST")
	}

	def "test GetSubject"() {
		when:
		X509Certificate cert = CertUtils.getX509CertificateFromPEMorDER(Base64.decode(base64Cert))
		String issuerDN = CertUtils.getSubject(cert)
		then:
		issuerDN.equals("CN=Test eIDCA,O=Test")
	}

    def "test GetNormalizeSubject"() {
		expect:
		CertUtils.getNormalizedSubject(null) == null
		CertUtils.getNormalizedSubject("CN=Test") == "CN=Test"
		CertUtils.getNormalizedSubject("O=ASDF, CN=Test") == "O=ASDF,CN=Test"
	}


	def "test toX500Name"() {
		expect:
		CertUtils.toX500Name(null) == null
		CertUtils.toX500Name("CN=Test") instanceof X500Name
		CertUtils.toX500Name("CN=Test").toString() == "CN=Test"
		CertUtils.toX500Name("O=ASDF, CN=Test").toString() == "O=ASDF,CN=Test"
	}

	def "test IsDNsEqual"() {
		expect:
		CertUtils.isDNsEqual("CN=Test eIDCA,O=Test","CN=Test eIDCA,O=Test")
		CertUtils.isDNsEqual("CN=Test eIDCA,givenNAme=Test, surname=eIDCS, serialNumber=123456,O=Test,c=SE","CN=Test eIDCA,GIVENNAME=Test,SURNAME=eIDCS,SERIALNUMBER=123456,O=Test,C=SE")
		CertUtils.isDNsEqual("serialNumber=123456, c=SE,O=Test, surname=eIDCS,givenNAme=Test, CN=Test eIDCA ","serialNumber=123456, c=SE,O=Test, surname=eIDCS,CN=Test eIDCA ,givenNAme=Test  ")
		!CertUtils.isDNsEqual("serialNumber=123456, c=SE,O=Test, surname=eIDCS,givenNAme=Test, CN=Test eIDCA ","serialNumber=123456, c=SE,O=Test, surname=eIDCS,CN=Test eIDCA ,givenNAme=Test2  ")
		when:
		CertUtils.isDNsEqual(null,null)
		then:
		thrown NullPointerException
	}

	def "test GetDNHashCode"() {
		expect:
		CertUtils.getDNHashCode(null) == 0
		CertUtils.getDNHashCode("CN=Test eIDCA,O=Test") == 255062283

		CertUtils.getDNHashCode("CN=Test eIDCA,givenNAme=Test, surname=eIDCS, serialNumber=123456,O=Test,c=SE") == CertUtils.getDNHashCode("CN=Test eIDCA,GIVENNAME=Test,SURNAME=eIDCS,SERIALNUMBER=123456,O=Test,C=SE")
		CertUtils.getDNHashCode("serialNumber=123456, c=SE,O=Test, surname=eIDCS,givenNAme=Test, CN=Test eIDCA ") == CertUtils.getDNHashCode("serialNumber=123456, c=SE,O=Test, surname=eIDCS,CN=Test eIDCA ,givenNAme=Test  ")
		CertUtils.getDNHashCode("serialNumber=123456, c=SE,O=Test, surname=eIDCS,givenNAme=Test, CN=Test eIDCA ") != CertUtils.getDNHashCode("serialNumber=123456, c=SE,O=Test, surname=eIDCS,CN=Test eIDCA ,givenNAme=Test2  ")
	}


	def "test GetSubjectDNField"() {
		expect:
		CertUtils.getSubjectDNField((String) null, null) == null
		CertUtils.getSubjectDNField((String) null, BCStyle.CN) == null
		CertUtils.getSubjectDNField("CN=Test eIDCA,givenNAme=Test, surname=eIDCS, serialNumber=123456,O=Test,c=SE", BCStyle.INITIALS) == null
		CertUtils.getSubjectDNField("CN=Test eIDCA,givenNAme=Test, surname=eIDCS, serialNumber=123456,O=Test,c=SE", BCStyle.CN).equals("Test eIDCA")
		CertUtils.getSubjectDNField("CN=Test eIDCA,givenNAme=Test, surname=eIDCS, serialNumber=123456,O=Test,c=SE", BCStyle.C).equals("SE")
		CertUtils.getSubjectDNField("CN=Test eIDCA1,CN=Test eIDCA2,CN=Test eIDCA3,givenNAme=Test, surname=eIDCS, serialNumber=123456,O=Test,c=SE", BCStyle.CN).equals("Test eIDCA1")

		when:
		X509Certificate cert = CertUtils.getX509CertificateFromPEMorDER(Base64.decode(base64Cert))
		then:
		CertUtils.getSubjectDNField((X509Certificate) null, null) == null
		CertUtils.getSubjectDNField((X509Certificate) null, BCStyle.CN) == null
		CertUtils.getSubjectDNField(cert, BCStyle.CN).equals("Test eIDCA")
	}


	def "test GetSubjectDNFields"() {
		expect:
		CertUtils.getSubjectDNFields((String) null, null).size() == 0
		CertUtils.getSubjectDNFields((String) null, BCStyle.CN).size() == 0
		CertUtils.getSubjectDNFields("CN=Test eIDCA,givenNAme=Test, surname=eIDCS, serialNumber=123456,O=Test,c=SE", BCStyle.INITIALS).size() == 0
		CertUtils.getSubjectDNFields("CN=Test eIDCA,givenNAme=Test, surname=eIDCS, serialNumber=123456,O=Test,c=SE", BCStyle.CN).size() == 1
		CertUtils.getSubjectDNFields("CN=Test eIDCA,givenNAme=Test, surname=eIDCS, serialNumber=123456,O=Test,c=SE", BCStyle.CN).get(0) == "Test eIDCA"
		CertUtils.getSubjectDNFields("CN=Test eIDCA,givenNAme=Test, surname=eIDCS, serialNumber=123456,O=Test,c=SE", BCStyle.C).get(0) == "SE"
		CertUtils.getSubjectDNFields("CN=Test eIDCA,givenNAme=Test, surname=eIDCS, serialNumber=123456,O=Test,c=SE", BCStyle.C).size() == 1

		when:
		List<String> fieldValues = CertUtils.getSubjectDNFields("CN=Test eIDCA1,CN=Test eIDCA2,CN=Test eIDCA3,givenNAme=Test, surname=eIDCS, serialNumber=123456,O=Test,c=SE", BCStyle.CN)
		then:
		fieldValues[0] == "Test eIDCA1"
		fieldValues[1] == "Test eIDCA2"
		fieldValues[2] == "Test eIDCA3"
	}


	def "test GetCertificateUniqueId"() {
		expect:
		CertUtils.getCertificateUniqueId(null) == null
		when:
		X509Certificate cert = CertUtils.getX509CertificateFromPEMorDER(Base64.decode(base64Cert))
		then:
		CertUtils.getCertificateUniqueId(cert) == "62654feb143fb774;CN=Test eIDCA,O=Test"
	}

	def "test GetGUIDFromAlternativeName"() {
		expect:
		CertUtils.getGUIDFromAlternativeName(CertUtils.getX509CertificateFromPEMorDER(Base64.decode(base64Cert))) == null
		when:
		X509Certificate certWithGuid = CertUtils.getX509CertificateFromPEMorDER(Base64.decode(base64LotOfExtensitonsCert))
		then:
		CertUtils.getGUIDFromAlternativeName(certWithGuid) == "123654123654123654"
	}

	def "test getEmailFromAlternativeName"() {
		expect:
		CertUtils.getEmailFromAlternativeName(null) == null
		when:
		X509Certificate certWithEmail= CertUtils.getX509CertificateFromPEMorDER(pemWithEmailSAN)
		then:
		CertUtils.getEmailFromAlternativeName(certWithEmail) == "test@test.com"
		CertUtils.getEmailFromAlternativeName(certWithFewExtenstions) == null
	}

	def "test GetCertSerialnumberAsString"()  {
		when:
		CertUtils.getCertSerialnumberAsString(null)
		then:
		thrown IllegalArgumentException
		when:
		X509Certificate cert = CertUtils.getX509CertificateFromPEMorDER(pEMCert)
		then:
		CertUtils.getCertSerialnumberAsString(cert).equals("62654feb143fb774")
	}

	def "test IsDeltaCRL"() {
		expect:
		!CertUtils.isDeltaCRL(null)
	    !CertUtils.isDeltaCRL(CertUtils.getCRLfromByteArray(cRLData))
		CertUtils.isDeltaCRL(CertUtils.getCRLfromByteArray(deltaCRLData))
	}

	def "test ReadCRLNumberFromCRL"() throws Exception  {
		expect:
		CertUtils.readCRLNumberFromCRL(null) == null
	    CertUtils.readCRLNumberFromCRL(CertUtils.getCRLfromByteArray(cRLData)) == 223
	    CertUtils.readCRLNumberFromCRL(CertUtils.getCRLfromByteArray(deltaCRLData)) == 227
	    CertUtils.readCRLNumberFromCRL(CertUtils.getCRLfromByteArray(Base64.decode(base64CrlData))) == 8
	    CertUtils.readCRLNumberFromCRL(CertUtils.getCRLfromByteArray(crlWithoutCRLNumber)) == null
	}

	def "test GetFirstSubjectField"() {
		expect:
		CertUtils.getFirstSubjectField(BCStyle.CN, "CN=Test CN,CN=Other") == "Test CN"
		CertUtils.getFirstSubjectField(BCStyle.OU, "CN=Test CN,CN=Other") == null
		CertUtils.getFirstSubjectField(BCStyle.OU, "") == null
		CertUtils.getFirstSubjectField(BCStyle.OU, null) == null
		CertUtils.getFirstSubjectField(null, null) == null
	}

	def "test GetCertificateChainfromPem"() {
		expect:
		CertUtils.getCertificateChainfromPem(certChainData).size()==2
	}

    def "test getPEMCertFromByteArray"() {
		when:
		String pemCertificate = CertUtils.getPEMCertFromByteArray(Base64.decode(base64Cert))
		then:
		pemCertificate.startsWith("-----BEGIN CERTIFICATE-----")
		pemCertificate.trim().endsWith("-----END CERTIFICATE-----")
		when:
		String[] lines = pemCertificate.split("\n")
		then:
		for(String line : lines){
			if(!line.equals("-----BEGIN CERTIFICATE-----") && !line.equals("-----END CERTIFICATE-----")){
				assert line.length() <= 64
			}
		}
	}


	def "test getPemCertificateRequestFromByteArray"()  {
		when:
		String pemCertificateRequest = CertUtils.getPemCertificateRequestFromByteArray(testReqData)
		then:
		pemCertificateRequest.startsWith("-----BEGIN CERTIFICATE REQUEST-----")
		pemCertificateRequest.trim().endsWith("-----END CERTIFICATE REQUEST-----")
		when:
		String[] lines = pemCertificateRequest.split("\n")
		then:
		for(String line : lines){
			if(!line.equals("-----BEGIN CERTIFICATE REQUEST-----") && !line.equals("-----END CERTIFICATE REQUEST-----")){
				assert line.length() <= 64
			}
		}

	}

	def "test getSubjectDNFromCSR"() throws Exception {
		expect:
		CertUtils.getSubjectDNFromCSR(testReqData) == "C=SE,ST=Sweden,L=Stockholm,O=CGI,OU=Certificate Service,CN=Johnny Cash,E=johnny@cash.com"
	}

	def "test getPublicKeyLengthFromCertificate"() {
		when:
		X509Certificate certificate_RSA_Key1024 = CertUtils.getX509CertificateFromPEMorDER(intermediateCA1Certificate.getBytes())
		then:
		CertUtils.getPublicKeyLengthFromCertificate(certificate_RSA_Key1024) == 4096
		when:
		X509Certificate certificate_RSA_Key2048 = CertUtils.getX509CertificateFromPEMorDER(certwithRSAKey2048.getBytes())
		then:
		CertUtils.getPublicKeyLengthFromCertificate(certificate_RSA_Key2048) == 2048
		when:
		X509Certificate certificate_DSA_Key1024 = CertUtils.getX509CertificateFromPEMorDER(certwithDSAKey.getBytes())
		then:
		CertUtils.getPublicKeyLengthFromCertificate(certificate_DSA_Key1024) == 1024
		when:
		X509Certificate certificate_ECDSA = CertUtils.getX509CertificateFromPEMorDER(certwithECDSAKey.getBytes())
		then:
		CertUtils.getPublicKeyLengthFromCertificate(certificate_ECDSA) == 256
	}



	void assertFieldEquals(List<String[]> fields, String field, String expectedValue){
		boolean found=false

		for(String[] attr : fields){
			if(attr[0].equals(field)){
				found = true
				assert attr[1] == expectedValue
			}
		}

		if(!found){
			assert false : "Field "+ field + " not found."
		}
	}

	void assertMultipleFieldEquals(List<String[]> fields, String field, String[] expectedValues){
		boolean found=false

		for(String[] attr : fields){
			if(attr[0].equals(field)){
				found = true
				boolean foundValue = false
				for(String expectedValue : expectedValues){
					if(attr[1].equals(expectedValue)){
						foundValue = true
					}
				}
				assert foundValue
			}
		}

		if(!found){
			assert false : "Field "+ field + " not found."
		}
	}

	/**
	 * Asserts that all items in the list contain all the values specified (order doesn't matter)
	 *
	 * @param fields			The key/value data to compare with
	 * @param expectedKey		The key to look up
	 * @param expectedValues	The values to match with the key
     */
	void assertMultipleFieldMatch(List<String[]> fields, String expectedKey, String[] expectedValues) {
		List<String> found = new ArrayList<String>()

		for (String[] field : fields) {
			if (field[0] == expectedKey) {
				found.add(field[1])
			}
		}

		assert (found as String[]) == expectedValues : "Arrays don't match"
	}



	public static byte[] base64Cert =("MIIDLTCCAhWgAwIBAgIIYmVP6xQ/t3QwDQYJKoZIhvcNAQEFBQAwJDETMBEGA1UE" +
			"AwwKVGVzdCBlSURDQTENMAsGA1UECgwEVGVzdDAeFw0xMTEwMjExNDM2MzlaFw0z" +
			"MTEwMjExNDM2MzlaMCQxEzARBgNVBAMMClRlc3QgZUlEQ0ExDTALBgNVBAoMBFRl" +
			"c3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDecUf5if2UdWbV/HIj" +
			"h6U3XIymmh28wo8VVxPIbV1A8Yxz7QaMkP8vqaDwHnB1B6mHEjn4VyVogxWxI70I" +
			"wPudUL+Oxkc9ZL7H7zkbi6l2d/n85PjyZvdarCwcBzpEqIRsc+Wa3bGFKBpdZjwL" +
			"XjuuI4YWx+uUrQ96X+WusvFcb8C4Ru3w/K8Saf7yLJNvqmTJrgAOeKY49Jnp9V5x" +
			"9dGe+xpHR3t2xhJ5HXhm+SeUsrH5fHXky7/OVKvLPOXSve+1KHpyp+eOxxgYozTh" +
			"5k+viL0pP9G3AbEPp1mXtxCNzRjUgNlG0BDSIbowD5JciLkz8uYbamLzoUiz1KzZ" +
			"uCfXAgMBAAGjYzBhMB0GA1UdDgQWBBT6HyWgz7ykq9BxTCaULtOIjen3bDAPBgNV" +
			"HRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFPofJaDPvKSr0HFMJpQu04iN6fdsMA4G" +
			"A1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQUFAAOCAQEAbG7Y+rm82Gz1yIWVFKBf" +
			"XxDee7UwX2pyKdDfvRf9lFLxXv4LKBnuM5Zlb2RPdAAe7tTMtnYDwOWs4Uniy57h" +
			"YrCKU3v80u4uZoH8FNCG22APWQ+xa5UQtuq0yRf2xp2e4wjGZLQZlYUbePAZEjle" +
			"0E2YIa/kOrlvy5Z62sj24yczBL9uHfWpQUefA1+R9JpbOj0WEk+rAV0xJ2knmC/R" +
			"NzHWz92kL6UKUFzyBXBiBbY7TSVjO+bV/uPaTEVP7QhJk4Cahg1a7h8iMdF78ths" +
			"+xMeZX1KyiL4Dpo2rocZAvdL/C8qkt/uEgOjwOTdmoRVxkFWcm+DRNa26cclBQ4t" +
			"Vw==").getBytes()

	public static byte[] pEMCert = ("\n" +
			"Some bag attributes\n" +
			"-----BEGIN CERTIFICATE-----\n" +
			"MIIDLTCCAhWgAwIBAgIIYmVP6xQ/t3QwDQYJKoZIhvcNAQEFBQAwJDETMBEGA1UE\n" +
			"AwwKVGVzdCBlSURDQTENMAsGA1UECgwEVGVzdDAeFw0xMTEwMjExNDM2MzlaFw0z\n" +
			"MTEwMjExNDM2MzlaMCQxEzARBgNVBAMMClRlc3QgZUlEQ0ExDTALBgNVBAoMBFRl\n" +
			"c3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDecUf5if2UdWbV/HIj\n" +
			"h6U3XIymmh28wo8VVxPIbV1A8Yxz7QaMkP8vqaDwHnB1B6mHEjn4VyVogxWxI70I\n" +
			"wPudUL+Oxkc9ZL7H7zkbi6l2d/n85PjyZvdarCwcBzpEqIRsc+Wa3bGFKBpdZjwL\n" +
			"XjuuI4YWx+uUrQ96X+WusvFcb8C4Ru3w/K8Saf7yLJNvqmTJrgAOeKY49Jnp9V5x\n" +
			"9dGe+xpHR3t2xhJ5HXhm+SeUsrH5fHXky7/OVKvLPOXSve+1KHpyp+eOxxgYozTh\n" +
			"5k+viL0pP9G3AbEPp1mXtxCNzRjUgNlG0BDSIbowD5JciLkz8uYbamLzoUiz1KzZ\n" +
			"uCfXAgMBAAGjYzBhMB0GA1UdDgQWBBT6HyWgz7ykq9BxTCaULtOIjen3bDAPBgNV\n" +
			"HRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFPofJaDPvKSr0HFMJpQu04iN6fdsMA4G\n" +
			"A1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQUFAAOCAQEAbG7Y+rm82Gz1yIWVFKBf\n" +
			"XxDee7UwX2pyKdDfvRf9lFLxXv4LKBnuM5Zlb2RPdAAe7tTMtnYDwOWs4Uniy57h\n" +
			"YrCKU3v80u4uZoH8FNCG22APWQ+xa5UQtuq0yRf2xp2e4wjGZLQZlYUbePAZEjle\n" +
			"0E2YIa/kOrlvy5Z62sj24yczBL9uHfWpQUefA1+R9JpbOj0WEk+rAV0xJ2knmC/R\n" +
			"NzHWz92kL6UKUFzyBXBiBbY7TSVjO+bV/uPaTEVP7QhJk4Cahg1a7h8iMdF78ths\n" +
			"+xMeZX1KyiL4Dpo2rocZAvdL/C8qkt/uEgOjwOTdmoRVxkFWcm+DRNa26cclBQ4t\n" +
			"Vw==\n" +
			"-----END CERTIFICATE-----\n" +
			"Some bag attributes").getBytes()


	public static byte[] pEMPKCS10 = ("\n" +
			"Some bag attributes\n" +
			"-----BEGIN CERTIFICATE REQUEST-----\n" +
			"MIIBnTCCAQYCAQAwXTELMAkGA1UEBhMCU0cxETAPBgNVBAoTCE0yQ3J5cHRvMRIw\n" +
			"EAYDVQQDEwlsb2NhbGhvc3QxJzAlBgkqhkiG9w0BCQEWGGFkbWluQHNlcnZlci5l\n" +
			"eGFtcGxlLmRvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAr1nYY1Qrll1r\n" +
			"uB/FqlCRrr5nvupdIN+3wF7q915tvEQoc74bnu6b8IbbGRMhzdzmvQ4SzFfVEAuM\n" +
			"MuTHeybPq5th7YDrTNizKKxOBnqE2KYuX9X22A1Kh49soJJFg6kPb9MUgiZBiMlv\n" +
			"tb7K3CHfgw5WagWnLl8Lb+ccvKZZl+8CAwEAAaAAMA0GCSqGSIb3DQEBBAUAA4GB\n" +
			"AHpoRp5YS55CZpy+wdigQEwjL/wSluvo+WjtpvP0YoBMJu4VMKeZi405R7o8oEwi\n" +
			"PdlrrliKNknFmHKIaCKTLRcU59ScA6ADEIWUzqmUzP5Cs6jrSRo3NKfg1bd09D1K\n" +
			"9rsQkRc9Urv9mRBIsredGnYECNeRaK5R1yzpOowninXC\n" +
			"-----END CERTIFICATE REQUEST-----\n" +
			"Some bag attributes\n").getBytes()


	public static byte[] pemWithEmailSAN = """-----BEGIN CERTIFICATE-----
MIIDvzCCAqegAwIBAgIJAJ1nAJoRZXX3MA0GCSqGSIb3DQEBCwUAMEwxCzAJBgNV
BAYTAkdCMRYwFAYDVQQIDA1XZXN0IE1pZGxhbmRzMRMwEQYDVQQHDApCaXJtaW5n
aGFtMRAwDgYDVQQKDAdFeGFtcGxlMB4XDTE5MDgwNzA5MTk1NVoXDTE5MDkwNjA5
MTk1NVowTDELMAkGA1UEBhMCR0IxFjAUBgNVBAgMDVdlc3QgTWlkbGFuZHMxEzAR
BgNVBAcMCkJpcm1pbmdoYW0xEDAOBgNVBAoMB0V4YW1wbGUwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCl0Els1e7JP80H5BfWz9NDVT/IUXB+5hqEYTsU
A1HnoUcc9e9WT5P7mHS46kR3vU4wT+FAg3ExN8HeWkMH4/cL3TuT97GQ/Ms0EeAs
1IQj++Jptfon5z1Hqbt9oJmewZx6zLe86M8AAz3k5cqvV1NbaYaStQIDrvXdjnWK
ixu0sfNtjT9E7puGYE71h5GXAVVKfzd+gM6J4ukhf4xodF9O4rtjpui1EbzGQK7A
Uw7s7YFxf8CRdRZFwW+c+Jja0BHJrp8iuUAzLVcJ8wlpPVKXwnG7F8ZHTRgSZ3UX
JDtvNpEqOBWqt0e5tLVM5oVXcCKId1EGTtV5287xxiFO35fRAgMBAAGjgaMwgaAw
HQYDVR0OBBYEFOpvvgpwOwMRyDEEGwsrUZcp8JgcMB8GA1UdIwQYMBaAFOpvvgpw
OwMRyDEEGwsrUZcp8JgcMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgWgMBgGA1UdEQQR
MA+BDXRlc3RAdGVzdC5jb20wLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJh
dGVkIENlcnRpZmljYXRlMA0GCSqGSIb3DQEBCwUAA4IBAQCYg+ypXf7O+2ndxAJv
sklJ7vtBviRpegQkcB43OxpaJGgPfRRIJthJyCMLCsv4wmx0+Dl+WUTD41fB9kGl
Kouhzztjbal/k2Td34I9knlOvOktlU8KjUJwe5iihZyQXVYADFuGW9jSJE6hE5gV
coMELvnWXJuZ+nrTRoBd2PiA0MVZuwKRtmJVRyJ8S9yqkZmjJ7BKsF2UzDbDtVZD
wOpwPB66eyZE5tPU/NC1dJjz4XyrCd1myfi5Kk7GBMrqUH6sObd3r/dh1cIefgRf
yyaohdi0duCDIO45OTKn7a0gTFtKA4+2/9Hy1otiuhauxiBnFtuzb5xXIC63bP3D
OMk7
-----END CERTIFICATE-----
""".bytes

	public static byte[] base64LotOfExtensitonsCert = (
			"MIIGlzCCBX+gAwIBAgIIUyeQwM56PyUwDQYJKoZIhvcNAQEFBQAwSDEoMCYGA1UE" +
					"AwwfU21hcnQgQ2FyZCAyLjAgRGVtbyBTb2Z0VG9rZW5DQTEcMBoGA1UECgwTU21h" +
					"cnQgQ2FyZCAyLjAgRGVtbzAeFw0xMjAyMTYwMTUzNTlaFw0xNDAyMTUwMTUzNTla" +
					"MIIB1DEUMBIGA1UECQwLQW5rZ2F0YW4gMjQxEjAQBgNVBEEMCWxpdGVuYW5rYTET" +
					"MBEGA1UEFBMKMDcwMTIzNDU2NzEXMBUGA1UEEAwOQW5rdHLDpHNrZXQgNDIxFTAT" +
					"BgNVBA8MDExpdGUgQmxhbmRhdDEPMA0GA1UEEQwGMTIzNDU2MR8wHQYJKoZIhvcN" +
					"AQkCDBB3d3cuYW5rZWJvcmcuY29tMRYwFAYDVQQuEw1BbmthUXVhbGlmaWVyMRYw" +
					"FAYKCZImiZPyLGQBAQwGYW5rYWthMRMwEQYDVQQDDApLYWxsZSBBbmthMRAwDgYD" +
					"VQQpDAdBbmtuYW1uMQowCAYDVQQFEwExMQ4wDAYDVQQqDAVLYWxsZTELMAkGA1UE" +
					"KwwCS0ExDTALBgNVBAQMBEFua2ExCzAJBgNVBAwMAk1yMRswGQYDVQQLDBJBbmtl" +
					"Ym9yZ3MgYmlsZW5oZXQxHDAaBgNVBAoME1NtYXJ0IENhcmQgMi4wIERlbW8xEjAQ" +
					"BgNVBAcMCUFua2xhbmRldDEVMBMGA1UECAwMQW5rcHJvdmluc2VuMRMwEQYKCZIm" +
					"iZPyLGQBGRYDY29tMRowGAYDVQQGExFBbmthbnMgU3RvcmEgTGFuZDCCASIwDQYJ" +
					"KoZIhvcNAQEBBQADggEPADCCAQoCggEBANNSWNl2NuRitb4krYALaMBzJJ/ORjI+" +
					"MHAjYEVkCW7QP1dt/1ZHuCgeEYKhxNPQZp635ijEeFUQrx6NjUE4AwRfop3yHuTf" +
					"yEOX5m4g7GpqnWC8bq6WzbP+QU/uA+55CA1LdfWwexNjDLDerffFTsMACPGwDFWg" +
					"eeAs/0FnSvQhVlgmA2dpTGCZmnxxjEJVQ1rqsCbpqJ1dQYAMTY2liGR7hRiPef+l" +
					"pV5cB8K5JkM7xEnZrGQKVecJlql1DvTqU0TWTF1WIpS8/sXVC+zWsfCUks93BKYf" +
					"0bIfJ1AH1Tpr4aOqf/oQtTB6zc9Pi36X4XsvNQOEbioeeL9IXMw6nzkCAwEAAaOC" +
					"AfUwggHxMB0GA1UdDgQWBBRKt5occ6+tx0QovmzJaQsIKR1kZTAMBgNVHRMBAf8E" +
					"AjAAMB8GA1UdIwQYMBaAFHwZ52Babm7N2gZbAWr6Ra25gsNIMIGcBgNVHR8EgZQw" +
					"gZEwgY6ggYuggYiGgYVodHRwOi8vc21hcnRjYXJkMjAuZGVtbzo4MDgwL2VqYmNh" +
					"L3B1YmxpY3dlYi93ZWJkaXN0L2NlcnRkaXN0P2NtZD1jcmwmaXNzdWVyPUNOPVNt" +
					"YXJ0IENhcmQgMi4wIERlbW8gU29mdFRva2VuQ0EsTz1TbWFydCBDYXJkIDIuMCBE" +
					"ZW1vMA4GA1UdDwEB/wQEAwIFoDAxBgNVHSUEKjAoBggrBgEFBQcDAgYIKwYBBQUH" +
					"AwQGCCsGAQUFBwMFBggrBgEFBQcDBzCBvgYDVR0RBIG2MIGzgg53d3cuYW5rYW5z" +
					"LmNvbaQmMCQxDTALBgNVBAMMBEFua2ExEzARBgoJkiaJk/IsZAEZFgNjb22GGGh0" +
					"dHA6Ly93d3cubGlsbGFua2FuLmNvbYcEAQIDBKAgBgorBgEEAYI3FAIDoBIMEGFu" +
					"a2FrYUBrYWxsZS5jb22gGAYJKwYBBAGCNxkBoAsECRI2VBI2VBI2VKAdBgYrBgEF" +
					"AgKgEzARoAIbAKELMAmgAwIBAKECMAAwDQYJKoZIhvcNAQEFBQADggEBAAxdIAt9" +
					"UFof6P2Fbzjar134BYRNKKYBftIVBmEL6WJo6+YNIYIoox0n2k0WqM+f4jd7/1rD" +
					"F9bO0rcloxFI9lFb88OstTaLCJIYJay1kN3w43AQdOai0Ta/whAdlrbVg21OA5rX" +
					"+lp83m+o7rYD0doXYn4jVSopaeaa4xmjBAcTyJOGVnr0VIO4Ri9f/UiF0r7bOZLX" +
					"TnD8fs1AiOuYsWdhEALCOuktVaBjK4Rx+uJSAC7LuxCljtZflqjLJgi61EO9AQHA" +
					"sYwwV9YcuHGleIOCThzYF7amriwyYI5b5/muaeanQUUq3isuKeIe1sS717pJZT8BJmA1ME8V8hErkp0=").getBytes()

	static byte[] base64CrlData = ("MIIDEjCCAfoCAQEwDQYJKoZIhvcNAQEFBQAwPjEgMB4GA1UEAwwXTG9naWNhIFN2ZXJpZ2UgU1QgZUlEQ0ExGjAYBgNVBAoMEUxvZ2ljYSBTdmVyaWdlIFNUFw0xMTA5MTUxNDU0MzNaFw0xMjA5MTQxNDU0MzNaMIIBVTAZAghajd9bDQg7UxcNMTEwOTEyMTU0NjE2WjAnAggTUHuJ6VTyeBcNMTEwOTEzMDgzMTE3WjAMMAoGA1UdFQQDCgEJMBkCCGl7lgke46G+Fw0xMTA5MTMwODM5MzRaMCcCCGWm3gl0oH3BFw0xMTA5MTMxMTA1MjBaMAwwCgYDVR0VBAMKAQkwJwIIITF3zViOMhEXDTExMDkxMzEzMTEwNVowDDAKBgNVHRUEAwoBCTAnAggZm958akZbpxcNMTEwOTE0MTEyNzE4WjAMMAoGA1UdFQQDCgEJMCcCCAXf9dMZ9fJnFw0xMTA5MTQxMzE3MDNaMAwwCgYDVR0VBAMKAQkwJwIIQr7SMu8oaawXDTExMDkxNDEzMjIzNFowDDAKBgNVHRUEAwoBCTAnAggGAK/BcjgrJhcNMTEwOTE0MTQxODQxWjAMMAoGA1UdFQQDCgEJoC8wLTAfBgNVHSMEGDAWgBSN0owBP7EKdNvlc60acoV1Q6L7+TAKBgNVHRQEAwIBCDANBgkqhkiG9w0BAQUFAAOCAQEAWnyDMhkaB7M3fHzTtqNAxZCZBscmy7THvEcf2TNlnWn7Ms4TalH7Ux4JqWZMJqd5um+0dzjCYMKIH8DYY1DO3rFcBK5bD7A84joAg2yAOYrloBdwDHKSM05RYEQ4dsVFh9fhPw4lSA1EH/bxYCb7mzVC9/OnCQ2rhWIVpPxazRmaMU2ZcXf+d7QfZfznduiOBZrr/tQVB41hbt5kJiv9pAIVzpJD81Yc5ohzd3t316ffXwhBZx7PmvumQvCFSlNV0qor7njuqZsceRSPYxyncgZUJ+9gjF8SC2RfgUBd3jE2TGJMHqU2ndYl5bk6BnjqvG62kEoyrb3oegeFrYD11mA=").getBytes()

	public static byte[] cRLData = Base64.decode(("MIICNDCCARwCAQEwDQYJKoZIhvcNAQEFBQAwZTE1MDMGA1UEAwwsTG9naWNhIFNF" +
			"IElNIENlcnRpZmljYXRlIFNlcnZpY2UgU1QgU2VydmVyQ0ExLDAqBgNVBAoMI0xv" +
			"Z2ljYSBTRSBJTSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlIFNUFw0xMjA2MTMxMTA0MTha" +
			"Fw0xMjA2MTQxMTA0MThaMFEwGQIIEIam4gZ1djYXDTEyMDExNjEwMjI1N1owGQII" +
			"ezNdlcNNFc0XDTEyMDExNjEwMjIyOFowGQIIa7ozg2tRCzcXDTEyMDExNjEwMjIy" +
			"OFqgMDAuMB8GA1UdIwQYMBaAFOBD1HKL2rBlAoaehRcftgg2gElPMAsGA1UdFAQE" +
			"AgIA3zANBgkqhkiG9w0BAQUFAAOCAQEAQWuejE69ixHeI2Uae9/+R3pYvdeUGL1t" +
			"OCsvy2xlkImvHORizypylEPOIxset/7iQ50gdFDOuwoo4CYK0kUQ4FnCQWLAUdEm" +
			"r+nymtaFwsKWDLETEe8yrkT83V81hiP75P39oJRd0K26BSWtWdIFilYGFHglBcSu" +
			"2oqbg0tYGJxq0HGXs/6DR/Qz/SSbkJfBfgEh0i5+IIPHmKpRMywTPEvrg/mw8a/g" +
			"zOQuKSAMfgJIBBONbuakdNydQRxmTs4wr7pd3fYizkKtIAULedUtt9zZvuBCG5WQ" +
			"RSAQ4Ei3jQ7sE8pq9sQp5uGwQ9sRQNPzNWLAxIW+y2Rxs2l/IBIniw==").getBytes())

	public static byte[] deltaCRLData = Base64.decode(("MIIB7TCB1gIBATANBgkqhkiG9w0BAQUFADBiMTIwMAYDVQQDDClMb2dpY2EgU0Ug" +
			"SU0gQ2VydGlmaWNhdGUgU2VydmljZSBTVCBlSURDQTEsMCoGA1UECgwjTG9naWNh" +
			"IFNFIElNIENlcnRpZmljYXRlIFNlcnZpY2UgU1QXDTEyMDYxMzExMTkzOVoXDTEy" +
			"MDYxNDExMTkzOVqgQDA+MB8GA1UdIwQYMBaAFEwtBd9R777GA+JZsEjWtbFAAkrj" +
			"MAsGA1UdFAQEAgIA4zAOBgNVHRsBAf8EBAICAOIwDQYJKoZIhvcNAQEFBQADggEB" +
			"AC0Nzus8HsiLOCleyAKff8bPmv6EC5SG1wCBzeg17bGd2LKxCT8DppWdlDVA5Qgg" +
			"caGY8YFOXYuDnNsLFiNHOUX6wXEPwYcuSemY11yn5+WeVFxkgcU6C7s3fZgZZwZH" +
			"8BPBk566Rtd6bhl79zRVPpMm1YacnkedqESA1KxVl3dOB6YKmSKJDkYp43wOKxq3" +
			"J1q5bPRBgXUM3N6T2djhlv80DKD10hg3g7OC/+yjYYYIhPpf1lQ/iGQ4zwLS9LPW" +
			"ABb4pN4vdWBMXX7F+lfMIa0xUrwnzqp+26r6ELLBBKfT7EP83xS7lzHAltEpveJ9" +
			"b4sFWlxjedl6qflBeIPekV8=").getBytes())

	public static byte[] crlWithoutCRLNumber = Base64.decode(("MIH9MGgCAQEwDQYJKoZIhvcNAQEFBQAwEjEQMA4GA1UEAxMHVGVzdCBDQRcNNz" +
			"AwMTAxMDAwMDAwWhcNNzAwMTAxMDAwMDAwWjAiMCACAQEXDTcwMDEwMTAwMDAwMFowDDAKBgNVHRUEAwoBCTANBgkqhkiG9w0BAQUFAAOBgQBgoh" +
			"xJP/v4JTKUAfOUmbbKbwCAQOQsnLl8mZ22ak7qZKGcURtB1cILsmd6kx3tkBYqnNZGRz2+tZR6HG8G+hGj2rSpwMeAjC+9z8o9lgdVgekw25O1kLq" +
			"Xu4H8qm4uoGUGnLw/EoLSK5uS72t9V8g5pAQBInTIJ8+ZzvFtcXqovQ==").getBytes())

	public static byte[] certChainData = ("Bag Attributes: <Empty Attributes>\n"+
			"subject=/CN=Connected Car Root CA v1 QA/L=Torslanda/DC=Connected Car/DC=Volvo Cars\n"+
			"issuer=/CN=Connected Car Root CA v1 QA/L=Torslanda/DC=Connected Car/DC=Volvo Cars\n"+
			"-----BEGIN CERTIFICATE-----\n"+
			"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\n"+
			"bIR8A8Rc9Oy/57+EJw4BJ/uwcXvIJegGnAap\n"+
			"-----END CERTIFICATE-----\n"+
			"Bag Attributes: <Empty Attributes>\n"+
			"subject=/CN=Connected Car Policy Vehicle CA v1 QA/L=Torslanda/DC=Connected Car/DC=Volvo Cars\n"+
			"issuer=/CN=Connected Car Root CA v1 QA/L=Torslanda/DC=Connected Car/DC=Volvo Cars\n"+
			"-----BEGIN CERTIFICATE-----\n"+
			"MIIGijCCBHKgAwIBAgIIXUBgfxfV4c4wDQYJKoZIhvcNAQELBQAwdTEkMCIGA1UE\n"+
			"AwwbQ29ubmVjdGVkIENhciBSb290IENBIHYxIFFBMRIwEAYDVQQHDAlUb3JzbGFu\n"+
			"ZGExHTAbBgoJkiaJk/IsZAEZFg1Db25uZWN0ZWQgQ2FyMRowGAYKCZImiZPyLGQB\n"+
			"GRYKVm9sdm8gQ2FyczAgFw0xMzAxMTgxNzMxMDRaGA8yMDU5MDExODE3MzEwNFow\n"+
			"fzEuMCwGA1UEAwwlQ29ubmVjdGVkIENhciBQb2xpY3kgVmVoaWNsZSBDQSB2MSBR\n"+
			"QTESMBAGA1UEBwwJVG9yc2xhbmRhMR0wGwYKCZImiZPyLGQBGRYNQ29ubmVjdGVk\n"+
			"IENhcjEaMBgGCgmSJomT8ixkARkWClZvbHZvIENhcnMwggIiMA0GCSqGSIb3DQEB\n"+
			"AQUAA4ICDwAwggIKAoICAQDRabJKLtWFmflw7XIrOud5CYuofkOv+VPm0Io1+Gcx\n"+
			"uG9gHPc84BkgQy9wTD72lttwE4zktfXWh4e1HR4QRvGl2ezh6omwBU3spRgLn/JN\n"+
			"mOW09BOQzhWQ21KcHYLmQw54FSHqZmJjh7uM/iKJW/m0jefuLy/iCINgNkXgaAr2\n"+
			"qdg8sCEbZ5Sqynb1AvBUeuEYb42XGjKnJIhZsmfdJM7LXZCx68R/pun4ZQNFMMl7\n"+
			"bxAuLbUQIHYmEXvYfm0V6yecwLMQycyOn9rtnk31/22QgX4jF0tZ5XT27krO2x3N\n"+
			"ce763RROKslkPSAScND/3UtitieC43eyvwS+KUq0if1+cmDdec2EMgNFjGxytMgc\n"+
			"MObiFEfdQrArnS3XAlIESckvqZjiJvysBgVVG9CWgHPv0mOaLVWfOPf4GeGBrZ7J\n"+
			"9yGCrpRfwct23MpwHwSONIMgiS+7RzHifshU7IFuy4Ob6pVQVCkjUI3zSdFW5S4p\n"+
			"NQGBwlHlbfkV+XfX3465eEeOkSyoeUQLmUXPvkDzJBnpSxFCMCh9mgWBVZ7m/8z7\n"+
			"9oXmN1erew7R2ZpYHBJzCHk+tgpHS8u0kUL+DUsG1Fh2NAaHAY7F3vgeIZT9bq2Y\n"+
			"wdPayvhW/MhMQaWDFBAOcZshutNyKkug5yZavWfPJZlYVjomEwTh+XkOoPF8A8if\n"+
			"7wIDAQABo4IBEDCCAQwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzABhiBodHRw\n"+
			"Oi8vb2NzcC5xYS52b2x2b2NhcnMuY29tL2NjLzAdBgNVHQ4EFgQUg0zjoaWKkY/9\n"+
			"Sr942jyWu1YtzoYwEgYDVR0TAQH/BAgwBgEB/wIBATAfBgNVHSMEGDAWgBSPXTXK\n"+
			"T56BtMqGrH4RqyUzgFDECjAUBgNVHSABAf8ECjAIMAYGBFUdIAAwUgYDVR0fBEsw\n"+
			"STBHoEWgQ4ZBaHR0cDovL2NybC5xYS52b2x2b2NhcnMuY29tL2NjL3RvcnNsYW5k\n"+
			"YS9jb25uZWN0ZWRjYXJyb290Y2F2MS5jcmwwDgYDVR0PAQH/BAQDAgEGMA0GCSqG\n"+
			"SIb3DQEBCwUAA4ICAQBeRdMlV/1K3YNosaj3DqFNzYwUQaOap/IyiFWth0TnXdW8\n"+
			"ONLNwQAoAekWgR7B8TIcfMpNL8iWBo4YHtdXm5HsIPtcgkYbPCDBA4eD4IG5zpqo\n"+
			"H8dZ3glqD/9uPBUMRFVwGk0gWdnLKHpENJmUHl5OuXKbPEC7IUWkzCgJJgiAYHp1\n"+
			"5iBSTmfbWQ5tGY9i82aqVuyKD5RxO+0XzGCHe+Zz66k50xFgbxNtGAmlXC0FTaMo\n"+
			"Nb0OsXQyyOxG4HQk9XJzo5zFhe6lqzJc6SXZL7ajI/DRAtg6CSknYDCvIWu0FgPD\n"+
			"j7oUsLAISGkFeY3nBA96TpD8P8D41AZR5yOnLUCc84T582akv8PjNEuBfKByAa0L\n"+
			"hfsHXXlaOue40unnEjttVkYocieith+UNV9O5SkZl9mlLjDf8q5EdP2LNnN5vWFo\n"+
			"0T0U0L6XppBrd/qk5Rj+cy5HNMofvPECHMzFLkZO2cshUNAbx7M8LCdMlWSic73y\n"+
			"Ef7M/WHEbp/l+K0BXHLz3FKi5v5Tcwyx3O92N6qiikHrUfgFzJkqpla0hr75u9wT\n"+
			"Otm6V/y6wiaKkXwy4JQf7hQ9YwmlGr2wqdd3k4S8D6JRmg8/PrLygGjSolRWLqhG\n"+
			"UEWNN/cfUGMmG90qG2sY/aIEva0mPmTKYjiL9CdwSBiw3V95ZZ2SXJeM0j0lUg==\n"+
			"-----END CERTIFICATE-----\n").getBytes()


	static byte[] testReqData = Base64.decode("MIIC2jCCAcICAQAwgZQxCzAJBgNVBAYTAlNFMQ8wDQYDVQQIDAZTd2VkZW4xEjAQ\n" +
			"BgNVBAcMCVN0b2NraG9sbTEMMAoGA1UECgwDQ0dJMRwwGgYDVQQLDBNDZXJ0aWZp\n" +
			"Y2F0ZSBTZXJ2aWNlMRQwEgYDVQQDDAtKb2hubnkgQ2FzaDEeMBwGCSqGSIb3DQEJ\n" +
			"ARYPam9obm55QGNhc2guY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n" +
			"AQEAr0Pqnq7BN7NT4epvQUX5f7Q4IDQaTaUtsKf82CX+tZ6hzpgQ6KoxLBCRjcuL\n" +
			"uLAOM2/ao7z8PadOQZGYALvOwbY5mC15MkJmZumWKPAGgApOjBmlkcMW5BjRwdy7\n" +
			"zCnA/EVBMISnbqd7XmUpY1vDe88F5KwR48qrrky8eLh/fFKpMO8ByQ0PhfbvFE3t\n" +
			"Gr2vk/kXnRZ/30HRv5SME4a2COmGhkI849pmFJGtfBOoaYAsm+irGnWjqPr+/Q54\n" +
			"YeIY4VidshN1LB6nMG+TCs/ij7ski5BQbVGrL4Ydw/DY+QaOLN6Gxe24BQOsi6VV\n" +
			"2jg8vetHiJx/BPylnEi/B8QYfQIDAQABoAAwDQYJKoZIhvcNAQEFBQADggEBAGcL\n" +
			"83PqwC1JC2lVMgjDXXbXSoYVCQYXl2V/sNzEaabMuCVgWPxWTksEpTmJkjH8p5PQ\n" +
			"j8HhxgqhpFqsII9FYlxbW6N4kLhrhEyET3G8juXyXJ/xPptHEiw6w8PBWpm7M+S4\n" +
			"eDUY5Xk795qBPlheGmJLEDCE6L86Sw5h6owx1UXhdAR2iS85ndf54Wi6sSmaOt0E\n" +
			"sCix5PsxasDEf9q6nBaGlgaeNxJYuIRBXaUpRfZkwpvPtpteyvwqcXpHgHzDMwIQ\n" +
			"SMynkOALC2GKOT1MwXShSluDkJHrqsXZMv5DiTzxADDwLxJ2nidBAM26HxHlCQV0\n" +
			"7ubUpr8XcpXY8f9tp10=\n")

	static def intermediateCA1Certificate= """
-----BEGIN CERTIFICATE-----
MIIG3DCCBMSgAwIBAgIILFhC7socJgswDQYJKoZIhvcNAQELBQAwgYMxMjAwBgNV
BAMMKUNvbm5lY3RlZCBDYXIgUG9saWN5IFZlaGljbGUgQ0EgdjEuMiBURVNUMRIw
EAYDVQQHDAlUb3JzbGFuZGExHTAbBgoJkiaJk/IsZAEZFg1Db25uZWN0ZWQgQ2Fy
MRowGAYKCZImiZPyLGQBGRYKVm9sdm8gQ2FyczAgFw0xNDA5MjYxNDQ3NDNaGA8y
MDYwMDkyNTE0NDc0M1owbzEeMBwGA1UEAwwVVmVoaWNsZSBDQSB2MjAxNiBURVNU
MRIwEAYDVQQHDAlUb3JzbGFuZGExHTAbBgoJkiaJk/IsZAEZFg1Db25uZWN0ZWQg
Q2FyMRowGAYKCZImiZPyLGQBGRYKVm9sdm8gQ2FyczCCAiIwDQYJKoZIhvcNAQEB
BQADggIPADCCAgoCggIBAMf/DYCjT9NSQZJ4C2M7G5zk+53yxNPi6OKUhwntiGYM
CzBq8MtJ27j+dGywJEF3hF1SdTdyafjZcR91WrZfrKk0iOUAA/+Ja1Eolo9NVsmK
miRrzj6t0cGHk0yindPF87S8ouJGsHo8orrfFTkgOP/2VIrqqr81UA6wrs3qbgou
y1FgLiVf03ap8KUtuJKIQcwrDvnllDBB3K7ClVBViKT20w3M3yU4j4WYlxngrZ05
sM9Gd0/rTIzCTx7FmRyVt/mQNCWVwJTZqwE39O4/7OoRE/fDaZ0szSZ38+G17Ho5
ecSHle0+mibslYdJe/QYB/J0Sig9Z3RcYMqzxYjVjGwW/jmgzkEMxAwitK+t6Zra
iYqiZMfKGpI5+zoSMfIj/l296esa6jV+zGUnw+V1kppu48T5udJdhF89w9i7OAhI
dkTCuiHnmjhKXS9z1uHWHsMCJUt0dNxRKD5I5bF4rFbTcOfhxDvyfrZ6k3hixKqe
uEyqDV6E3SZUWyqKBnO1k3L85Wt5G512p2Vm2BmXtxRh+MSlydr8QkyzEGQPRa0/
e87673cvuM+UtKid5RjRQ8tePkKSnKsCvtfLpJwckpH0Xo1zAiUoiNsAcgUFoygh
neJMaq6xLgFjfQ2I0C0eiPhLsfN2eDjxWl+2XhHuzR0+OHvY/zMltEwkFIHsM88L
AgMBAAGjggFjMIIBXzCBhgYIKwYBBQUHAQEEejB4MEYGCCsGAQUFBzAChjpodHRw
Oi8vdHJ1c3QudGVzdC52b2x2b2NhcnMuY29tL2NjL3ZlaGljbGVwb2xpY3ljYXYx
LjIuY3J0MC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcC50ZXN0LnZvbHZvY2Fycy5j
b20vY2MvMB0GA1UdDgQWBBRzlbx6zp24GETTUN37uVcSuDOSPDASBgNVHRMBAf8E
CDAGAQH/AgEAMBsGA1UdIAEB/wQRMA8wDQYLKwYBBAGCqBwCAgEwUwYDVR0fBEww
SjBIoEagRIZCaHR0cDovL2NybC50ZXN0LnZvbHZvY2Fycy5jb20vY2MvdG9yc2xh
bmRhL3BvbGljeV92ZWhpY2xlX3YxLjIuY3JsMB8GA1UdIwQYMBaAFIO5ZTgoxFFV
OxC6dZkyIarfAylBMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAgEA
TeFyr57NEalBjShjTQmknPJ9LayfwxITMHTnrEZrleKzr/O6y1rtjdyuUHFPaakr
ai6Cn41q/vud9waukQKd1FnIARBuzKeTuuneo+ZGBJQ3PhMJYTqy0FzLjxICww5C
BQsDIU4euDXPuqCMfxhZ6Jdt1UXq7bscuzLgo0JH/lS0nJzyGcJexU3M3bOarGIM
lcynT8qP4nl7VXNgrPqJaKIG58Du/qQRLAiCHENLo8Cke4ulxo66+RdVJ+m1TvEg
Q6r8GhUwlhWq6tDRZ9FLXgeggz8yemt3XW0OZUrIb8y9KnV9wJWZgTHEUfWTu49e
/iK6eI54NvwgNN3A5L1Z6PS/lCxw7Ljcx04bbZtRwzty3YE97IFzMJNkJRaXlbkb
lYeQhOCgeJSff4dnKkN0zJ7S2yiew//C/zvt1pYIOGaFoZ13THS5JvM5f2qGLoIL
584NWWXrNcAikNRXOF2m4cre278d2QswomcB5uTagY5kJLEStp3GHwKSYe29jq4Z
iCDfeHg2zLipYG0mvJg9yAnuVgOJzDmhzGxfV7fS0B9JWD4p8V1X0FQRNnqf51+k
SDabpqXjKiufTqgq8Jb1xYrwautY9f7DWbFABfCx4/k/zSTkbTtRVxUX1kK5Xios
uc74nJCxwr58yWAXu0RZJwpJqt9LojOV7zDs5cAxwDs=
-----END CERTIFICATE-----
"""

	public static String certwithRSAKey2048 = '''-----BEGIN CERTIFICATE-----
MIID4TCCAsmgAwIBAgIJAIuAKtdD1NKjMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNV
BAYTAlNFMRIwEAYDVQQIEwlTdG9ja2hvbG0xDjAMBgNVBAcTBUtpc3RhMR0wGwYD
VQQKExRDZXJ0aWZpY2F0ZSBTZXJ2aWNlczEQMA4GA1UEAxMHcnNhY2VydDAeFw0x
ODAxMTYxMjQ3MDBaFw0yODAxMTQxMjQ3MDBaMGIxCzAJBgNVBAYTAlNFMRIwEAYD
VQQIEwlTdG9ja2hvbG0xDjAMBgNVBAcTBUtpc3RhMR0wGwYDVQQKExRDZXJ0aWZp
Y2F0ZSBTZXJ2aWNlczEQMA4GA1UEAxMHcnNhY2VydDCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBANGz2rQezgw+qcD5wj4SyVWyHhI9B/Qe5yr2rUrDHOqb
Okuu5skFBK+89tKF1CAtYRl98tyy9UrSliMUYmsyFjgWa7zNki3x2G++Onof3QtM
BEC59wa3qDVXniYYGmYLW4WY5ZqlyYSMytB/x8v+d6o47uoErQr3m8Pw6INg98T5
LM4haBEGA76GMV0oq+KR1TIBqi+xR0CLOLmg+WD7KWy4pSjPAtIz2ZOShQS+RLkA
SEbzq02LoqCKrhaO25mbo8jdLj0zuMje8h2xEHXNEy73g0K8iImUy+Xhbn3bluE7
q+STiJDKzxykLtCDoMdV1Tti1uJ9ygBwrpgen/sU58sCAwEAAaOBmTCBljB8BgNV
HSMEdTBzoWakZDBiMQswCQYDVQQGEwJTRTESMBAGA1UECBMJU3RvY2tob2xtMQ4w
DAYDVQQHEwVLaXN0YTEdMBsGA1UEChMUQ2VydGlmaWNhdGUgU2VydmljZXMxEDAO
BgNVBAMTB3JzYWNlcnSCCQCLgCrXQ9TSozAJBgNVHRMEAjAAMAsGA1UdDwQEAwIE
8DANBgkqhkiG9w0BAQsFAAOCAQEAZe8jLCVOke3INd1QDrLwMUYS01NOMRh7Xn8y
u1f7i1c2fnOJ/nDN86BowWBtiOb0CW+l2YRlSCEJUZmRHpb4mkQnELB29PQtPxXX
VNnXkjCjtZZv4/GWkE7yRLLxKMptGOxWErYmOTmZgJaW/uF2PcrAVlPz6pvKvnu3
dO7I83P5cRdRDdSx8LPlpEoksv5lgesJAAEtOP0dTqOxp+xvfojS1nOcvp8ZhbMG
+4jJMIjTU+8MK6/n/cKUCVqZKDv422P9XRGBfhVYQCJH2kxuz3H37pbyrZw6BmFI
ih1QGJIp010A0ETiN8rmRtCaKyOB16QXRMe8/YvFAuD8KBGx3g==
-----END CERTIFICATE-----'''

	public static String certwithDSAKey = '''-----BEGIN CERTIFICATE-----
MIIDnzCCA1ugAwIBAgIJAPVEhTv6js6NMAsGCWCGSAFlAwQDAjBiMQswCQYDVQQG
EwJTRTESMBAGA1UECBMJU3RvY2tob2xtMQ4wDAYDVQQHEwVLaXN0YTEdMBsGA1UE
ChMUQ2VydGlmaWNhdGUgU2VydmljZXMxEDAOBgNVBAMTB2RzYWNlcnQwHhcNMTgw
MTE2MTI1MjAxWhcNMjgwMTE0MTI1MjAxWjBiMQswCQYDVQQGEwJTRTESMBAGA1UE
CBMJU3RvY2tob2xtMQ4wDAYDVQQHEwVLaXN0YTEdMBsGA1UEChMUQ2VydGlmaWNh
dGUgU2VydmljZXMxEDAOBgNVBAMTB2RzYWNlcnQwggG2MIIBKwYHKoZIzjgEATCC
AR4CgYEArpYI3AhOpQ/n5MEQ//yAujYFTuZ6gTS2yY3NJfY7KhcWrGbTxeF2qdWM
yfy7scl+NMmC0/HFaXr3ec/R2NoDSctCkpK0ApCa8cBNdK/H7YXdvKJ2te99IMij
N3s4G0hpnq8Jjofk4X6QJqLM4i1mLBDqi6g89GZdYr749t/e8LkCFQD/4yst9/6a
mMAXZMlAngMloDU9uQKBgGOj6U9C8woinuFJp4VbMMO9CFozI2inOcy1u5GhMCJg
2aLuPo9dPDaJdNB4+hipWTwscjFdQ3w2GpetwkDiH6nAEOsycpvrGemMaqT+j+Lh
WGBKf2sfN9WzRmOZ3zE9KrTjLMjFSdvp1llxPP8e2MaBiPAkU00mmkx4yb1hI66s
A4GEAAKBgH7Y8LHfm+GsM89dV69swqMEBH9/lWlbUf0ndwo7tgISA+80JS4kGoQa
ZruzLGdXMFAlMlfAjMmlzaGGE0AbsJzdlqYnR2sLdOGbw/dPbtXQnHhivgbRcpfW
duJwSuqeWYZo239LhZZT6YBBK2BJpL5WN+pLuI5JYyvHsBl9MMeYo4GZMIGWMHwG
A1UdIwR1MHOhZqRkMGIxCzAJBgNVBAYTAlNFMRIwEAYDVQQIEwlTdG9ja2hvbG0x
DjAMBgNVBAcTBUtpc3RhMR0wGwYDVQQKExRDZXJ0aWZpY2F0ZSBTZXJ2aWNlczEQ
MA4GA1UEAxMHZHNhY2VydIIJAPVEhTv6js6NMAkGA1UdEwQCMAAwCwYDVR0PBAQD
AgTwMAsGCWCGSAFlAwQDAgMxADAuAhUAlpn1ZLYugHpEuVnLmqLRjiFkDugCFQC0
15hNzaN2iwDNrwHgbpHCGEZErQ==
-----END CERTIFICATE-----'''


	public static String certwithECDSAKey = '''-----BEGIN CERTIFICATE-----
MIICWjCCAgGgAwIBAgIJALYl0TBT9pfBMAoGCCqGSM49BAMCMGQxCzAJBgNVBAYT
AlNFMRIwEAYDVQQIEwlTdG9ja2hvbG0xDjAMBgNVBAcTBUtpc3RhMR0wGwYDVQQK
ExRDZXJ0aWZpY2F0ZSBTZXJ2aWNlczESMBAGA1UEAxMJZWNkc2FjZXJ0MB4XDTE4
MDExNjEyNTMwNFoXDTI4MDExNDEyNTMwNFowZDELMAkGA1UEBhMCU0UxEjAQBgNV
BAgTCVN0b2NraG9sbTEOMAwGA1UEBxMFS2lzdGExHTAbBgNVBAoTFENlcnRpZmlj
YXRlIFNlcnZpY2VzMRIwEAYDVQQDEwllY2RzYWNlcnQwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAAStuFM9dl+sVqyvMHUom61t4VbUg77AYkULktrGijIW9bfbGXIy
jA0Dx18QfQcML4wq1lPujwWOg+cnUuk4fPp8o4GbMIGYMH4GA1UdIwR3MHWhaKRm
MGQxCzAJBgNVBAYTAlNFMRIwEAYDVQQIEwlTdG9ja2hvbG0xDjAMBgNVBAcTBUtp
c3RhMR0wGwYDVQQKExRDZXJ0aWZpY2F0ZSBTZXJ2aWNlczESMBAGA1UEAxMJZWNk
c2FjZXJ0ggkAtiXRMFP2l8EwCQYDVR0TBAIwADALBgNVHQ8EBAMCBPAwCgYIKoZI
zj0EAwIDRwAwRAIgD4Ea53lfIbZ6vNJ4n6SzoPLGaY1cNH8W/By9wnKu/BsCIHen
iB9zntNWErwN8r3X1JAC4vz5gDcTMev07YXRMkYK
-----END CERTIFICATE-----'''

	private X509Certificate certWithManyExtenstions
	private X509Certificate certWithFewExtenstions
}
