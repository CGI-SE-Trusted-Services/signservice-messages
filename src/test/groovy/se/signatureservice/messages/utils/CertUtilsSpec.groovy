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
package se.signatureservice.messages.utils

import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.util.encoders.Base64
import spock.lang.Specification

import java.security.cert.CertificateFactory
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

	def "test GetSubject"() {
		when:
		X509Certificate cert = CertUtils.getX509CertificateFromPEMorDER(Base64.decode(base64Cert))
		String issuerDN = CertUtils.getSubject(cert)
		then:
		issuerDN.equals("CN=Test eIDCA,O=Test")
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
		CertUtils.getSubjectDNFields((String) null, null).isEmpty()
		CertUtils.getSubjectDNFields((String) null, BCStyle.CN).isEmpty()
		CertUtils.getSubjectDNFields("CN=Test eIDCA,givenNAme=Test, surname=eIDCS, serialNumber=123456,O=Test,c=SE", BCStyle.INITIALS).isEmpty()
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


	public static byte[] base64LotOfExtensitonsCert = (
			"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").getBytes()

	private X509Certificate certWithManyExtenstions
	private X509Certificate certWithFewExtenstions
}
