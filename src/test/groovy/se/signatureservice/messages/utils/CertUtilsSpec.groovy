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

	private X509Certificate certWithManyExtenstions
	private X509Certificate certWithFewExtenstions
}
