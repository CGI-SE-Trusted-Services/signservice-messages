package se.signatureservice.messages.saml2

import org.apache.xml.security.Init
import org.apache.xml.security.utils.Base64
import org.bouncycastle.jce.provider.BouncyCastleProvider
import se.signatureservice.messages.DummyMessageSecurityProvider
import se.signatureservice.messages.MessageSecurityProvider
import se.signatureservice.messages.saml2.assertion.SAMLAssertionMessageParser
import se.signatureservice.messages.utils.SystemTime
import se.signatureservice.messages.xmldsig.jaxb.ObjectFactory
import org.w3c.dom.Document
import spock.lang.Specification

import javax.xml.transform.OutputKeys
import javax.xml.transform.Transformer
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat

class CommonSAMLMessageParserSpecification extends Specification {


	SAMLAssertionMessageParser samp;
	se.signatureservice.messages.saml2.assertion.jaxb.ObjectFactory of = new se.signatureservice.messages.saml2.assertion.jaxb.ObjectFactory()
	se.signatureservice.messages.saml2.protocol.jaxb.ObjectFactory samlpOf = new se.signatureservice.messages.saml2.protocol.jaxb.ObjectFactory()
    ObjectFactory dsignObj = new ObjectFactory()

	CertificateFactory cf
	
	List<X509Certificate> twoReceiptiensValidFirst
	
	MessageSecurityProvider secProv = new DummyMessageSecurityProvider();

	SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");
	

	def mockedSystemTime

	def currentTimeZone

	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Init.init()
	}

	def setup(){
		currentTimeZone = TimeZone.getDefault()
		TimeZone.setDefault(TimeZone.getTimeZone("Europe/Stockholm"))

		mockedSystemTime = Mock(SystemTime)
		mockedSystemTime.getSystemTime() >> new Date(1436279213000)

		samp = new SAMLAssertionMessageParser();
		samp.init(secProv, null);
		samp.systemTime  = mockedSystemTime

		cf = CertificateFactory.getInstance("X.509")
		X509Certificate invalidCert = cf.generateCertificate(new ByteArrayInputStream(Base64.decode(base64Cert)))
		X509Certificate validCert = samp.messageSecurityProvider.getDecryptionCertificate(samp.messageSecurityProvider.decryptionKeyIds.iterator().next())

		twoReceiptiensValidFirst = [validCert,invalidCert]

	}

	def cleanup(){
		TimeZone.setDefault(currentTimeZone)
	}

	protected String docToString(Document doc) throws Exception {

		ByteArrayOutputStream bo = new ByteArrayOutputStream();

		TransformerFactory factory = TransformerFactory.newInstance();
		Transformer transformer = factory.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		transformer.setOutputProperty(OutputKeys.INDENT, "yes");
		DOMSource source = new DOMSource(doc);
		StreamResult result = new StreamResult(bo);
		transformer.transform(source, result);

		bo.close();
		return new String(bo.toByteArray(),"UTF-8")

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
		"Vw==").getBytes();

}
