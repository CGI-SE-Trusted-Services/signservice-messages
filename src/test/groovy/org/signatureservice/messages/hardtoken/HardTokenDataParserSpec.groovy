package org.signatureservice.messages.hardtoken

import org.bouncycastle.jce.provider.BouncyCastleProvider

import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.apache.xml.security.Init;
import org.apache.xml.security.utils.Base64;
import org.signatureservice.messages.DummyMessageSecurityProvider;
import org.signatureservice.messages.MessageContentException;
import org.signatureservice.messages.MessageSecurityProvider;
import org.signatureservice.messages.hardtoken.jaxb.HardTokenData;
import org.signatureservice.messages.hardtoken.jaxb.ObjectFactory;
import org.signatureservice.messages.hardtoken.jaxb.PINData;
import org.signatureservice.messages.utils.MessageGenerateUtils;
import spock.lang.Specification

class HardTokenDataParserSpec extends Specification {
	
	HardTokenDataParser pp;
	ObjectFactory of = new ObjectFactory()
	
	X509Certificate recipient
	
	def TimeZone currentTimeZone;
	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Init.init();
	}
	
	def setup(){
		currentTimeZone = TimeZone.getDefault()
		TimeZone.setDefault(TimeZone.getTimeZone("Europe/Stockholm"))
		DummyMessageSecurityProvider secprov = new DummyMessageSecurityProvider();
		pp = new HardTokenDataParser(secprov)
		
		recipient = secprov.getDecryptionCertificate(MessageSecurityProvider.DEFAULT_DECRYPTIONKEY)
		
	}

	def cleanup(){
		TimeZone.setDefault(currentTimeZone)
	}


	def "Verify that parse method validates agains schema"(){
		setup:
		def htd = of.createHardTokenData()
		byte[] data = pp.marshall(htd)
		when:
		pp.parse(data)
		then:
		thrown MessageContentException
		
	}	
	
	def "Verify that marshall and parse generates and parser valid XML"(){
		setup:
		def htd = genHardTokenData()
		when:
		byte[] data = pp.marshall(htd) 
		String message = new String(data, "UTF-8")
       // printXML(message)
		def xml = slurpXml(message)
		then:
        message =~ 'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"'
        message =~ 'xmlns:xenc="http://www.w3.org/2001/04/xmlenc#'
        message =~ 'xmlns:hardtoken="http://certificateservices.org/xsd/hardtoken"'
		
		xml.@version == HardTokenDataParser.DEFAULT_VERSION
		xml.tokenType == "SomeTokenType"
		xml.tokenClass == "Ordinary"
		xml.tokenImplementation == "org.test.SomeTokenImplementation"
		xml.serialNumber == "443322"
		xml.pinDatas.pin[0].name == "BASIC"
		xml.pinDatas.pin[0].initialPIN == "foo123"
		xml.pinDatas.pin[0].pUK == "12345678"
		xml.pinDatas.pin[1].name == "SIGNATURE"
		xml.pinDatas.pin[1].initialPIN == "foo124"
		xml.pinDatas.pin[1].pUK == "87654321"
		xml.supportsRemoteUnblock == "true"
		xml.encKeyKeyRecoverable == "true"
		
		xml.createTime == "1970-01-01T01:02:03.000+01:00"
		xml.modifyTime == "1970-01-01T01:02:04.000+01:00"
		
		when:
		HardTokenData htd2 = pp.parse(data)
		
		then:
		htd2 != null
	}
	
	def "Verify that genHardTokenData generates a basic HardTokenData structure without any key recovery functionality"(){
		setup:
		PINData p1 = of.createPINData()
		p1.initialPIN = "foo123"
		p1.name = "BASIC"
		p1.puk = "12345678"
		
		PINData p2 = of.createPINData()
		p2.initialPIN = "foo124"
		p2.name = "SIGNATURE"
		p2.puk = "87654321"
		def pins = [p1,p2]
		when:
		def htd = pp.genHardTokenData("SomeTokenType", "SomeTokenClass", "SomeSerialNumber", true, new Date(123000L),new Date(124000L),pins)
		then:
		htd.version == HardTokenDataParser.DEFAULT_VERSION
		htd.tokenType == "SomeTokenType"
		htd.tokenClass == "SomeTokenClass"
		htd.serialNumber == "SomeSerialNumber"
		htd.supportsRemoteUnblock
		!htd.encKeyKeyRecoverable
		MessageGenerateUtils.xMLGregorianCalendarToDate(htd.createTime).time == 123000L
		MessageGenerateUtils.xMLGregorianCalendarToDate(htd.modifyTime).time == 124000L
		htd.getPinDatas().getPin().size() == 2
		htd.getPinDatas().getPin()[0].name == "BASIC"
		htd.getPinDatas().getPin()[1].name == "SIGNATURE"
		htd.copyOfSN == null
		htd.copies == null
		
	}
	
	def "Verify that encryptAndMarshall generates a valid EncryptedData xml enc structure and decryptAndParse can parse it back again."(){
		setup:
		HardTokenData htd = genHardTokenData()
		
		def cf = CertificateFactory.getInstance("X.509")
		when:
		byte[] data = pp.encryptAndMarshall(htd, [recipient])
		String message = new String(data, "UTF-8")
		//printXML(message)
		def xml = slurpXml(message)
		then:
		message =~ 'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"'
		message =~ 'xmlns:xenc="http://www.w3.org/2001/04/xmlenc#'
		
		cf.generateCertificate(new ByteArrayInputStream(Base64.decode(xml.KeyInfo.EncryptedKey.KeyInfo.X509Data.X509Certificate.toString().getBytes()))) == recipient
		
		when:
		HardTokenData htd2 = pp.decryptAndParse(data)
		then:
		htd2.serialNumber == htd.serialNumber
	}

	

	private HardTokenData genHardTokenData(){
		PINData p1 = of.createPINData()
		p1.initialPIN = "foo123"
		p1.name = "BASIC"
		p1.puk = "12345678"
		
		PINData p2 = of.createPINData()
		p2.initialPIN = "foo124"
		p2.name = "SIGNATURE"
		p2.puk = "87654321"
		
		HardTokenData htd = of.createHardTokenData()
		htd.version = HardTokenDataParser.DEFAULT_VERSION
		htd.copyOfSN = "snr1"
		htd.createTime = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(123000L))
		htd.encKeyKeyRecoverable = true
		htd.modifyTime = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(124000L))
		htd.serialNumber = "443322"
		htd.supportsRemoteUnblock = "true"
		htd.tokenType = "SomeTokenType"
		htd.tokenClass = "Ordinary"
		htd.tokenImplementation = "org.test.SomeTokenImplementation"
		
		htd.pinDatas = of.createHardTokenDataPinDatas()
		htd.pinDatas.getPin().add(p1)
		htd.pinDatas.getPin().add(p2)
		return htd
	}
}
