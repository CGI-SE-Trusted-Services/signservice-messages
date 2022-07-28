package org.certificateservices.messages.sensitivekeys

import org.apache.xml.security.Init
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.certificateservices.messages.DummyMessageSecurityProvider
import org.certificateservices.messages.MessageContentException
import org.certificateservices.messages.MessageSecurityProvider
import org.certificateservices.messages.sensitivekeys.jaxb.KeyData
import org.certificateservices.messages.sensitivekeys.jaxb.ObjectFactory
import spock.lang.Specification

import groovy.xml.XmlSlurper
import javax.crypto.KeyGenerator
import java.security.*
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

/**
 * Created by philip on 02/03/17.
 */
class SensitiveKeysParserSpec extends Specification {

    SensitiveKeysParser pp
    X509Certificate recipient
    ObjectFactory of = new ObjectFactory()

    Key symmetricKey
    KeyPair asymmetricRSAKey
    KeyPair asymmetricECKey

    KeyFactory rsaKeyFactory

    def TimeZone currentTimeZone;
    def setupSpec(){
        Security.addProvider(new BouncyCastleProvider())
        Init.init();
    }

    def setup(){
        currentTimeZone = TimeZone.getDefault()
        TimeZone.setDefault(TimeZone.getTimeZone("Europe/Stockholm"))
        DummyMessageSecurityProvider secprov = new DummyMessageSecurityProvider();
        pp = new SensitiveKeysParser(secprov)

        recipient = secprov.getDecryptionCertificate(MessageSecurityProvider.DEFAULT_DECRYPTIONKEY)

        rsaKeyFactory = KeyFactory.getInstance("RSA")

        KeyGenerator aeskeyGen = KeyGenerator.getInstance("AES");
        aeskeyGen.init(256);
        symmetricKey = aeskeyGen.generateKey();

        KeyPairGenerator rsakeyGen = KeyPairGenerator.getInstance("RSA")
        rsakeyGen.initialize(1024)
        asymmetricRSAKey = rsakeyGen.generateKeyPair()

        KeyPairGenerator eccKeyGen = KeyPairGenerator.getInstance("EC")
        ECGenParameterSpec ecsp = new ECGenParameterSpec("secp256r1");
        eccKeyGen.initialize(ecsp);

        asymmetricECKey = eccKeyGen.generateKeyPair()
    }

    def cleanup(){
        TimeZone.setDefault(currentTimeZone)
    }

    def "Verify that encrypt and marshalling of symmetric key generates valid XML and then decrypted and marshalled back into a jaxb object with same values"(){
        when:
        byte[] data = pp.encryptAndMarshall(pp.genKeyData(symmetricKey),[recipient])
        //printXML(data)
        then:
        new String(data,"UTF-8").contains("xenc:EncryptedData")

        when:
        KeyData kd = pp.decryptAndParse(data)
        then:
        kd.version == "2.0"
        kd.symmetricKey.algorithm == "AES"
        kd.symmetricKey.data.length > 0
        kd.symmetricKey.format == "RAW"

        when: "Try to reconstruct symmetric key"
        Key symKey = pp.getSymmetricKey(kd)

        then:
        symKey == symmetricKey
    }

    def """Verify that encrypt and marshalling of asymmetric RSA key generates valid XML and then decrypted and marshalled back into a jaxb object with same values"""(){
        when:
        byte[] data = pp.encryptAndMarshall(pp.genKeyData(asymmetricRSAKey),[recipient])
        //printXML(data)
        then:
        new String(data,"UTF-8").contains("xenc:EncryptedData")

        when:
        KeyData kd = pp.decryptAndParse(data)
        then:
        kd.version == "2.0"
        kd.asymmetricKey.publicKey.algorithm == "RSA"
        kd.asymmetricKey.publicKey.data.length > 0
        kd.asymmetricKey.publicKey.format == "X.509"
        kd.asymmetricKey.privateKey.algorithm == "RSA"
        kd.asymmetricKey.privateKey.data.length > 0
        kd.asymmetricKey.privateKey.format == "PKCS#8"
        when: "Try to reconstruct asymmetric key"
        KeyPair kp = pp.getAssymmetricKey(kd)

        then:
        kp.private.encoded == asymmetricRSAKey.private.encoded
        kp.public.encoded == asymmetricRSAKey.public.encoded
    }

    def """Verify that encrypt and marshalling of asymmetric EC key generates valid XML and then decrypted and marshalled back into a jaxb object with same values"""(){
        when:
        byte[] data = pp.encryptAndMarshall(pp.genKeyData(asymmetricECKey),[recipient])
        //printXML(data)
        then:
        new String(data,"UTF-8").contains("xenc:EncryptedData")

        when:
        KeyData kd = pp.decryptAndParse(data)
        then:
        kd.version == "2.0"
        kd.asymmetricKey.publicKey.algorithm == "EC"
        kd.asymmetricKey.publicKey.data.length > 0
        kd.asymmetricKey.publicKey.format == "X.509"
        kd.asymmetricKey.privateKey.algorithm == "EC"
        kd.asymmetricKey.privateKey.data.length > 0
        kd.asymmetricKey.privateKey.format == "PKCS#8"
        when: "Try to reconstruct asymmetric key"
        KeyPair kp = pp.getAssymmetricKey(kd)

        then:
        kp.private.encoded == asymmetricECKey.private.encoded
        kp.public.encoded == asymmetricECKey.public.encoded
    }

    def """Verify that marshall without encrypting generates a valid xml"""(){
        when:
        byte[] data = pp.marshall(pp.genKeyData(symmetricKey))
        //printXML(data)
        def xml = new XmlSlurper().parseText(new String(data,"UTF-8"))
        then:
        xml.@version == "2.0"
        xml.symmetricKey.algorithm == "AES"
        xml.symmetricKey.data.toString().length() > 0
        xml.symmetricKey.format == "RAW"
        when: // Try to unmarshall
        KeyData kd = pp.parse(data)
        then:
        kd.version == "2.0"
        kd.symmetricKey.algorithm == "AES"
        kd.symmetricKey.data.length > 0
        kd.symmetricKey.format == "RAW"
    }


    def "Verify that getAssymmetricKey throws MessageContentException for invalid data format or encoding"(){
        setup:
        KeyData kd = pp.genKeyData(asymmetricRSAKey)
        when:
        kd.asymmetricKey.publicKey.format = "NONSUPPORTED"
        pp.getAssymmetricKey(kd)
        then:
        thrown(MessageContentException)
        when:
        kd = pp.genKeyData(asymmetricRSAKey) // Reset data
        kd.asymmetricKey.privateKey.format = "NONSUPPORTED"
        pp.getAssymmetricKey(kd)
        then:
        thrown(MessageContentException)
        when:
        kd = pp.genKeyData(asymmetricRSAKey) // Reset data
        kd.asymmetricKey.publicKey.algorithm = "NONSUPPORTED"
        pp.getAssymmetricKey(kd)
        then:
        thrown(MessageContentException)
        when:
        kd = pp.genKeyData(asymmetricRSAKey) // Reset data
        kd.asymmetricKey.publicKey.data = "INVALID".getBytes()
        pp.getAssymmetricKey(kd)
        then:
        thrown(MessageContentException)
        when:
        kd = pp.genKeyData(asymmetricRSAKey) // Reset data
        kd.asymmetricKey.privateKey.data = "INVALID".getBytes()
        pp.getAssymmetricKey(kd)
        then:
        thrown(MessageContentException)

    }

}
