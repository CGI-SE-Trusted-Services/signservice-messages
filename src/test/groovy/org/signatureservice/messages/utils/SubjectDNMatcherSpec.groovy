package org.signatureservice.messages.utils

import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.util.encoders.Base64
import spock.lang.Specification

import java.security.cert.X509Certificate

/**
 * Created by philip on 2017-08-07.
 */
class SubjectDNMatcherSpec extends Specification {

    SubjectDNMatcher matcher = new SubjectDNMatcher()



    def setupSpec(){
        CertUtils.installBCProvider()
    }

    def "Verify that correct asn1 identifier is found for a given symbol"(){
        expect:
        matcher.getIdentifier("CN") == BCStyle.CN
        matcher.getIdentifier("cN") == BCStyle.CN
        matcher.getIdentifier("countryofcitizenship") == BCStyle.COUNTRY_OF_CITIZENSHIP
        matcher.getIdentifier("unknown" ) == null
    }

    def "Verify that subjectMatch returns true if a certificate has a field that matches"(){
        setup:
        X509Certificate cert = CertUtils.getCertfromByteArray(Base64.decode(CertUtilsSpec.base64LotOfExtensitonsCert))
        println cert.subjectDN.toString()
        expect:
        matcher.subjectMatch(cert,"Cn"," Kalle Anka  ")
        !matcher.subjectMatch(cert,"Cn"," Arne Anka  ")
        !matcher.subjectMatch(cert,"unknown", "unknown")
        matcher.subjectMatch(cert, BCStyle.CN," Kalle Anka  ")
        !matcher.subjectMatch(cert, BCStyle.OU," Kalle Anka  ")
    }
}
