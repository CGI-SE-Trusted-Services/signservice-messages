package org.signatureservice.messages.xades.v132

import org.signatureservice.messages.xades.v132.jaxb.QualifyingPropertiesType
import org.signatureservice.messages.xmldsig.jaxb.ObjectFactory
import org.signatureservice.messages.xmldsig.jaxb.ObjectType
import spock.lang.Specification

/**
 * Created by philip on 2017-04-05.
 */
class UnsignedXadesParserSpec extends Specification {

    UnsignedXadesParser parser = new UnsignedXadesParser()

    ObjectFactory dsOf = new ObjectFactory()

    def xadesMsg = """<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"  Target="#id-31223380321b5583b18ebe9e56fc8b38">
<xades:SignedProperties Id="xades-88efae1f299bedee2f006ee269a438e0">
  <xades:SignedSignatureProperties>
    <xades:SigningTime>1970-01-01T01:00:05.000+01:00</xades:SigningTime>
  </xades:SignedSignatureProperties>
  <xades:SignedDataObjectProperties>
  </xades:SignedDataObjectProperties>
</xades:SignedProperties>
</xades:QualifyingProperties></ds:Object>""".getBytes("UTF-8")

    def "Verify that parseUnsignedMessage parses and marshallUnsignedMessage generates a XADES xml object correctly"(){
        when:
        ObjectType o = parser.parseUnsignedMessage(xadesMsg)
        then:
        o.getContent()[0].value instanceof QualifyingPropertiesType

        when:
        byte[] data = parser.marshallUnsignedMessage(dsOf.createObject(o))
        then:
        new String(data,"UTF-8") == """<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"><xades:QualifyingProperties Target="#id-31223380321b5583b18ebe9e56fc8b38"><xades:SignedProperties Id="xades-88efae1f299bedee2f006ee269a438e0"><xades:SignedSignatureProperties><xades:SigningTime>1970-01-01T01:00:05.000+01:00</xades:SigningTime></xades:SignedSignatureProperties><xades:SignedDataObjectProperties/></xades:SignedProperties></xades:QualifyingProperties></ds:Object>"""

    }


}
