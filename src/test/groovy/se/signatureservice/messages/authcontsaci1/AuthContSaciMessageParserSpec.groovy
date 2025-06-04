package se.signatureservice.messages.authcontsaci1


import se.signatureservice.messages.authcontsaci1.jaxb.AttributeMappingType
import se.signatureservice.messages.authcontsaci1.jaxb.SAMLAuthContextType
import se.signatureservice.messages.saml2.assertion.jaxb.AttributeType
import se.signatureservice.messages.saml2.assertion.jaxb.NameIDType
import se.signatureservice.messages.sweeid2.dssextenstions1_1.jaxb.ContextInfoType
import se.signatureservice.messages.utils.MessageGenerateUtils
import spock.lang.Specification

/**
 * Created by philip on 2017-05-20.
 */
class AuthContSaciMessageParserSpec extends Specification {


    AuthContSaciMessageParser p = new AuthContSaciMessageParser()

    def currentTimeZone
    def setup(){
        currentTimeZone = TimeZone.getDefault()
        TimeZone.setDefault(TimeZone.getTimeZone("Europe/Stockholm"))
    }

    def cleanup(){
        TimeZone.setDefault(currentTimeZone)
    }

    def "Verify that external generated message can be parsed with the parser"(){
        when:
        SAMLAuthContextType ac = p.parse(externalSACI)
        then:
        ac.getAuthContextInfo().serviceID == "ca4104354a972bce"
        ac.getIdAttributes().attributeMapping.get(0).type == "rdn"
    }

    def "Verify that genSAMLAuthContext generates correct XML"(){

        when:
        byte[] data = p.genSAMLAuthContext(genContextInfoType(),genAttributeMappings())
        then:
        new String(data,"UTF-8") == """<saci:SAMLAuthContext xmlns:saci="http://id.elegnamnden.se/auth-cont/1.0/saci" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saci:AuthContextInfo IdentityProvider="SomeIdentityProvider" AuthenticationInstant="3917-02-01T00:00:00.000+01:00" AuthnContextClassRef="SomeAuthnContextClassRef" AssertionRef="SomeAssertionRef" ServiceID="SomeServiceID"/><saci:IdAttributes><saci:AttributeMapping Type="rdn" Ref="2.5.4.6"><saml:Attribute Name="urn:oid:2.5.4.6" FriendlyName="Land"><saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">SE</saml:AttributeValue></saml:Attribute></saci:AttributeMapping><saci:AttributeMapping Type="rdn" Ref="2.5.4.42"><saml:Attribute Name="urn:oid:2.5.4.42" FriendlyName="Förnamn"><saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">Valfrid</saml:AttributeValue></saml:Attribute></saci:AttributeMapping></saci:IdAttributes></saci:SAMLAuthContext>"""

    }

    private ContextInfoType genContextInfoType(){
        ContextInfoType cit = new ContextInfoType()
        cit.serviceID = "SomeServiceID"
        cit.authnContextClassRef = "SomeAuthnContextClassRef"
        cit.identityProvider = new NameIDType()
        cit.identityProvider.value = "SomeIdentityProvider"
        cit.authenticationInstant = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(2017,1,1))
        cit.assertionRef = "SomeAssertionRef"
        return cit
    }

    private List<AttributeMappingType> genAttributeMappings(){
        AttributeType attr1 = new AttributeType()
        attr1.name = "urn:oid:2.5.4.6"
        attr1.friendlyName = "Land"
        attr1.attributeValue.add("SE")
        AttributeMappingType amt1 = new AttributeMappingType()
        amt1.setRef("2.5.4.6")
        amt1.setType("rdn")
        amt1.setAttribute(attr1)

        AttributeType attr2 = new AttributeType()
        attr2.name = "urn:oid:2.5.4.42"
        attr2.friendlyName = "Förnamn"
        attr2.attributeValue.add("Valfrid")
        AttributeMappingType amt2 = new AttributeMappingType()
        amt2.setRef("2.5.4.42")
        amt2.setType("rdn")
        amt2.setAttribute(attr2)

        return [amt1,amt2]
    }

    static def externalSACI = """<saci:SAMLAuthContext xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:saci="http://id.elegnamnden.se/auth-cont/1.0/saci" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saci:AuthContextInfo ServiceID="ca4104354a972bce" AssertionRef="_0ec54156665f47e7ba4c961b296f94ae" IdentityProvider="https://m00-mg-local.testidp.funktionstjanster.se/samlv2/idp/metadata/0/0" AuthenticationInstant="2013-06-24T13:30:57.521+02:00" AuthnContextClassRef="http://id.elegnamnden.se/loa/1.0/loa3"/><saci:IdAttributes><saci:AttributeMapping Type="rdn" Ref="2.5.4.5"><saml:Attribute FriendlyName="Personnummer" Name="urn:oid:1.2.752.29.4.13"><saml:AttributeValue xsi:type="xsd:string">195006262546</saml:AttributeValue></saml:Attribute></saci:AttributeMapping><saci:AttributeMapping Type="rdn" Ref="2.5.4.6"><saml:Attribute FriendlyName="Land" Name="urn:oid:2.5.4.6"><saml:AttributeValue xsi:type="xsd:string">SE</saml:AttributeValue></saml:Attribute></saci:AttributeMapping><saci:AttributeMapping Type="rdn" Ref="2.5.4.42"><saml:Attribute FriendlyName="Förnamn" Name="urn:oid:2.5.4.42"><saml:AttributeValue xsi:type="xsd:string">Valfrid</saml:AttributeValue></saml:Attribute></saci:AttributeMapping><saci:AttributeMapping Type="rdn" Ref="2.5.4.3"><saml:Attribute FriendlyName="Användarnamn" Name="urn:oid:2.16.840.1.113730.3.1.241"><saml:AttributeValue xsi:type="xsd:string">Valfrid Lindeman</saml:AttributeValue></saml:Attribute></saci:AttributeMapping><saci:AttributeMapping Type="rdn" Ref="2.5.4.4"><saml:Attribute FriendlyName="Efternamn" Name="urn:oid:2.5.4.4"><saml:AttributeValue xsi:type="xsd:string">Lindeman</saml:AttributeValue></saml:Attribute></saci:AttributeMapping><saci:AttributeMapping Type="san" Ref="1"><saml:Attribute FriendlyName="E-post" Name="urn:oid:0.9.2342.19200300.100.1.3"><saml:AttributeValue xsi:type="xsd:string">vli@example.com</saml:AttributeValue></saml:Attribute></saci:AttributeMapping></saci:IdAttributes></saci:SAMLAuthContext>""".getBytes("UTF-8")
}
