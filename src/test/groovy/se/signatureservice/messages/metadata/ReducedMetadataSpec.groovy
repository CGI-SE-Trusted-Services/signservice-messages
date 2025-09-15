package se.signatureservice.messages.metadata

import groovy.json.JsonSlurper
import org.apache.xml.security.Init
import se.signatureservice.messages.DummyMessageSecurityProvider
import se.signatureservice.messages.csmessages.manager.MessageSecurityProviderManager
import se.signatureservice.messages.utils.CertUtils
import spock.lang.Ignore
import spock.lang.Specification

/**
 * Created by fredrik 2025-08-28.
 */
class ReducedMetadataSpec extends Specification {
    ReducedMetadata withEntityAttributes
    ReducedMetadata withoutEntityAttributes
    ReducedMetadata withOrgAsDisplayNameSource
    ReducedMetadata withKeyAsDisplayNameSource
    ReducedMetadata withNoDisplayNameSources
    ReducedMetadata withDisplayNameSourceInSecondRoleDescriptor
    ReducedMetadata withAttributeConsumingServices

    def setupSpec() {
        Init.init()
        CertUtils.installBCProvider()
        MessageSecurityProviderManager.initMessageSecurityProvider(new DummyMessageSecurityProvider())
    }

    def setup() {
        withEntityAttributes = ReducedMetadataIO.fromBytes(metaDataWithExtensions, false).get(0)
        withoutEntityAttributes = ReducedMetadataIO.fromBytes(metaDataWithNoExtensions, false).get(0)
        withOrgAsDisplayNameSource = ReducedMetadataIO.fromBytes(metaDataNoUIInfo, false).get(0)
        withKeyAsDisplayNameSource = ReducedMetadataIO.fromBytes(metaDataWithKey, false).get(0)
        withNoDisplayNameSources = ReducedMetadataIO.fromBytes(metaDataNoDisplayNameSources, false).get(0)
        withDisplayNameSourceInSecondRoleDescriptor = ReducedMetadataIO.fromBytes(metaDataWithUIInfoInSecondRoleDescriptor, false).get(0)
        withAttributeConsumingServices = ReducedMetadataIO.fromBytes(metaDataWithAttributeConsumingServices, false).get(0)
    }

    def "Verify that hasEntityAttributeValue looks upp correct name"() {
        expect:
        withEntityAttributes.hasEntityAttributeValue("urn:oasis:names:tc:SAML:attribute:assurance-certification", "http://id.elegnamnden.se/loa/1.0/loa3-sigmessage")
        !withEntityAttributes.hasEntityAttributeValue("urn:oasis:names:tc:SAML:attribute:assurance-certification", "http://id.elegnamnden.se/loa/1.0/loa2-sigmessage")
        !withEntityAttributes.hasEntityAttributeValue("urn:oasis:names:tc:SAML:attribute:assurance-certification", "urn:oid:1.2.246.517.3002.110.3")
        withEntityAttributes.hasEntityAttributeValue("FinnishAuthMethod", "urn:oid:1.2.246.517.3002.110.3")
        !withoutEntityAttributes.hasEntityAttributeValue("urn:oasis:names:tc:SAML:attribute:assurance-certification", "http://id.elegnamnden.se/loa/1.0/loa2-sigmessage")
    }

    @Ignore
    def "Test verify signature"() {
        setup:
        //MetaDataBuilder.parse(signed, true) as EntityDescriptor
        expect:
        true
    }

    def "Test displayName"() {
        setup:
        def svName = withoutEntityAttributes.getDisplayName("sv", "en")
        def enName = withoutEntityAttributes.getDisplayName("en", "en")
        def deName = withoutEntityAttributes.getDisplayName("de", "en")
        def noLangName    = withoutEntityAttributes.getDisplayName(null, "en")


        def svName2 = withOrgAsDisplayNameSource.getDisplayName("sv", "en")
        def enName2 = withOrgAsDisplayNameSource.getDisplayName("en", "en")
        def deName2 = withOrgAsDisplayNameSource.getDisplayName("de", "en")
        def noLangName2    = withOrgAsDisplayNameSource.getDisplayName(null, "en")

        def svName3 = withNoDisplayNameSources.getDisplayName("sv", "en")
        def enName3 = withNoDisplayNameSources.getDisplayName("en", "en")
        def deName3 = withNoDisplayNameSources.getDisplayName("de", "en")
        def noLangName3    = withNoDisplayNameSources.getDisplayName(null, "en")

        def svName4 = withKeyAsDisplayNameSource.getDisplayName("sv", "en")

        def deName5 = withDisplayNameSourceInSecondRoleDescriptor.getDisplayName("de", "en")

        expect:
        svName == "UIInfo EN"
        enName == "UIInfo EN"
        deName == "UIInfo DE"
        noLangName == "UIInfo EN"

        svName2 == "Org SV"
        enName2 == "Org EN"
        deName2 == "Org EN"
        noLangName2 == "Org EN"

        svName3 == null
        enName3 == null
        deName3 == null
        noLangName3 == null

        svName4 == "eid.test.legitimeringstjanst.se"
        deName5 == "UIInfo in second roleDescriptor DE"
    }

    def "Verify json serialisation 1"() {
        setup:
        def json = ReducedMetadataIO.asJson(withEntityAttributes)
        def slurper = new JsonSlurper()
        def tree = slurper.parseText(json)

        expect:
        tree.attributeConsumingServices == []
        tree.entityAttributes == [
                "FinnishAuthMethod"                                        : ["urn:oid:1.2.246.517.3002.110.1", "urn:oid:1.2.246.517.3002.110.2", "urn:oid:1.2.246.517.3002.110.3", "urn:oid:1.2.246.517.3002.110.5", "urn:oid:1.2.246.517.3002.110.6", "urn:oid:1.2.246.517.3002.110.999"],
                "urn:oasis:names:tc:SAML:attribute:assurance-certification": ["http://id.elegnamnden.se/loa/1.0/loa3", "http://id.elegnamnden.se/loa/1.0/loa3-sigmessage"]
        ]
        tree.entityID == "https://idp.switch.ch/idp/shibboleth"
        tree.requestedPrincipalSelection == ["urn:oid:1.2.752.29.4.13", "urn:oid:1.2.752.29.4.14"]
        tree.roleDescriptors == [[
                                         "elementLocalName": "IDPSSODescriptorType",
                                         "errorMessages"   : ["Error no trusted X509Certificate could be found in MetaData"],
                                         signingCertificates:[],
                                         "uiInfos"         : [[
                                                                      "displayNames": [[
                                                                                               "lang" : "en",
                                                                                               "value": "UIInfo EN"
                                                                                       ], [
                                                                                               "lang" : "de",
                                                                                               "value": "UIInfo DE"
                                                                                       ]]
                                                              ]]
                                 ]]
        tree.singleSignOnServices == [[
                                              "binding" : "http://ssobinding1.com",
                                              "location": "http://ssolocation1.com"
                                      ]]
    }

    def "Verify json serialisation 2"() {
        setup:
        def json = ReducedMetadataIO.asJson(withAttributeConsumingServices)
        def slurper = new JsonSlurper()
        def tree = slurper.parseText(json)

        expect:
        tree.attributeConsumingServices == [ [
                                                 "names" : [ "Sweden Connect Test-SP             för eIDAS", "Sweden Connect Test SP     for eIDAS" ],
                                                 "requestedAttributes" : [ [
                                                                               "name" : "urn:oid:1.2.752.29.4.13",
                                                                               "required" : false
                                                                           ], [
                                                                               "name" : "urn:oid:1.2.752.201.3.7",
                                                                               "required" : false
                                                                           ], [
                                                                               "name" : "urn:oid:1.2.752.201.3.4",
                                                                               "required" : true
                                                                           ] ]
                                                 ] ]
        tree.entityAttributes == [
                "http://macedir.org/entity-category": ["http://id.elegnamnden.se/st/1.0/public-sector-sp", "http://id.elegnamnden.se/ec/1.0/eidas-naturalperson"]
        ]
        tree.entityID == "urn:visma:ticket-server:eidas-sp-pubtest"
        tree.requestedPrincipalSelection == []
        tree.roleDescriptors == [[
                                         "elementLocalName"      : "SPSSODescriptorType",
                                         "errorMessages"         : [],
                                         "signingCertificates"   : ["MIIDXjCCAkYCCQCHiKACz5NJPTANBgkqhkiG9w0BAQUFADBxMQswCQYDVQQGEwJTRTEOMAwGA1UECgwFVmlzbWExEzARBgNVBAsMCkNvbnN1bHRpbmcxGzAZBgNVBAMMEnRpY2tldC1zZXJ2ZXItdGVzdDEgMB4GCSqGSIb3DQEJARYRY2ljZXJvbkB2aXNtYS5jb20wHhcNMTUwMjA5MDkyNDMxWhcNMjUwMjA2MDkyNDMxWjBxMQswCQYDVQQGEwJTRTEOMAwGA1UECgwFVmlzbWExEzARBgNVBAsMCkNvbnN1bHRpbmcxGzAZBgNVBAMMEnRpY2tldC1zZXJ2ZXItdGVzdDEgMB4GCSqGSIb3DQEJARYRY2ljZXJvbkB2aXNtYS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCuWktafleN0P63DYefjInOGrzePfeSSFZfd17rPjdLsd63Cm3Sx6frZMNh0VL8684C2nBy9JK1uZbckUV7dWFFzcG7RobaGCdeS6DwIBHAm0Z4Kg3Eex18bk7VMIXl80BUlPvMS8lGC0z8V5wUxvR/o+mt8h2MP+SNVTvMwz/KFyo5HkpRyFH1M+PNJKWsS4Vk5pscPLXKzASirLQ1iWMXgbSu0iPeV8/Iz+KnGwv9VQk84mDQ1I7EuRUHTrZ3zcurZ+1DV2wxKh85J88ewMtcItL6jphjv9RgCPmAyqs05Ow0CVwrkXCkP8u7dqX1P3yMN8oWHWQP1kuCnLp5E9FFAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBADlINW5OcMpxhzrxFvOOlzTPPAfGUfihNlyvpg9Y9xrtMJylMtThL63tX/LoeUIWsy0wYlbsuL+x5mNa/N/M3bpsVYka3jRQamB3g2+etXP0fnvKIdn6ecAcSkmjzTCX9yhflwTmeryas4GO7NG66o42AVk34X85jmN9uLOYzI0pRwT3j5XEv7jP8ffCef2FrHvR0HHp1kCSNl/slVANlaLbAy3XzTZwz0FPKqMUBZgaKGSAHXA0blaX+zW3XcZ0Y6jH625dFWOWogaBEQWIujf1EZl2JDu7WPfPELgG2ixmitIGl0n/wbUZR2WwEhggLqsXWBRxADb5w/LKRI3xaQU="],
                                         "signingCertificatesCNs": ["ticket-server-test"],
                                         "uiInfos"               : [[
                                                                            "displayNames": [[
                                                                                                     "lang" : "en",
                                                                                                     "value": "Visma-test eIDAS     SP"
                                                                                             ], [
                                                                                                     "lang" : "sv",
                                                                                                     "value": "Visma-test eIDAS     SP"
                                                                                             ]]
                                                                    ]]
                                 ]]
        tree.singleSignOnServices == []
        tree.organisation == [
                "displayNames": [[
                                         "lang" : "en",
                                         "value": "Visma eIDAS     Test-SP"
                                 ], [
                                         "lang" : "sv",
                                         "value": "Visma eIDAS     Test-SP"
                                 ]]
        ]
    }


    static def metaDataWithExtensions = """
<EntityDescriptor entityID="https://idp.switch.ch/idp/shibboleth" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <Extensions>
    <mdattr:EntityAttributes
          xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute">
      <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            Name="FinnishAuthMethod"
            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" 
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
              xsi:type="xs:string">
          urn:oid:1.2.246.517.3002.110.1
        </saml:AttributeValue>
        <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" 
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
              xsi:type="xs:string">
          urn:oid:1.2.246.517.3002.110.2
        </saml:AttributeValue>
        <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" 
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
              xsi:type="xs:string">
          urn:oid:1.2.246.517.3002.110.3
        </saml:AttributeValue>
        <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" 
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
              xsi:type="xs:string">
          urn:oid:1.2.246.517.3002.110.5
        </saml:AttributeValue>
        <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" 
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
              xsi:type="xs:string">
          urn:oid:1.2.246.517.3002.110.6
        </saml:AttributeValue>
        <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" 
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
              xsi:type="xs:string">
          urn:oid:1.2.246.517.3002.110.999
        </saml:AttributeValue>
      </saml:Attribute>
            <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            Name="urn:oasis:names:tc:SAML:attribute:assurance-certification"
            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" 
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
              xsi:type="xs:string">
          http://id.elegnamnden.se/loa/1.0/loa3
        </saml:AttributeValue>
        <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" 
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
              xsi:type="xs:string">
          http://id.elegnamnden.se/loa/1.0/loa3-sigmessage
        </saml:AttributeValue>
      </saml:Attribute>
    </mdattr:EntityAttributes>
  </Extensions>
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <Extensions>
      <mdui:UIInfo>
        <mdui:DisplayName xml:lang="en">UIInfo EN</mdui:DisplayName>
        <mdui:DisplayName xml:lang="de">UIInfo DE</mdui:DisplayName>
        <mdui:Description xml:lang="en">
            Switzerland's national research and eduction network.
        </mdui:Description>
        <mdui:Description xml:lang="de">
            Das schweizerische Hochschul- und Forschungsnetzwerk.
        </mdui:Description>
        <mdui:Logo height="16" width="16">https://switch.ch/resources/images/smalllogo.png</mdui:Logo>
        <mdui:Logo height="97" width="172">https://switch.ch/resources/images/logo.png</mdui:Logo>
        <mdui:InformationURL xml:lang="en">http://switch.ch</mdui:InformationURL>
        <mdui:InformationURL xml:lang="de">http://switch.ch/de</mdui:InformationURL>
      </mdui:UIInfo>
      <mdui:DiscoHints>
        <mdui:IPHint>130.59.0.0/16</mdui:IPHint>
        <mdui:IPHint>2001:620::0/96</mdui:IPHint>
        <mdui:DomainHint>switch.ch</mdui:DomainHint>
        <mdui:GeolocationHint>geo:47.37328,8.531126</mdui:GeolocationHint>
      </mdui:DiscoHints>
      <psc:RequestedPrincipalSelection
                    xmlns:psc="http://id.swedenconnect.se/authn/1.0/principal-selection/ns">
                <psc:MatchValue Name="urn:oid:1.2.752.29.4.13" />
                <psc:MatchValue Name="urn:oid:1.2.752.29.4.14" />
      </psc:RequestedPrincipalSelection>
    </Extensions>
    <SingleSignOnService Binding="http://ssobinding1.com" Location="http://ssolocation1.com"/>
  </IDPSSODescriptor>
</EntityDescriptor>""".getBytes("UTF-8")


    static def metaDataWithNoExtensions = """
<EntityDescriptor entityID="https://idp.switch.ch/idp/shibboleth" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <Extensions>
          <mdui:UIInfo>
            <mdui:DisplayName xml:lang="en">UIInfo EN</mdui:DisplayName>
            <mdui:DisplayName xml:lang="de">UIInfo DE</mdui:DisplayName>
          </mdui:UIInfo>
        </Extensions>
        <SingleSignOnService Binding="http://ssobinding1.com" Location="http://ssolocation1.com"/>
    </IDPSSODescriptor>
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <Extensions>
          <mdui:UIInfo>
            <mdui:DisplayName xml:lang="en">UIInfo in second roleDescriptor EN</mdui:DisplayName>
            <mdui:DisplayName xml:lang="de">UIInfo in second roleDescriptor DE</mdui:DisplayName>
          </mdui:UIInfo>
        </Extensions>
        <SingleSignOnService Binding="http://ssobinding1.com" Location="http://ssolocation1.com"/>
    </IDPSSODescriptor>
    <md:Organization xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
        <md:OrganizationName xml:lang="sv" xmlns:xml="http://www.w3.org/XML/1998/namespace">CGI Sverige AB
        </md:OrganizationName>
        <md:OrganizationName xml:lang="en" xmlns:xml="http://www.w3.org/XML/1998/namespace">CGI Sverige AB
        </md:OrganizationName>
        <md:OrganizationDisplayName xml:lang="sv" xmlns:xml="http://www.w3.org/XML/1998/namespace">Org SV
        </md:OrganizationDisplayName>
        <md:OrganizationDisplayName xml:lang="en" xmlns:xml="http://www.w3.org/XML/1998/namespace">Org EN
        </md:OrganizationDisplayName>
        <md:OrganizationURL xml:lang="en" xmlns:xml="http://www.w3.org/XML/1998/namespace">https://www.cgi.se
        </md:OrganizationURL>
    </md:Organization>
</EntityDescriptor>""".getBytes("UTF-8")

    static def metaDataNoUIInfo = """
<EntityDescriptor entityID="https://idp.switch.ch/idp/shibboleth" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <SingleSignOnService Binding="http://ssobinding1.com" Location="http://ssolocation1.com"/>
    </IDPSSODescriptor>
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <Extensions>
          <mdui:UIInfo>
            <mdui:DisplayName xml:lang="en">UIInfo in second roleDescriptor EN</mdui:DisplayName>
            <mdui:DisplayName xml:lang="de">UIInfo in second roleDescriptor DE</mdui:DisplayName>
          </mdui:UIInfo>
        </Extensions>
        <SingleSignOnService Binding="http://ssobinding1.com" Location="http://ssolocation1.com"/>
    </IDPSSODescriptor>
    <md:Organization xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
        <md:OrganizationName xml:lang="sv" xmlns:xml="http://www.w3.org/XML/1998/namespace">CGI Sverige AB
        </md:OrganizationName>
        <md:OrganizationName xml:lang="en" xmlns:xml="http://www.w3.org/XML/1998/namespace">CGI Sverige AB
        </md:OrganizationName>
        <md:OrganizationDisplayName xml:lang="sv" xmlns:xml="http://www.w3.org/XML/1998/namespace">Org SV
        </md:OrganizationDisplayName>
        <md:OrganizationDisplayName xml:lang="en" xmlns:xml="http://www.w3.org/XML/1998/namespace">Org EN
        </md:OrganizationDisplayName>
        <md:OrganizationURL xml:lang="en" xmlns:xml="http://www.w3.org/XML/1998/namespace">https://www.cgi.se
        </md:OrganizationURL>
    </md:Organization>
</EntityDescriptor>""".getBytes("UTF-8")

    static def metaDataWithKey = """
<EntityDescriptor entityID="https://idp.switch.ch/idp/shibboleth" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <KeyDescriptor use="signing">
                <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                    <X509Data>
                        <X509Certificate>
                            MIIEsTCCApmgAwIBAgIJAPCkIMwObBVaMA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNVBAYTAlNFMRowGAYDVQQKDBFDeWJlcmNvbSBHcm91cCBBQjExMC8GA1UEAwwoVW5kZXJza3JpZnRzdGrDpG5zdGVuIEludGVybiBQS0kgVEVTVCBDQTAeFw0xODAxMTkxMjIzNTVaFw0yODAxMTcxMjIzNTVaMFMxCzAJBgNVBAYTAlNFMRowGAYDVQQKDBFDeWJlcmNvbSBHcm91cCBBQjEoMCYGA1UEAwwfZWlkLnRlc3QubGVnaXRpbWVyaW5nc3RqYW5zdC5zZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOVRwFypvddyFOr5A9t83HH0/KusjXYO05gsvYlIIujrCQwtVMUVKnDtL72xk0ElwyF0OsXUzXYRjZ5ad0Nwd3XSoWGUpk+4Xil7kiNIYOwQPwlVk4BK5LjfuIH380TB/nolN7m/NQJ1r05D74NcxRkrt2bQG9uaKIE2HkIvgI0bqTghOLITSzBNm2Xo4XZbbVaIUvl0Jma5GWoIVRT0s6A/NHacLKr9HQSA6WPLhL1V1uFaO+CmlZY/nVhYlrWwTVCWPF+wq6CtXM/XO1AXg9qmUqdLw9KCAjbWMmON6u3DVSe4/Z8zq0iKnOSatoxZfzwBdBG0CXR1GMEykZ5OmY0CAwEAAaN/MH0wHwYDVR0jBBgwFoAUgshB9D2QLjWKDUrWLyHaW68QRqAwDAYDVR0TAQH/BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgWgMB0GA1UdDgQWBBSBs1+OyuOvdwVUy4aV4iaibfEbvTANBgkqhkiG9w0BAQsFAAOCAgEAKfm7FVG2gxSoFm2feQN/qGUInK7cz7yRyaqyumgZjZsb4MoH34iVUIqUjbIzAy21iy6AuE1tbGAH/mEkdj45CSMqFOwosYn+9Zwcy7BAvAdzawdcnp5S/dCp9esvLltMPkv/iOOjgPq72tivVOX5QYwUP42CJ9kPigsDwG4O8gHD9W7+XfHeWkvVscBScoxTMmv3KJRIs0u/2YNMpPBtoRDX0M1rlayGmzz7wOhviIHkXYCksMBuL8i0N9PE/B8YUOGwz6D3sBtbUmkZnAcWwKwx1ADAj1DRKT7R2zmnnMrvtr0/DoYHQQlDoNUPWgyoaozL9pXoSyP3fAhSuLKX53rq25W5Aq9GwqW5swouAgasPIIu6ehLqWcyaNkOxRUK4bGenOribTHkPrkIm3u3CkY15JWH/8R9FxljThJivmtNtxiAeERXb6ca2MQrLgRNKxZd3gD1OwTIBLsOSSuLvk03L36HrvBnwq6qQ0ofUEoC2iV3HWw3SDhG6IAdgbZ7bo9TPbixKhaUbhcBKaEJNmBbs/ivamFHCIk+XdZmLfcIQBNOwGIMXVB2e0Xc//ghgglrXFS+MJK1hQtdRcRbEEgXAXWUzy6mjV5Jk5wNVrZKThkVcGHFvcLGB144CRY/jzs22UEDq044d8DjlXQEkZK8YHiXMcAz3ui6JhlDD6k=
                        </X509Certificate>
                    </X509Data>
                </KeyInfo>
        </KeyDescriptor>
        <SingleSignOnService Binding="http://ssobinding1.com" Location="http://ssolocation1.com"/>
    </IDPSSODescriptor>
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <Extensions>
          <mdui:UIInfo>
            <mdui:DisplayName xml:lang="en">UIInfo in second roleDescriptor EN</mdui:DisplayName>
            <mdui:DisplayName xml:lang="de">UIInfo in second roleDescriptor DE</mdui:DisplayName>
          </mdui:UIInfo>
        </Extensions>
        <SingleSignOnService Binding="http://ssobinding1.com" Location="http://ssolocation1.com"/>
    </IDPSSODescriptor>
</EntityDescriptor>""".getBytes("UTF-8")


    static def metaDataNoDisplayNameSources = """
<EntityDescriptor entityID="https://idp.switch.ch/idp/shibboleth" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <SingleSignOnService Binding="http://ssobinding1.com" Location="http://ssolocation1.com"/>
    </IDPSSODescriptor>
</EntityDescriptor>""".getBytes("UTF-8")


    static def metaDataWithUIInfoInSecondRoleDescriptor = """
<EntityDescriptor entityID="https://idp.switch.ch/idp/shibboleth" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <SingleSignOnService Binding="http://ssobinding1.com" Location="http://ssolocation1.com"/>
    </IDPSSODescriptor>
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <Extensions>
          <mdui:UIInfo>
            <mdui:DisplayName xml:lang="en">UIInfo in second roleDescriptor EN</mdui:DisplayName>
            <mdui:DisplayName xml:lang="de">UIInfo in second roleDescriptor DE</mdui:DisplayName>
          </mdui:UIInfo>
        </Extensions>
        <SingleSignOnService Binding="http://ssobinding1.com" Location="http://ssolocation1.com"/>
    </IDPSSODescriptor>
</EntityDescriptor>""".getBytes("UTF-8")

    static def metaDataWithAttributeConsumingServices =  """<md:EntityDescriptor entityID="urn:visma:ticket-server:eidas-sp-pubtest"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
    xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <md:Extensions xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
    <mdattr:EntityAttributes xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute">
    <saml:Attribute Name="http://macedir.org/entity-category"
    NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">
    http://id.elegnamnden.se/st/1.0/public-sector-sp
    </saml:AttributeValue>
                    <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">
    http://id.elegnamnden.se/ec/1.0/eidas-naturalperson
    </saml:AttributeValue>
                </saml:Attribute>
    </mdattr:EntityAttributes>
        </md:Extensions>
    <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
    <md:Extensions>
    <mdui:UIInfo xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui">
    <mdui:DisplayName xml:lang="en" xmlns:xml="http://www.w3.org/XML/1998/namespace">Visma-test eIDAS
    SP
    </mdui:DisplayName>
                    <mdui:DisplayName xml:lang="sv" xmlns:xml="http://www.w3.org/XML/1998/namespace">Visma-test eIDAS
    SP
    </mdui:DisplayName>
                    <mdui:Description xml:lang="en" xmlns:xml="http://www.w3.org/XML/1998/namespace">eIDAS Foreign ID
    Service Provider
    </mdui:Description>
                    <mdui:Description xml:lang="sv" xmlns:xml="http://www.w3.org/XML/1998/namespace">eIDAS Foreign ID
    Service Provider
    </mdui:Description>
                    <mdui:InformationURL xml:lang="sv" xmlns:xml="http://www.w3.org/XML/1998/namespace">
    http://www.visma.com
    </mdui:InformationURL>
                    <mdui:PrivacyStatementURL xml:lang="sv" xmlns:xml="http://www.w3.org/XML/1998/namespace">
    http://www.visma.com
    </mdui:PrivacyStatementURL>
                    <mdui:Logo height="19" width="97">http://www.visma.com/style/images/logo.png</mdui:Logo>
                </mdui:UIInfo>
    </md:Extensions>
            <md:KeyDescriptor>
                <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:X509Data>
    <ds:X509Certificate>
    MIIDXjCCAkYCCQCHiKACz5NJPTANBgkqhkiG9w0BAQUFADBxMQswCQYDVQQGEwJTRTEOMAwGA1UECgwFVmlzbWExEzARBgNVBAsMCkNvbnN1bHRpbmcxGzAZBgNVBAMMEnRpY2tldC1zZXJ2ZXItdGVzdDEgMB4GCSqGSIb3DQEJARYRY2ljZXJvbkB2aXNtYS5jb20wHhcNMTUwMjA5MDkyNDMxWhcNMjUwMjA2MDkyNDMxWjBxMQswCQYDVQQGEwJTRTEOMAwGA1UECgwFVmlzbWExEzARBgNVBAsMCkNvbnN1bHRpbmcxGzAZBgNVBAMMEnRpY2tldC1zZXJ2ZXItdGVzdDEgMB4GCSqGSIb3DQEJARYRY2ljZXJvbkB2aXNtYS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCuWktafleN0P63DYefjInOGrzePfeSSFZfd17rPjdLsd63Cm3Sx6frZMNh0VL8684C2nBy9JK1uZbckUV7dWFFzcG7RobaGCdeS6DwIBHAm0Z4Kg3Eex18bk7VMIXl80BUlPvMS8lGC0z8V5wUxvR/o+mt8h2MP+SNVTvMwz/KFyo5HkpRyFH1M+PNJKWsS4Vk5pscPLXKzASirLQ1iWMXgbSu0iPeV8/Iz+KnGwv9VQk84mDQ1I7EuRUHTrZ3zcurZ+1DV2wxKh85J88ewMtcItL6jphjv9RgCPmAyqs05Ow0CVwrkXCkP8u7dqX1P3yMN8oWHWQP1kuCnLp5E9FFAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBADlINW5OcMpxhzrxFvOOlzTPPAfGUfihNlyvpg9Y9xrtMJylMtThL63tX/LoeUIWsy0wYlbsuL+x5mNa/N/M3bpsVYka3jRQamB3g2+etXP0fnvKIdn6ecAcSkmjzTCX9yhflwTmeryas4GO7NG66o42AVk34X85jmN9uLOYzI0pRwT3j5XEv7jP8ffCef2FrHvR0HHp1kCSNl/slVANlaLbAy3XzTZwz0FPKqMUBZgaKGSAHXA0blaX+zW3XcZ0Y6jH625dFWOWogaBEQWIujf1EZl2JDu7WPfPELgG2ixmitIGl0n/wbUZR2WwEhggLqsXWBRxADb5w/LKRI3xaQU=
    </ds:X509Certificate>
                    </ds:X509Data>
    </ds:KeyInfo>
            </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
            <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    Location="https://ticket-test1.siriusit.net/eidas.authenticate.response?system=eidas"
    index="0" isDefault="true"/>
    <md:AttributeConsumingService index="0" isDefault="true" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
            <md:ServiceName xml:lang="sv" xmlns:xml="http://www.w3.org/XML/1998/namespace">Sweden Connect Test-SP
            för eIDAS
    </md:ServiceName>
                <md:ServiceName xml:lang="en" xmlns:xml="http://www.w3.org/XML/1998/namespace">Sweden Connect Test SP
    for eIDAS
    </md:ServiceName>
                <md:RequestedAttribute Name="urn:oid:1.2.752.29.4.13" isRequired="false"/>
    <md:RequestedAttribute Name="urn:oid:1.2.752.201.3.7" isRequired="false"/>
            <md:RequestedAttribute Name="urn:oid:1.2.752.201.3.4" isRequired="true"/>
    </md:AttributeConsumingService>
        </md:SPSSODescriptor>
    <md:Organization xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
    <md:OrganizationName xml:lang="en" xmlns:xml="http://www.w3.org/XML/1998/namespace">Visma
    </md:OrganizationName>
            <md:OrganizationName xml:lang="sv" xmlns:xml="http://www.w3.org/XML/1998/namespace">Visma
    </md:OrganizationName>
            <md:OrganizationDisplayName xml:lang="en" xmlns:xml="http://www.w3.org/XML/1998/namespace">Visma eIDAS
    Test-SP
    </md:OrganizationDisplayName>
            <md:OrganizationDisplayName xml:lang="sv" xmlns:xml="http://www.w3.org/XML/1998/namespace">Visma eIDAS
    Test-SP
    </md:OrganizationDisplayName>
            <md:OrganizationURL xml:lang="en" xmlns:xml="http://www.w3.org/XML/1998/namespace">http://www.visma.com
    </md:OrganizationURL>
            <md:OrganizationURL xml:lang="sv" xmlns:xml="http://www.w3.org/XML/1998/namespace">http://www.visma.com
    </md:OrganizationURL>
        </md:Organization>
    <md:ContactPerson contactType="support" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
            <md:SurName>support</md:SurName>
            <md:EmailAddress>mailto:ciceron@visma.com</md:EmailAddress>
    </md:ContactPerson>
        <md:ContactPerson contactType="technical" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
            <md:SurName>technical</md:SurName>
    <md:EmailAddress>mailto:ciceron@visma.com</md:EmailAddress>
        </md:ContactPerson>
    </md:EntityDescriptor>""".getBytes("UTF-8")

    static def signed = """<?xml version="1.0" encoding="UTF-8"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" entityID="https://idp.switch.ch/idp/shibboleth"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<ds:Reference URI="">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<ds:DigestValue>yOQeMtK5oM5404cBY/sOnclyYp8M0bE9mW4yTjRErD4=</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue>
fepMS3HTW4YQ0ERS9XKCIUba1qY83LQCs2r1vJ8rjjyJzjXz0j16VqJvw/puaJwIyeb0vp6UsLKQ&#13;
UtAmUcRoJvCGgmVIS1eSUwfQLRasOsXeNQ5hDBlvoPLGJvKro/JGAnuZhszS7v7uxz9f5TW4RZHO&#13;
P/LYcaokXeEv6/M4AtN7jbYHgEFWLBceH4HX3Esi0r6c4o1YAXFDUzO8dQu9Ju1BgA7hHOBsQ6/E&#13;
QoyxGo2f8XTh9vZ5W69NvJI1EAtEEBWYV8MceQ/bp1DgM6bbaZk+1EwmbKdQ1xB5DgAijXg+jXHD&#13;
I6ibLfrgUiUGGDFyXDDKYPuvDNh6iAG6pzWfAg==
</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEtjCCAp6gAwIBAgIILMvMsnobWPkwDQYJKoZIhvcNAQELBQAwOzEdMBsGA1UEAwwUU2lnbiBT
ZXJ2aWNlIFRlc3QgQ0ExGjAYBgNVBAoMEVNpZ25hdHVyZSBTZXJ2aWNlMB4XDTE3MDYxNDA5MTg1
MloXDTQyMDYxNTA5MTU1NlowOzEdMBsGA1UEAwwUQmFja2VuZCBTZXJ2aWNlIFRlc3QxGjAYBgNV
BAoMEVNpZ25hdHVyZSBTZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmita
DRYToFkqpk5vaZWQIyWoxq9F22OA1Su/ugx5rxWHauNR+/KuiqNqri4cJrfLKPGDb0dUpzACM1B2
T1B4VwNvlSg2/WcbLNPreZT6wgL98Of0w77cpphN4y2NDeH/uR9czeRGadAhlbNSrGDZIGrmMH4l
gwiCtHo92XXKXseMajYbZN8DAj1hNePrF1v7GYpqAbMMEUzeeJjLLDBkcqx/Ic630AaoQlcSHHsA
7Fa7YwBrUsCCL2INc+l56YpsK+/s5XJTCrg6tQy+6EWsFgIS+X4jz1e9nZ+H6QynP5kvFx+Tsr9B
YeVQG2wyxzzW01013S/HY4laDZRerATkpQIDAQABo4G9MIG6MAwGA1UdEwEB/wQCMAAwHwYDVR0j
BBgwFoAUVl9ii9pud/WHDi57E8YjuuggmT8wEwYDVR0lBAwwCgYIKwYBBQUHAwIwRQYDVR0fBD4w
PDA6oDigNoY0aHR0cDovL2NybC5zaWduc2VydmljZXRlc3QuY29tL3NpZ25zZXJ2aWNldGVzdGNh
LmNybDAdBgNVHQ4EFgQU1RHGFVUXbbTaKRSV2u/icU9aYjkwDgYDVR0PAQH/BAQDAgSwMA0GCSqG
SIb3DQEBCwUAA4ICAQBTdNcxY6n66UKjwarJjxWuxj1IUBok50lU+WQ0cAFlwZt978apMycKjfiW
WzDJcVGbTniligO89ZaLSokTu2+jAx/wYy9OoEjVhz9Nder+RMPkDtl7sEWnNdvNN/ZnJL1la1wU
Bkve6w4Sz58VCCyYOEgj4J4XGzwUx0l77Z0ZBOo/h3v+8qe3rLR/vAS7KaFiRTETRTfaC8fhdzcP
gOklptKhG1iuKy+6fBzyrKcsqxkRm9L/znB/WYHDmkWJjr1fgpvkNO6+RLb9SMEIIZXNWVx9Pd+z
aP6kMiQ0hpxZZS8G7THcZCuGs7UysfQLez4/EOJ7Cg0Q1IKGEHpyBWXFkZw63dDKEeUOHGV/MAYO
r6iKvKRRAKL+GHLFchGLouPFYh3CjgOwRYTDLIJTWbaK+Dh1UUtuxdv3mS2LLeTwVN2u1cWROUHv
tHmLQH0JrZ8uboA6POI3zOCpzEWesP0ydDegsbot/F4RLRvCNcHXZGbUKsC/P03cspBiZtH/kxyZ
Y6Q2PQpOMHg9qvYql5sf9G5WxcBjaPVdl2zBdcmLFuD2eNthpyPwB+TMMmrRSQaP8i2W0kMdU0e+
Lt/T/qgBSULCH1r6/oucIZ4bCyhqKfwYqM6ZSojhsiAXMUtxiOca25I6psMhbMkJKNIX3kphBkyS
r09QdVXdwXLlK9l7IQ==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><Extensions/><SingleSignOnService Binding="http://ssobinding1.com" Location="http://ssolocation1.com"/></IDPSSODescriptor></EntityDescriptor>""".getBytes("UTF-8")
}
