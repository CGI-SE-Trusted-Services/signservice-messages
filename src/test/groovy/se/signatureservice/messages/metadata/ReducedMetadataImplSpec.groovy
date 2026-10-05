package se.signatureservice.messages.metadata

import groovy.json.JsonSlurper
import org.apache.xml.security.Init
import se.signatureservice.messages.ContextMessageSecurityProvider
import se.signatureservice.messages.DummyMessageSecurityProvider
import se.signatureservice.messages.MessageContentException
import se.signatureservice.messages.MessageProcessingException
import se.signatureservice.messages.csmessages.manager.MessageSecurityProviderManager
import se.signatureservice.messages.saml2.metadata.SAMLMetaDataMessageParser
import se.signatureservice.messages.saml2.metadata.jaxb.EntitiesDescriptorType
import se.signatureservice.messages.saml2.metadata.jaxb.EntityDescriptorType
import se.signatureservice.messages.saml2.metadata.jaxb.IDPSSODescriptorType
import se.signatureservice.messages.saml2.metadata.jaxb.SPSSODescriptorType
import se.signatureservice.messages.utils.CertUtils
import spock.lang.Specification

/**
 * Unit tests for ReducedMetadataImpl
 *
 * Created by fredrik 2025-08-28.
 */
class ReducedMetadataImplSpec extends Specification {
    ReducedMetadata withEntityAttributes
    ReducedMetadata withoutEntityAttributes
    ReducedMetadata withOrgAsDisplayNameSource
    ReducedMetadata withKeyAsDisplayNameSource
    ReducedMetadata withNoDisplayNameSources
    ReducedMetadata withDisplayNameSourceInSecondRoleDescriptor
    ReducedMetadata withAttributeConsumingServices
    static SAMLMetaDataMessageParser samlMetaDataMessageParser

    def setupSpec() {
        Init.init()
        CertUtils.installBCProvider()
        MessageSecurityProviderManager.initMessageSecurityProvider(new DummyMessageSecurityProvider())
        samlMetaDataMessageParser = new SAMLMetaDataMessageParser()
        samlMetaDataMessageParser.init(MessageSecurityProviderManager.getMessageSecurityProvider(), null)
    }

    def setup() {
        withEntityAttributes = fromBytes(metaDataWithExtensions, false).get(0)
        withoutEntityAttributes = fromBytes(metaDataWithNoExtensions, false).get(0)
        withOrgAsDisplayNameSource = fromBytes(metaDataNoUIInfo, false).get(0)
        withKeyAsDisplayNameSource = fromBytes(metaDataWithKey, false).get(0)
        withNoDisplayNameSources = fromBytes(metaDataNoDisplayNameSources, false).get(0)
        withDisplayNameSourceInSecondRoleDescriptor = fromBytes(metaDataWithUIInfoInSecondRoleDescriptor, false).get(0)
        withAttributeConsumingServices = fromBytes(metaDataWithAttributeConsumingServices, false).get(0)
    }

    def "Verify that hasEntityAttributeValue looks upp correct name"() {
        expect:
        withEntityAttributes.hasEntityAttributeValue("urn:oasis:names:tc:SAML:attribute:assurance-certification", "http://id.elegnamnden.se/loa/1.0/loa3-sigmessage")
        !withEntityAttributes.hasEntityAttributeValue("urn:oasis:names:tc:SAML:attribute:assurance-certification", "http://id.elegnamnden.se/loa/1.0/loa2-sigmessage")
        !withEntityAttributes.hasEntityAttributeValue("urn:oasis:names:tc:SAML:attribute:assurance-certification", "urn:oid:1.2.246.517.3002.110.3")
        withEntityAttributes.hasEntityAttributeValue("FinnishAuthMethod", "urn:oid:1.2.246.517.3002.110.3")
        !withoutEntityAttributes.hasEntityAttributeValue("urn:oasis:names:tc:SAML:attribute:assurance-certification", "http://id.elegnamnden.se/loa/1.0/loa2-sigmessage")
    }

    def "Test verify signature"() {
        setup:
        fromBytes(signed, true)
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

    def "test json ignored properties"() {
        given:
        def idpWithKey = withKeyAsDisplayNameSource
        def spWithKey = withAttributeConsumingServices
        def withAuthnCCRefs = withEntityAttributes

        def idps = [
                withEntityAttributes,
                withoutEntityAttributes,
                withOrgAsDisplayNameSource,
                withKeyAsDisplayNameSource,
                withNoDisplayNameSources,
                withDisplayNameSourceInSecondRoleDescriptor
        ]

        def sps = [
                withAttributeConsumingServices
        ]

        expect:
        idpWithKey.getSigningCertificateFingerprints(new ContextMessageSecurityProvider.Context(MetadataConstants.CONTEXT_USAGE_ASSERTIONCONSUME))
        idpWithKey.getAllSigningCertificateFingerprints()
        spWithKey.getSigningCertificateFingerprints(new ContextMessageSecurityProvider.Context(MetadataConstants.CONTEXT_USAGE_SIGNREQUEST))
        spWithKey.getAllSigningCertificateFingerprints()

        withAuthnCCRefs.getAuthnContextClassRefs()

        idps.every {
            it.firstRoleDescriptor(IDPSSODescriptorType.class.getSimpleName())
            it.getDestination("http://ssobinding1.com")

            try {
                it.getSigningCertificateFingerprints(new ContextMessageSecurityProvider.Context(MetadataConstants.CONTEXT_USAGE_SIGNREQUEST))
                return false
            } catch (MessageProcessingException e) {
                return true
            }
        }

        sps.every {
            it.firstRoleDescriptor(SPSSODescriptorType.class.getSimpleName())
            !it.getAuthnContextClassRefs()

            try {
                it.getDestination("http://ssobinding1.com")
                return false
            } catch (MessageContentException e) {
                try {
                    it.requestedPrincipalSelection()
                    return false
                } catch (MessageContentException f) {
                    try {
                        it.getSigningCertificateFingerprints(new ContextMessageSecurityProvider.Context(MetadataConstants.CONTEXT_USAGE_ASSERTIONCONSUME))
                        return false
                    } catch (MessageProcessingException g) {
                        return true
                    }
                }
            }
        }
    }

    def "Verify json serialisation 1"() {
        setup:
        def json = withEntityAttributes.asJson()
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
        def json = withAttributeConsumingServices.asJson()
        def slurper = new JsonSlurper()
        def tree = slurper.parseText(json)

        expect:
        tree.attributeConsumingServices == [ [
                                                 "names" : [ "Sweden Connect Test-SP för eIDAS", "Sweden Connect Test SP for eIDAS" ],
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
                                                                                                     "value": "Visma-test eIDAS SP"
                                                                                             ], [
                                                                                                     "lang" : "sv",
                                                                                                     "value": "Visma-test eIDAS SP"
                                                                                             ]]
                                                                    ]]
                                 ]]
        tree.singleSignOnServices == []
        tree.organisation == [
                "displayNames": [[
                                         "lang" : "en",
                                         "value": "Visma eIDAS Test-SP"
                                 ], [
                                         "lang" : "sv",
                                         "value": "Visma eIDAS Test-SP"
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

    static def signed = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="_084afe96f592198a3584819d7f1a5cd535" cacheDuration="P0Y0M0DT12H0M0.000S" entityID="https://m00-mg-local.idp.funktionstjanster.se/samlv2/idp/metadata/0/22"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#_084afe96f592198a3584819d7f1a5cd535"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>wylSg/lp1U9lz8aLwh37Qk9RFv6yY+Uej596MHXj8zU=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>V11R4PnCP3ThEpSMJU2MIyAYop3lWhKuHQ+AhA3rpO2m6nsw/fMjYHdZL7z8UnCs3hj5SDw7kNjZZELV+B4gZCjweCWWHeaykt7D/adf/vIhwAxa5KiVtP1ceE+VhtEIewL916LuqNnZoVCp4/ZmH0H6pQ76ATWVUrbAzsc/jwd2J3y0zKWPCDB8up6MshERp1+zSx/e82LGY8LX9S5ZSF4S5YAsE9HSKERnxIoeoB/e9R2Z17+dtu5IhGfMH+Q1us7rjJH5YOrDMJoYv+E78Iec5g95S+Zt5n3ntP1ITJj7fB0xxBd+5hNb9UqKvolHLSHB1it94crXojZna9xsng==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIG1jCCBb6gAwIBAgIQD+3JXT3m11m5QRMRq8GsKDANBgkqhkiG9w0BAQsFADBZMQswCQYDVQQG
EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMTMwMQYDVQQDEypEaWdpQ2VydCBHbG9iYWwgRzIg
VExTIFJTQSBTSEEyNTYgMjAyMCBDQTEwHhcNMjUwNDI4MDAwMDAwWhcNMjYwNDI3MjM1OTU5WjBd
MQswCQYDVQQGEwJTRTESMBAGA1UEBxMJU3RvY2tob2xtMRcwFQYDVQQKEw5DR0kgU3ZlcmlnZSBB
QjEhMB8GA1UEAxMYaWRwLmZ1bmt0aW9uc3RqYW5zdGVyLnNlMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEA4asnDxupa4zHopK+2DnrokKWCSh4TX3R1JlRJxiQQtCiOUoAsfuUgLrApGvp
H95QzVPQ+gMv65cqGoLi9guObEyRdikb07t+5uSglBemGVd0T/nyxrc61yPaTmlfKlJh/jshSMnU
Q39/h20Lkpvlu0dl0Yr924a1oHHHQ4qrrBYxtWZnK0NpgghQ2K26WOezzy+u5yXye6TBt5KKwy17
PpXN9Tq/ULMDenX4B6BDVcis4oMPBEaV073/XnU0xZxPLlugfJjDUiMIZph1efdzZ5PwALFZJhlj
G8OxuSTCe4M4jDg27DlPFQf/CuRAQrxp0kAoHxXtnlCHvhzvpWDJswIDAQABo4IDlDCCA5AwHwYD
VR0jBBgwFoAUdIWAwGbH3zfez70pN6oDHb7tzRcwHQYDVR0OBBYEFIoUd8pp6OOXN2psZrGKHcEh
mPOEMCMGA1UdEQQcMBqCGGlkcC5mdW5rdGlvbnN0amFuc3Rlci5zZTA+BgNVHSAENzA1MDMGBmeB
DAECAjApMCcGCCsGAQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDgYDVR0PAQH/
BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjCBnwYDVR0fBIGXMIGUMEigRqBE
hkJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRHbG9iYWxHMlRMU1JTQVNIQTI1NjIw
MjBDQTEtMS5jcmwwSKBGoESGQmh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2Jh
bEcyVExTUlNBU0hBMjU2MjAyMENBMS0xLmNybDCBhwYIKwYBBQUHAQEEezB5MCQGCCsGAQUFBzAB
hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wUQYIKwYBBQUHMAKGRWh0dHA6Ly9jYWNlcnRzLmRp
Z2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbEcyVExTUlNBU0hBMjU2MjAyMENBMS0xLmNydDAMBgNV
HRMBAf8EAjAAMIIBfgYKKwYBBAHWeQIEAgSCAW4EggFqAWgAdgAOV5S8866pPjMbLJkHs/eQ35vC
PXEyJd0hqSWsYcVOIQAAAZZ86V0uAAAEAwBHMEUCIQCcaX8yxk2siZZCewHTAVjM6Xf0gP1ioLKG
6JvM8AZzgAIgUp4Wy4iNoC1Nv+W2H5kb6OhEGDOJnjzzjA3f/9oByC8AdgBJnJtp3h187Pw23s2H
ZKa4W68Kh4AZ0VVS++nrKd34wwAAAZZ86V12AAAEAwBHMEUCIQDf5wTmWkkZG/6SfiIWSRn9EbNS
sc8EMTKsCgVY53wUvgIgFYxTGMOZFGvKqJioqZcpshg11SiOqCWSQoxifrRUagIAdgDLOPcViXyE
oURfW8Hd+8lu8ppZzUcKaQWFsMsUwxRY5wAAAZZ86V1bAAAEAwBHMEUCIQD29ao7HhnhA7IJ7pvS
8QJD8o8Dj4uOHM3RSuug2mYl6gIgfYTJ6f6bGxsJdFbbfIPk1vkNHEZcfjcZsPFi9dfRqqQwDQYJ
KoZIhvcNAQELBQADggEBABWg4qfMkzFbF4iRWZqJGKur/uR6ag028kt3nXXZBTDEawmWKLMCYG/S
2dLr75XmC8K/MzK/mcvlKImuBZULIOCNmuMawrQne+kgo807QvZIB1QX9whDLImGoFDRQU3Yr3vA
hV9dVwRBKPoGO03S5WlhfT+MeTx/MEV3EhUNdmXMS4ED6A3QlGD/abAzMJGdzaCqZ5bL9BC8P/zE
ih/CVDrOFULzP/iWHbhdkAN+1X5I5j39dsQqDY3aVeWaIUmGUEiHT9UMhjFTQxiJhkcaQtWY5Hal
dR1n2pp6YjXvWqgtwRu730rFsojk42EP2fubJMO4AdTIKlL+gZk0L/WEdjc=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><md:IDPSSODescriptor WantAuthnRequestsSigned="false" errorURL="https://m00-mg-local.idp.funktionstjanster.se/samlv2/idp/error/0/22?mgvhostparam=0&amp;error=ERRORURL_CODE" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MIIG1jCCBb6gAwIBAgIQD+3JXT3m11m5QRMRq8GsKDANBgkqhkiG9w0BAQsFADBZMQswCQYDVQQG
EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMTMwMQYDVQQDEypEaWdpQ2VydCBHbG9iYWwgRzIg
VExTIFJTQSBTSEEyNTYgMjAyMCBDQTEwHhcNMjUwNDI4MDAwMDAwWhcNMjYwNDI3MjM1OTU5WjBd
MQswCQYDVQQGEwJTRTESMBAGA1UEBxMJU3RvY2tob2xtMRcwFQYDVQQKEw5DR0kgU3ZlcmlnZSBB
QjEhMB8GA1UEAxMYaWRwLmZ1bmt0aW9uc3RqYW5zdGVyLnNlMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEA4asnDxupa4zHopK+2DnrokKWCSh4TX3R1JlRJxiQQtCiOUoAsfuUgLrApGvp
H95QzVPQ+gMv65cqGoLi9guObEyRdikb07t+5uSglBemGVd0T/nyxrc61yPaTmlfKlJh/jshSMnU
Q39/h20Lkpvlu0dl0Yr924a1oHHHQ4qrrBYxtWZnK0NpgghQ2K26WOezzy+u5yXye6TBt5KKwy17
PpXN9Tq/ULMDenX4B6BDVcis4oMPBEaV073/XnU0xZxPLlugfJjDUiMIZph1efdzZ5PwALFZJhlj
G8OxuSTCe4M4jDg27DlPFQf/CuRAQrxp0kAoHxXtnlCHvhzvpWDJswIDAQABo4IDlDCCA5AwHwYD
VR0jBBgwFoAUdIWAwGbH3zfez70pN6oDHb7tzRcwHQYDVR0OBBYEFIoUd8pp6OOXN2psZrGKHcEh
mPOEMCMGA1UdEQQcMBqCGGlkcC5mdW5rdGlvbnN0amFuc3Rlci5zZTA+BgNVHSAENzA1MDMGBmeB
DAECAjApMCcGCCsGAQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDgYDVR0PAQH/
BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjCBnwYDVR0fBIGXMIGUMEigRqBE
hkJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRHbG9iYWxHMlRMU1JTQVNIQTI1NjIw
MjBDQTEtMS5jcmwwSKBGoESGQmh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2Jh
bEcyVExTUlNBU0hBMjU2MjAyMENBMS0xLmNybDCBhwYIKwYBBQUHAQEEezB5MCQGCCsGAQUFBzAB
hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wUQYIKwYBBQUHMAKGRWh0dHA6Ly9jYWNlcnRzLmRp
Z2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbEcyVExTUlNBU0hBMjU2MjAyMENBMS0xLmNydDAMBgNV
HRMBAf8EAjAAMIIBfgYKKwYBBAHWeQIEAgSCAW4EggFqAWgAdgAOV5S8866pPjMbLJkHs/eQ35vC
PXEyJd0hqSWsYcVOIQAAAZZ86V0uAAAEAwBHMEUCIQCcaX8yxk2siZZCewHTAVjM6Xf0gP1ioLKG
6JvM8AZzgAIgUp4Wy4iNoC1Nv+W2H5kb6OhEGDOJnjzzjA3f/9oByC8AdgBJnJtp3h187Pw23s2H
ZKa4W68Kh4AZ0VVS++nrKd34wwAAAZZ86V12AAAEAwBHMEUCIQDf5wTmWkkZG/6SfiIWSRn9EbNS
sc8EMTKsCgVY53wUvgIgFYxTGMOZFGvKqJioqZcpshg11SiOqCWSQoxifrRUagIAdgDLOPcViXyE
oURfW8Hd+8lu8ppZzUcKaQWFsMsUwxRY5wAAAZZ86V1bAAAEAwBHMEUCIQD29ao7HhnhA7IJ7pvS
8QJD8o8Dj4uOHM3RSuug2mYl6gIgfYTJ6f6bGxsJdFbbfIPk1vkNHEZcfjcZsPFi9dfRqqQwDQYJ
KoZIhvcNAQELBQADggEBABWg4qfMkzFbF4iRWZqJGKur/uR6ag028kt3nXXZBTDEawmWKLMCYG/S
2dLr75XmC8K/MzK/mcvlKImuBZULIOCNmuMawrQne+kgo807QvZIB1QX9whDLImGoFDRQU3Yr3vA
hV9dVwRBKPoGO03S5WlhfT+MeTx/MEV3EhUNdmXMS4ED6A3QlGD/abAzMJGdzaCqZ5bL9BC8P/zE
ih/CVDrOFULzP/iWHbhdkAN+1X5I5j39dsQqDY3aVeWaIUmGUEiHT9UMhjFTQxiJhkcaQtWY5Hal
dR1n2pp6YjXvWqgtwRu730rFsojk42EP2fubJMO4AdTIKlL+gZk0L/WEdjc=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://m00-mg-local.idp.funktionstjanster.se/samlv2/idp/sloreq/0/22?mgvhostparam=0" ResponseLocation="https://m00-mg-local.idp.funktionstjanster.se/samlv2/idp/sloresp/0/22?mgvhostparam=0"/><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://m00-mg-local.idp.funktionstjanster.se/samlv2/idp/sloreq/0/22?mgvhostparam=0" ResponseLocation="https://m00-mg-local.idp.funktionstjanster.se/samlv2/idp/sloresp/0/22?mgvhostparam=0"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://m00-mg-local.idp.funktionstjanster.se/samlv2/idp/req/0/22?mgvhostparam=0"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://m00-mg-local.idp.funktionstjanster.se/samlv2/idp/req/0/22?mgvhostparam=0"/></md:IDPSSODescriptor></md:EntityDescriptor>
""".getBytes("UTF-8")

    private static List<ReducedMetadata> fromBytes(byte[] bytes, boolean verifySignature) throws MessageProcessingException, MessageContentException {
        Object o = samlMetaDataMessageParser.parseMessage(
                new ContextMessageSecurityProvider.Context(MetadataConstants.CONTEXT_USAGE_METADATA_SIGN),
                bytes, verifySignature
        );
        var list = new LinkedList<ReducedMetadata>();
        collectMetadata(o, list);
        return list;
    }

    private static void collectMetadata(Object metaData, List<ReducedMetadata> list) {
        if (metaData instanceof EntityDescriptorType) {
            list.add(new ReducedMetadataImpl(((EntityDescriptorType) metaData), null));
        } else {
            if (metaData instanceof EntitiesDescriptorType) {
                for (Object edt : ((EntitiesDescriptorType) metaData).getEntityDescriptorOrEntitiesDescriptor()) {
                    collectMetadata(edt, list);
                }
            }
        }
    }
}
