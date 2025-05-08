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
package se.signatureservice.messages

import org.bouncycastle.asn1.x500.style.BCStyle
import spock.lang.Specification
import spock.lang.Unroll

import java.security.KeyStore

import static SimpleMessageSecurityProvider.SETTING_PREFIX
import static TruststoreHelper.*

/**
 * Unit test for TruststoreHelper
 *
 * @author Philip Vendil 2021-06-01
 */
class TruststoreHelperSpec extends Specification {

    TruststoreHelper helper

    def setup(){
        Properties config = new Properties()
        helper = new TruststoreHelper(config, KeyStore.getInstance("JKS") , SimpleMessageSecurityProvider.SETTING_PREFIX)
    }

    def "Verify that if truststore type is CA the provider is initialized properly, and subject match settings is not necessary if useSubjectMatch is false"(){
        setup:
        helper = new TruststoreHelper(newConfig([(SETTING_TRUSTKEYSTORE_TYPE): TRUSTKEYSTORE_TYPE_CA, (SETTING_TRUSTKEYSTORE_MATCHSUBJECT): "false"]),
        KeyStore.getInstance("JKS") , SimpleMessageSecurityProvider.SETTING_PREFIX)
        expect:
        helper.trustStoreType == TRUSTKEYSTORE_TYPE_CA
        helper.trustStoreMatchSubject == false
        helper.trustStoreMatchField == null
        helper.trustStoreMatchValue == null
    }

    def "Verify that if truststore type is CA the provider is initialized properly with subject match settings if useSubjectMatch is true"(){
        setup:
        helper = new TruststoreHelper(newConfig([(SETTING_TRUSTKEYSTORE_TYPE): TRUSTKEYSTORE_TYPE_CA,
                                                 (SETTING_TRUSTKEYSTORE_MATCHDNFIELD): "CN",
                                                 (SETTING_TRUSTKEYSTORE_MATCHDNVALUE): "Tommy"]),
                KeyStore.getInstance("JKS") , SimpleMessageSecurityProvider.SETTING_PREFIX)
        expect:
        helper.trustStoreType == TRUSTKEYSTORE_TYPE_CA
        helper.trustStoreMatchSubject == true
        helper.trustStoreMatchField == BCStyle.CN
        helper.trustStoreMatchValue == "Tommy"
    }

    @Unroll
    def "Verify that getTrustStoreType() with valid truststore type configuration is returned in trimmed uppercase"(){
        setup:
        Properties config = new Properties()
        config.setProperty(SimpleMessageSecurityProvider.SETTING_PREFIX + SETTING_TRUSTKEYSTORE_TYPE, value)
        expect:
        helper.getTrustStoreType(config, SimpleMessageSecurityProvider.SETTING_PREFIX) == expected
        where:
        value           | expected
        "  cA   "       | TRUSTKEYSTORE_TYPE_CA
        "  endentity "  | TRUSTKEYSTORE_TYPE_ENDENTITY
    }

    def "Verify that getTrustStoreType() with unset truststore type returns default value"(){
        expect:
        helper.getTrustStoreType(new Properties(), SimpleMessageSecurityProvider.SETTING_PREFIX) == TRUSTKEYSTORE_TYPE_ENDENTITY
    }

    def "Verify that invalid configuration to getTrustStoreType throws MessageProcessingException"(){
        setup:
        Properties config = new Properties()
        config.setProperty(SimpleMessageSecurityProvider.SETTING_PREFIX + SETTING_TRUSTKEYSTORE_TYPE, " invalid")
        when:
        helper.getTrustStoreType(config, SimpleMessageSecurityProvider.SETTING_PREFIX)
        then:
        def e = thrown MessageProcessingException
        e.message == "Invalid setting for simple message security provider, setting simplesecurityprovider.trustkeystore.type should have a value of either CA or ENDENTITY not: INVALID"
    }

    @Unroll
    def "Verify that useSubjectMatch() with valid configuration returns boolean"(){
        setup:
        Properties config = new Properties()
        config.setProperty(SimpleMessageSecurityProvider.SETTING_PREFIX + SETTING_TRUSTKEYSTORE_MATCHSUBJECT, value)
        expect:
        helper.useSubjectMatch(config, SimpleMessageSecurityProvider.SETTING_PREFIX) == expected
        where:
        value           | expected
        "  TrUe   "     | true
        "  fAlse "      | false
    }

    def "Verify that useSubjectMatch() with unset use subject match returns default value"(){
        expect:
        helper.useSubjectMatch(new Properties(), SimpleMessageSecurityProvider.SETTING_PREFIX) == DEFAULT_TRUSTKEYSTORE_MATCHSUBJECT as Boolean
    }

    def "Verify that useSubjectMatch() with invalid configuration throws MessageProcessingException"(){
        setup:
        Properties config = new Properties()
        config.setProperty(SimpleMessageSecurityProvider.SETTING_PREFIX + SETTING_TRUSTKEYSTORE_MATCHSUBJECT, " invalid")
        when:
        helper.useSubjectMatch(config, SimpleMessageSecurityProvider.SETTING_PREFIX)
        then:
        def e = thrown MessageProcessingException
        e.message == "Invalid setting for simple message security provider, setting simplesecurityprovider.trustkeystore.matchsubject should have a value of either true or false not: invalid"
    }

    @Unroll
    def "Verify that getMatchSubjectField() with valid value returns expected DN field"(){
        expect:
        helper.getMatchSubjectField(value, SimpleMessageSecurityProvider.SETTING_PREFIX) == expected
        where:
        value           | expected
        "CN"            | BCStyle.CN
        "OU"            | BCStyle.OU
        "UID"           | BCStyle.UID
    }

    def "Verify that getMatchSubjectField() with invalid configuration throws MessageProcessingException"(){
        when:
        helper.getMatchSubjectField("invalid", SimpleMessageSecurityProvider.SETTING_PREFIX)
        then:
        def e = thrown MessageProcessingException
        e.message == "Invalid DN field invalid configured in setting simplesecurityprovider.trustkeystore.matchdnfield."
    }

    def "Verify that getMatchSubjectValue() with valid value returns expected DN field"(){
        setup:
        Properties config = new Properties()
        config.setProperty(SimpleMessageSecurityProvider.SETTING_PREFIX+ SETTING_TRUSTKEYSTORE_MATCHDNVALUE, " someValue ")
        expect:
        helper.getMatchSubjectValue(config, SimpleMessageSecurityProvider.SETTING_PREFIX) == "someValue"
    }

    def "Verify that getMatchSubjectValue() without setting throws MessageProcessingException"(){
        when:
        helper.getMatchSubjectValue(new Properties(), SimpleMessageSecurityProvider.SETTING_PREFIX)
        then:
        def e = thrown MessageProcessingException
        e.message == "Error required configuration property simplesecurityprovider.trustkeystore.matchdnvalue not set."
    }

    def newConfig(Map m) {
        def config = new Properties()
        if(m[SETTING_TRUSTKEYSTORE_TYPE]){
            config.setProperty(SETTING_PREFIX + SETTING_TRUSTKEYSTORE_TYPE, m[SETTING_TRUSTKEYSTORE_TYPE])
        }
        if(m[SETTING_TRUSTKEYSTORE_MATCHSUBJECT]){
            config.setProperty(SETTING_PREFIX + SETTING_TRUSTKEYSTORE_MATCHSUBJECT, m[SETTING_TRUSTKEYSTORE_MATCHSUBJECT])
        }
        if(m[SETTING_TRUSTKEYSTORE_MATCHDNFIELD]){
            config.setProperty(SETTING_PREFIX + SETTING_TRUSTKEYSTORE_MATCHDNFIELD, m[SETTING_TRUSTKEYSTORE_MATCHDNFIELD])
        }
        if(m[SETTING_TRUSTKEYSTORE_MATCHDNVALUE]){
            config.setProperty(SETTING_PREFIX + SETTING_TRUSTKEYSTORE_MATCHDNVALUE, m[SETTING_TRUSTKEYSTORE_MATCHDNVALUE])
        }

        return  config
    }

}
