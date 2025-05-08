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
package se.signatureservice.messages.csmessages

import org.bouncycastle.jce.provider.BouncyCastleProvider

import java.security.Security
import se.signatureservice.messages.csmessages.jaxb.CSResponse
import se.signatureservice.messages.sysconfig.jaxb.GetActiveConfigurationRequest
import se.signatureservice.messages.sysconfig.jaxb.GetActiveConfigurationResponse
import se.signatureservice.messages.sysconfig.jaxb.PublishConfigurationRequest
import spock.lang.Specification

class DefaultMessageNameCatalogueSpec extends Specification {

    static MessageNameCatalogue messageNameCatalogue;

    def setupSpec() {
        Security.addProvider(new BouncyCastleProvider())
        Properties config = new Properties();
        config.setProperty(DefaultMessageNameCatalogue.SETTING_MESSAGE_NAME_PREFIX + "getactiveconfigurationrequest", "SomeOtherName");
        config.setProperty(DefaultMessageNameCatalogue.OLD_SETTING_MESSAGE_NAME_PREFIX + "publishconfigurationrequest", "SomeAltOtherName");
        messageNameCatalogue = new DefaultMessageNameCatalogue();
        messageNameCatalogue.init(config);
    }


    def "Test default name is returned as the simple name of the payload element class."() {
        expect:
        messageNameCatalogue.lookupName(null, new GetActiveConfigurationResponse()) == "GetActiveConfigurationResponse"
    }

    def "Test that overriden name is returned when setting for payload element exists."() {
        expect:
        messageNameCatalogue.lookupName(null, new GetActiveConfigurationRequest()) == "SomeOtherName"
        messageNameCatalogue.lookupName(null, new PublishConfigurationRequest()) == "SomeAltOtherName"
    }

    def "Test that by default is 'FailureResponse' returned for a PKIResponse."() {
        expect:
        messageNameCatalogue.lookupName(null, new CSResponse()) == "FailureResponse"
    }


}
