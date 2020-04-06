/************************************************************************
 *                                                                       *
 *  Certificate Service - Messages                                       *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.certificateservices.messages.csmessages

import org.bouncycastle.jce.provider.BouncyCastleProvider

import java.security.PrivateKey
import java.security.Security
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;


import org.certificateservices.messages.DummyMessageSecurityProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import org.certificateservices.messages.csmessages.jaxb.CSResponse
import org.certificateservices.messages.sysconfig.jaxb.GetActiveConfigurationRequest
import org.certificateservices.messages.sysconfig.jaxb.GetActiveConfigurationResponse
import org.certificateservices.messages.sysconfig.jaxb.PublishConfigurationRequest

import spock.lang.Specification


public class DefaultMessageNameCatalogueSpec extends Specification {
	

	static MessageNameCatalogue messageNameCatalogue;
	

	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Properties config = new Properties();
		config.setProperty(DefaultMessageNameCatalogue.SETTING_MESSAGE_NAME_PREFIX + "getactiveconfigurationrequest", "SomeOtherName");
		config.setProperty(DefaultMessageNameCatalogue.OLD_SETTING_MESSAGE_NAME_PREFIX + "publishconfigurationrequest", "SomeAltOtherName");
		messageNameCatalogue = new DefaultMessageNameCatalogue();
		messageNameCatalogue.init(config);
	}

	
	@Test
	def "Test default name is returned as the simple name of the payload element class."(){
		expect:
		messageNameCatalogue.lookupName(null, new GetActiveConfigurationResponse()) == "GetActiveConfigurationResponse"
	}
	
	@Test
	def "Test that overriden name is returned when setting for payload element exists."(){
		expect:
		messageNameCatalogue.lookupName(null,new GetActiveConfigurationRequest()) == "SomeOtherName"
		messageNameCatalogue.lookupName(null,new PublishConfigurationRequest()) == "SomeAltOtherName"
	}
	
	@Test
	def "Test that by default is 'FailureResponse' returned for a PKIResponse."(){
		expect:
		messageNameCatalogue.lookupName(null,new CSResponse()) == "FailureResponse"
	}


}
