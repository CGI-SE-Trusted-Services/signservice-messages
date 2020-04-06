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
package org.certificateservices.messages

import java.security.PrivateKey
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import org.certificateservices.messages.DummyMessageSecurityProvider;
import org.junit.Test;

import spock.lang.Specification


import static org.certificateservices.messages.MessageSecurityProvider.*
class DummyPKIMessageSecurityProviderSpec extends Specification {
	
	@Test
	def "Test that getSigningKey() returns a valid signing key"(){
		when:
		  DummyMessageSecurityProvider prov = new DummyMessageSecurityProvider();
		  PrivateKey key = prov.getSigningKey();
		then:
		 assert key != null
		 assert key instanceof RSAPrivateKey
	}
	
	@Test
	def "Test that getSigningCertificate() returns a valid signing certificate"(){
		when:
		  DummyMessageSecurityProvider prov = new DummyMessageSecurityProvider();
		  X509Certificate cert = prov.getSigningCertificate();
		then:
		 assert cert != null
		 assert cert instanceof X509Certificate
	}
	
	@Test
	def "Test that getDecryptionKey() and getDecryptionCertificate() getDecryptionCertificateChain() returns default key and certificate for DEFAULT_DECRYPTIONKEY"(){
		when:
		  DummyMessageSecurityProvider prov = new DummyMessageSecurityProvider();
		  X509Certificate cert = prov.getDecryptionCertificate(DEFAULT_DECRYPTIONKEY)
		  X509Certificate[] certChain = prov.getDecryptionCertificateChain(DEFAULT_DECRYPTIONKEY)
		  PrivateKey key = prov.getDecryptionKey(DEFAULT_DECRYPTIONKEY);
		then:
		 assert cert != null
		 assert cert instanceof X509Certificate	
		 assert key != null
		 assert key instanceof PrivateKey
		 assert certChain.length == 1
		 assert certChain instanceof X509Certificate[]
		 	 
	}

	@Test
	def "Verify that getDecryptionKeyIds() returns a valid signing key id and that getDecryptionKey() and getDecryptionCertificate() getDecryptionCertificateChain() returns related key and certificate."(){
		when:
		  DummyMessageSecurityProvider prov = new DummyMessageSecurityProvider();
		  Set<String> keyIds = prov.getDecryptionKeyIds();
		  String keyId = keyIds.iterator().next();
		then:
		   keyIds.size() == 3
		   keyId == "A2a5JrfZL6oHCSexVqT9GyeV66QaYYY1YbqU+/eDkyc="
		when:
		  X509Certificate cert = prov.getDecryptionCertificate(keyId)
		  X509Certificate[] certChain = prov.getDecryptionCertificateChain(keyId)
		  PrivateKey key = prov.getDecryptionKey(keyId);
		then:
		 assert cert != null
		 assert cert instanceof X509Certificate
		 assert key != null
		 assert key instanceof PrivateKey
		 assert certChain.length == 1 
		 assert certChain instanceof X509Certificate[]
			  
	}
	
	@Test
	def "Verify that getDecryptionKey() and getDecryptionCertificate() throws MessageProcessingException on invalid key id."(){
		when:
		  DummyMessageSecurityProvider prov = new DummyMessageSecurityProvider();
		  prov.getDecryptionKey("INVALID")
		then:
		   thrown MessageProcessingException
		when:
		  prov.getDecryptionCertificate("INVALID")
		then:
		   thrown MessageProcessingException
		when:
		   prov.getDecryptionCertificateChain("INVALID")
		 then:
			thrown MessageProcessingException
			  
	}
	
}
