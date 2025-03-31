/************************************************************************
 *                                                                       *
 *  Certificate Service - Messages                                       *
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


import spock.lang.Specification
import spock.lang.Unroll

import static EncryptionAlgorithmScheme.*

class EncryptionAlgorithmSchemeSpec extends Specification{
	
	@Unroll
	def "Verify that encryption algorithm #algorithm has data encryption URI #dataalgvalue and a key encryption algorithm URI: #keyalgvalue"(){
		expect:
		algorithm.getDataEncryptionAlgorithmURI() == dataalgvalue
		algorithm.getKeyEncryptionAlgorithmURI() == keyalgvalue
		where:
		algorithm                   | dataalgvalue                                           | keyalgvalue
		RSA_PKCS1_5_WITH_AES128     | "http://www.w3.org/2001/04/xmlenc#aes128-cbc"          | "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
		RSA_OAEP_WITH_AES128        | "http://www.w3.org/2001/04/xmlenc#aes128-cbc"          | "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
		RSA_PKCS1_5_WITH_AES192     | "http://www.w3.org/2001/04/xmlenc#aes192-cbc"          | "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
		RSA_OAEP_WITH_AES192        | "http://www.w3.org/2001/04/xmlenc#aes192-cbc"          | "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
		RSA_PKCS1_5_WITH_AES256     | "http://www.w3.org/2001/04/xmlenc#aes256-cbc"          | "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
		RSA_OAEP_WITH_AES256        | "http://www.w3.org/2001/04/xmlenc#aes256-cbc"          | "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
		RSA_PKCS1_5_WITH_AES128_GCM | "http://www.w3.org/2009/xmlenc11#aes128-gcm"           | "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
		RSA_OAEP_WITH_AES128_GCM    | "http://www.w3.org/2009/xmlenc11#aes128-gcm"           | "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
		RSA_PKCS1_5_WITH_AES192_GCM | "http://www.w3.org/2009/xmlenc11#aes192-gcm"           | "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
		RSA_OAEP_WITH_AES192_GCM    | "http://www.w3.org/2009/xmlenc11#aes192-gcm"           | "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
		RSA_PKCS1_5_WITH_AES256_GCM | "http://www.w3.org/2009/xmlenc11#aes256-gcm"           | "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
		RSA_OAEP_WITH_AES256_GCM    | "http://www.w3.org/2009/xmlenc11#aes256-gcm"           | "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"

	}

	@Unroll
	def "Verify getByName #name"() {
		expect:
		EncryptionAlgorithmScheme.getByName(name) == expectedScheme

		where:
		name							| expectedScheme
		"RSA_PKCS1_5_WITH_AES128"		| EncryptionAlgorithmScheme.RSA_PKCS1_5_WITH_AES128
		"RSA_OAEP_WITH_AES128"			| EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES128
		"RSA_PKCS1_5_WITH_AES192"		| EncryptionAlgorithmScheme.RSA_PKCS1_5_WITH_AES192
		"RSA_OAEP_WITH_AES192"			| EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES192
		"RSA_PKCS1_5_WITH_AES256"		| EncryptionAlgorithmScheme.RSA_PKCS1_5_WITH_AES256
		"RSA_OAEP_WITH_AES256"			| EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256
		"RSA_PKCS1_5_WITH_AES128_GCM"	| EncryptionAlgorithmScheme.RSA_PKCS1_5_WITH_AES128_GCM
		"RSA_OAEP_WITH_AES128_GCM"		| EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES128_GCM
		"RSA_PKCS1_5_WITH_AES192_GCM"	| EncryptionAlgorithmScheme.RSA_PKCS1_5_WITH_AES192_GCM
		"RSA_OAEP_WITH_AES192_GCM"		| EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES192_GCM
		"RSA_PKCS1_5_WITH_AES256_GCM"	| EncryptionAlgorithmScheme.RSA_PKCS1_5_WITH_AES256_GCM
		"RSA_OAEP_WITH_AES256_GCM"		| EncryptionAlgorithmScheme.RSA_OAEP_WITH_AES256_GCM
		"RSA_Unknown_WITH_ABC256"	| null
		null						| null
	}
}
