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
package org.certificateservices.messages;

import spock.lang.Specification;
import spock.lang.Unroll;

import static org.certificateservices.messages.SigningAlgorithmScheme.*

class SigningAlgorithmSchemeSpec extends Specification{
	
	@Unroll
	def "Verify that signature algorithm #algorithm has hash URI #hashurivalue and a signature algorithm URI: #urivalue"(){
		expect:
		algorithm.getHashAlgorithmURI() == hashurivalue
		algorithm.getSignatureAlgorithmURI() == signurivalue
		where:
		algorithm                   | hashurivalue                                            | signurivalue
		RSAWithSHA256               | "http://www.w3.org/2001/04/xmlenc#sha256"               | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
		RSAWithSHA512               | "http://www.w3.org/2001/04/xmlenc#sha512"               | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
		ECDSAWithSHA256             | "http://www.w3.org/2001/04/xmlenc#sha256"               | "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
		ECDSAWithSHA512             | "http://www.w3.org/2001/04/xmlenc#sha512"               | "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
	}

	@Unroll
	def "Verify getByName #name"() {
		expect:
		SigningAlgorithmScheme.getByName(name) == expectedScheme

		where:
		name				| expectedScheme
		"RSAWithSHA256"		| SigningAlgorithmScheme.RSAWithSHA256
		"RSAWithSHA512"		| SigningAlgorithmScheme.RSAWithSHA512
		"ECDSAWithSHA256"	| SigningAlgorithmScheme.ECDSAWithSHA256
		"ECDSAWithSHA512"	| SigningAlgorithmScheme.ECDSAWithSHA512
		"UnknownWithABC256"	| null
		null				| null
	}

}
