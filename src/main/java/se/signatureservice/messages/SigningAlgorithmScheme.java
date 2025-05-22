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
package se.signatureservice.messages;

/**
 * Definition of all supported Signature Algorithm by Message Security Providers.
 * 
 * @author Philip Vendil
 *
 */
public enum SigningAlgorithmScheme {
	
	RSAWithSHA256("http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
	RSAWithSHA512("http://www.w3.org/2001/04/xmlenc#sha512", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"),

	ECDSAWithSHA256("http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"),
	ECDSAWithSHA512("http://www.w3.org/2001/04/xmlenc#sha512", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512");
	
	String hashAlgorithmURI;
	String signatureAlgorithmURI;
	
	SigningAlgorithmScheme(String hashAlgorithmURI, String signatureAlgorithmURI){
		this.hashAlgorithmURI = hashAlgorithmURI;
		this.signatureAlgorithmURI = signatureAlgorithmURI;
	}
	
	public String getHashAlgorithmURI(){
		return hashAlgorithmURI;
	}
	
	public String getSignatureAlgorithmURI(){
		return signatureAlgorithmURI;
	}

	public static SigningAlgorithmScheme getByName(String name){
		if(name != null) {
			for (SigningAlgorithmScheme s : values()) {
				if (s.name().equalsIgnoreCase(name.trim())) {
					return s;
				}
			}
		}
		return null;
	}
}
