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

import org.apache.xml.security.encryption.XMLCipher;

/**
 * Definition of all supported Encryption Algorithms by Message Security Providers.
 * 
 * @author Philip Vendil
 *
 */
public enum EncryptionAlgorithmScheme {

	RSA_PKCS1_5_WITH_AES128(XMLCipher.AES_128, XMLCipher.RSA_v1dot5),
	RSA_OAEP_WITH_AES128(XMLCipher.AES_128, XMLCipher.RSA_OAEP),
	RSA_PKCS1_5_WITH_AES192(XMLCipher.AES_192, XMLCipher.RSA_v1dot5),
	RSA_OAEP_WITH_AES192(XMLCipher.AES_192, XMLCipher.RSA_OAEP),
	RSA_PKCS1_5_WITH_AES256(XMLCipher.AES_256, XMLCipher.RSA_v1dot5),
	RSA_OAEP_WITH_AES256(XMLCipher.AES_256, XMLCipher.RSA_OAEP);
	
	String dataEncryptionAlgorithmURI;
	String keyEncryptionAlgorithmURI;
	
	EncryptionAlgorithmScheme(String dataEncryptionAlgorithmURI,
	                             String keyEncryptionAlgorithmURI){
		this.dataEncryptionAlgorithmURI = dataEncryptionAlgorithmURI;
		this.keyEncryptionAlgorithmURI = keyEncryptionAlgorithmURI;
	}
	
	public String getDataEncryptionAlgorithmURI(){
		return dataEncryptionAlgorithmURI;
	}

	public String getKeyEncryptionAlgorithmURI(){
		return keyEncryptionAlgorithmURI;
	}

	public static EncryptionAlgorithmScheme getByName(String name){
		if(name != null) {
			for (EncryptionAlgorithmScheme e : values()) {
				if (e.name().equalsIgnoreCase(name.trim())) {
					return e;
				}
			}
		}
		return null;
	}
}
