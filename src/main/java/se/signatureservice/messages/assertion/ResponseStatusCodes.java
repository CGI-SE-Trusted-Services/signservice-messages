/************************************************************************
 *                                                                       *
 *  Signature Service - Messages                                         *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3 of the License, or any later version.                      *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.messages.assertion;

/**
 * Enumeration describing available SAMLP response status codes.
 * 
 * @author Philip Vendil
 *
 */
public enum ResponseStatusCodes {

	SUCCESS("urn:oasis:names:tc:SAML:2.0:status:Success"),
	REQUESTER("urn:oasis:names:tc:SAML:2.0:status:Requester"),
	RESPONDER("urn:oasis:names:tc:SAML:2.0:status:Responder"),
	VERSION_MISMATCH("urn:oasis:names:tc:SAML:2.0:status:VersionMismatch");
	
	
	private String uRIValue;
	private ResponseStatusCodes(String uRIValue){
		this.uRIValue = uRIValue;
	}
	
	public String getURIValue(){
		return uRIValue;
	}
	
}
