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
package org.signatureservice.messages.pkimessages;



/**
 * XSD Input implementation of a LSInput Interface used when resolving references inside XSD
 * schema to avoid external look-ups.
 * 
 * @author Philip Vendil
 *
 */
public class XSDLSInput extends org.signatureservice.messages.csmessages.XSDLSInput {
	

	/**
	 * Default constructor.
	 * 
	 * @param publicId the publicId of the schema.
	 * @param systemId the systemId of the schema
	 * @param content the schema data.
	 */
	public XSDLSInput(String publicId, String systemId, String content){
	    super(publicId, systemId, content);
	}
	


}
