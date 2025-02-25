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

import org.signatureservice.messages.MessageSecurityProvider;



/**
 * Clone of org.certificateservices.messages.csmessages.X509DataOnlyKeySelector for
 * backward compability.
 * 
 * @author Philip Vendil
 */
@Deprecated
public class X509DataOnlyKeySelector extends org.signatureservice.messages.csmessages.X509DataOnlyKeySelector {
	

	/**
	 * Default constructor.
	 * @param pkiMessageSecurityProvider the provider to use.
	 */
	public X509DataOnlyKeySelector(MessageSecurityProvider pkiMessageSecurityProvider){
		super(pkiMessageSecurityProvider);
	}

	
}


