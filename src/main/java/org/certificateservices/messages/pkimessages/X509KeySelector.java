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
package org.certificateservices.messages.pkimessages;


import java.security.KeyStore;
import java.security.KeyStoreException;

/**
 * Clone of org.certificateservices.messages.csmessages.X509KeySelector for
 * backward compability.
 * 
 * @author Philip Vendil
 */
@Deprecated
public class X509KeySelector extends org.certificateservices.messages.csmessages.X509KeySelector {


	/**
	 * Creates an <code>X509KeySelector</code>.
	 *
	 * @param keyStore the keystore
	 * @throws KeyStoreException if the keystore has not been initialized
	 * @throws NullPointerException if <code>keyStore</code> is 
	 *    <code>null</code>
	 */
	public X509KeySelector(KeyStore keyStore) throws KeyStoreException {
		super(keyStore);
	}

}


