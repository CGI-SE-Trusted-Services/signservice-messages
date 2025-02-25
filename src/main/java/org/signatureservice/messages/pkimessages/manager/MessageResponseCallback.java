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
package org.signatureservice.messages.pkimessages.manager;

import org.signatureservice.messages.pkimessages.jaxb.PKIMessage;

/**
 * Callback interface used to signal that a response targeted for this client (i.e destinationId = current sourceId)
 * <p>
 * Main method is responseRecieved
 * <p>
 * <b>Important</b> only messages with a destination matching this source id should be sent through
 * this callback.
 * 
 * @author Philip Vendil
 *
 */
public interface MessageResponseCallback {
	
	/**
	 * Method signaling that a response was received.
     * <p>
     * <b>Important</b> only messages with a destination matching this source id should be sent through
     * this callback.
	 * @param responseMessage the response message that was received.
	 */
	public void responseReceived(PKIMessage responseMessage);

}
