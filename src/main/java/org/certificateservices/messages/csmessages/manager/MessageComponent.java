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
package org.certificateservices.messages.csmessages.manager;

/**
 * Base interface defining a component used for transporting messages such as a sender or a listener.
 * 
 * @author Philip Vendil
 *
 */
public interface MessageComponent {
	
	/**
	 * Method that should provide the name of the JMS Component to use in log files etc..
	 */
	public abstract String getName();

}
