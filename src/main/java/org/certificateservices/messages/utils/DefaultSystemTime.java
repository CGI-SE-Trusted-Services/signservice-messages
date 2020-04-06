/************************************************************************
*                                                                       *
*  Certificate Service - Messages                                   *
*                                                                       *
*  This software is free software; you can redistribute it and/or       *
*  modify it under the terms of the GNU Affero General Public License   *
*  License as published by the Free Software Foundation; either         *
*  version 3   of the License, or any later version.                    *
*                                                                       *
*  See terms of license at gnu.org.                                     *
*                                                                       *
*************************************************************************/
package org.certificateservices.messages.utils;

import java.util.Date;

/**
 * Default implementation of SystemTime that gets the system time from
 * System.currentTimeMillis()
 * 
 * @author Philip Vendil
 *
 */
public class DefaultSystemTime implements SystemTime {

	/**
	 * Default implementation of SystemTime that gets the system time from
     * System.currentTimeMillis()
     * 
	 * @see org.certificateservices.messages.utils.SystemTime#getSystemTime()
	 */
	public Date getSystemTime() {
		return new Date(System.currentTimeMillis());
	}
	
	/**
	 * Default implementation of SystemTime that gets the system time from
     * System.currentTimeMillis()
     * 
	 * @see org.certificateservices.messages.utils.SystemTime#getSystemTimeMS()
	 */
	public long getSystemTimeMS() {
		return System.currentTimeMillis();
	}

}
