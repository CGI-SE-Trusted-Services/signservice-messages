/************************************************************************
*                                                                       *
*  Certificate Service - Messages                                   *
*                                                                       *
*  This software is free software; you can redistribute it and/or       *
*  modify it under the terms of the GNU Lesser General Public License   *
*  License as published by the Free Software Foundation; either         *
*  version 3   of the License, or any later version.                    *
*                                                                       *
*  See terms of license at gnu.org.                                     *
*                                                                       *
*************************************************************************/
package org.signatureservice.messages.utils;

import java.util.Date;


/**
 * Interface to do system time modularized, mockable and testable.
 * <p>
 * Usually will DefaultSystemTime implementation be sufficient.
 * 
 * @author Philip Vendil
 *
 */
public interface SystemTime {
	
	/**
	 * Method that returns the current system time in milliseconds
	 * @return current system time in milliseconds in date format.
	 */
	Date getSystemTime();

	/**
	 * Method that returns the current system time in milliseconds
	 * @return current system time in milliseconds.
	 */
	long getSystemTimeMS();
}
