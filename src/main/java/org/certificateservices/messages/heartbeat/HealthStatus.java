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
package org.certificateservices.messages.heartbeat;

/**
 * Health status enumeration indicating the level of severity of a given monitoring point
 * or the overall status.
 * 
 * @author Philip Vendil
 *
 */
public enum HealthStatus {
	/**
	 * Indicating that everything is OK with related monitoring point.
	 */
	OK,
	/**
	 * Indicating some non critical error is occurring at the monitoring point that should be supervised,
	 * to avoid it stop functioning in the future.
	 */
	WARNING,
	/**
	 * Indicating a critical error occurred at the monitoring point that should be corrected. 
	 */
	ERROR;
}
