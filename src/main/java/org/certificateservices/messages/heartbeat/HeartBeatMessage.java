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
package org.certificateservices.messages.heartbeat;

import java.util.List;

import org.certificateservices.messages.MessageContentException;

/**
 * Value object containing all the information about a receipt message.
 * 
 * @author Philip Vendil
 *
 */
public class HeartBeatMessage {

	private String systemId;
	private List<MonitoringPoint> monitoringPoints;	
	private HealthStatus overallStatus;
	
	/**
	 * Default constructor for a heart beat message.
	 * 
	 * @param systemId the id of the system sending the heart beat, never null
	 * @param monitoringPoints a list of monitoring points in the heart beat, at least one message should exists
	 * @param overallStatus summary status of the system, never null.  
	 * @throws MessageContentException if invalid parameters where sent to the constructor.
	 */
	public HeartBeatMessage(String systemId, List<MonitoringPoint> monitoringPoints, HealthStatus overallStatus) throws MessageContentException{
		if(systemId == null || systemId.equals("")){
			throw new MessageContentException("Error creating heart beat message, the system id cannot be null or empty");
		}
		if(monitoringPoints == null || monitoringPoints.size() <1){
			throw new MessageContentException("Error creating heart beat message, at least one monitoring point must exist in the message.");
		}
		if(overallStatus == null){
			throw new MessageContentException("Error creating heart beat message, overall status cannot be null.");
		}
		this.systemId = systemId;
		this.monitoringPoints = monitoringPoints;
		this.overallStatus = overallStatus;
	}
	
	/**
	 * 
	 * @return the id of the system sending the heart beat, never null
	 */
	public String getSystemId() {
		return systemId;
	}
	

	
	/**
	 * 
	 * @return the current set of monitoring point, never null.
	 */
	public List<MonitoringPoint> getMonitoringPoints() {
		return monitoringPoints;
	}

	/**
	 * 
	 * @return summary status of the system, never null.  
	 */
	public HealthStatus getOverallStatus() {
		return overallStatus;
	}
	
	
		
	
}
