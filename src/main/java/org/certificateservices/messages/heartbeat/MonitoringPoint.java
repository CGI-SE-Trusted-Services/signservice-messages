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

import java.util.Date;

import org.certificateservices.messages.MessageContentException;

/**
 * Value object of a monitored object, indicating it's status and optional descriptive
 * message.
 * 
 * @author Philip Vendil
 *
 */
public class MonitoringPoint {
	
	public static String MONITORING_POINT_ID_OVERALL_HEALTH = "HEALTH";
	
	private String monitoringPointId;
	private Date timestamp;
	private HealthStatus status;
	private String description;
	private Long currentThroughput;
	private Long maxThroughput;
	private String throughputUnits;
	
	/**
	 * Minimal constructor containing all required parameters.
	 *  
	 * @param monitoringPointId id of the monitoring point in the system, never null or empty.
	 * @param timestamp time stamp of when the monitoring occurred, never null.
	 * @param status the current status of the monitoring point, never null.
	 * @throws IllegalArgumentException  if constructor parameters contained invalid data.
	 */
	public MonitoringPoint(String monitoringPointId, Date timestamp,
			HealthStatus status) throws MessageContentException {
		super();
		if(monitoringPointId == null || monitoringPointId.equals("")){
			throw new MessageContentException("Error creating monitoring point in heart beat message, the monitoring point id cannot be null or empty");
		}
		if(timestamp == null){
			throw new MessageContentException("Error creating monitoring point in heart beat message, time stamp cannot be null.");
		}
		if(status == null){
			throw new MessageContentException("Error creating monitoring point in heart beat message, status cannot be null.");
		}
		this.monitoringPointId = monitoringPointId;
		this.timestamp = timestamp;
		this.status = status;
	}
	
	/**
	 * Constuctor containing a descriptive message about the monitoring point. 
	 * 
	 * @param monitoringPointId id of the monitoring point in the system, never null or empty.
	 * @param timestamp time stamp of when the monitoring occurred, never null.
	 * @param status the current status of the monitoring point, never null.
	 * @param description optional description of the statue of the monitoring point, can be null.
	 * @throws IllegalArgumentException  if constructor parameters contained invalid data.
	 */
	public MonitoringPoint(String monitoringPointId, Date timestamp,
			HealthStatus status, String description) throws MessageContentException {
		this(monitoringPointId, timestamp, status);
		this.description = description;
	}
	
	

	/**
	 * Constuctor containing optional throughput data about the monitoring point.
	 * 
	 * @param monitoringPointId id of the monitoring point in the system, never null or empty.
	 * @param timestamp time stamp of when the monitoring occurred, never null.
	 * @param status the current status of the monitoring point, never null.
	 * @param description optional description of the statue of the monitoring point, can be null.
	 * @param currentThroughput optional current throughput of the given monitoring point, can be null if not applicable.
	 * @param maxThroughput optional estimated maximum throughput of the given monitoring point, can be null if not applicable.
	 * @param throughputUnits optional string containing the units to display when showing the throughput, can be null if not applicable.
	 * @throws IllegalArgumentException  if constructor parameters contained invalid data.
	 */
	public MonitoringPoint(String monitoringPointId, Date timestamp,
			HealthStatus status, String description, Long currentThroughput,
			Long maxThroughput, String throughputUnits) throws MessageContentException {
		this(monitoringPointId, timestamp, status, description);
		this.currentThroughput = currentThroughput;
		this.maxThroughput = maxThroughput;
		this.throughputUnits = throughputUnits;
	}

	/**
	 * 
	 * @return id of the monitoring point in the system, never null or empty.
	 */
	public String getMonitoringPointId() {
		return monitoringPointId;
	}

	/**
	 * 
	 * @return time stamp of when the monitoring occurred, never null.
	 */
	public Date getTimestamp() {
		return timestamp;
	}

	/**
	 * 
	 * @return the current status of the monitoring point, never null.
	 */
	public HealthStatus getStatus() {
		return status;
	}

	/**
	 * 
	 * @return optional description of the statue of the monitoring point, can be null.
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * 
	 * @return optional current throughput of the given monitoring point, can be null if not applicable.
	 */
	public Long getCurrentThroughput() {
		return currentThroughput;
	}

	/**
	 * 
	 * @return optional estimated maximum throughput of the given monitoring point, can be null if not applicable.
	 */
	public Long getMaxThroughput() {
		return maxThroughput;
	}

	/**
	 * 
	 * @return optional string containing the units to display when showing the throughput, can be null if not applicable.
	 */
	public String getThroughputUnits() {
		return throughputUnits;
	}

}
