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

import java.util.List;

import org.certificateservices.messages.MessageContentException;
import org.junit.Test;

import spock.lang.Specification;


public class HeartBeatMessageSpec extends Specification {

	@Test
	def "Test HeartBeat constructors"(){
		when:
		HeartBeatMessage msg = new HeartBeatMessage("somesystemId", [new MonitoringPoint("somemonitoringid", new Date(), HealthStatus.OK)], HealthStatus.OK)	
		then:
		assert msg.getSystemId() == "somesystemId"
		assert msg.getMonitoringPoints().size() == 1
		assert msg.getOverallStatus() == HealthStatus.OK
		
		when:
		new HeartBeatMessage(null, [new MonitoringPoint("somemonitoringid", new Date(), HealthStatus.OK)], HealthStatus.OK)
		then:
		thrown(MessageContentException)
		
		when:
		new HeartBeatMessage("", [new MonitoringPoint("somemonitoringid", new Date(), HealthStatus.OK)], HealthStatus.OK)
		then:
		thrown(MessageContentException)
		
		when:
		new HeartBeatMessage("somesystemId", [], HealthStatus.OK)
		then:
		thrown(MessageContentException)
		
		when:
		new HeartBeatMessage("somesystemId", null, HealthStatus.OK)
		then:
		thrown(MessageContentException)
		
		when:
		new HeartBeatMessage("somesystemId", [new MonitoringPoint("somemonitoringid", new Date(), HealthStatus.OK)],null)
		then:
		thrown(MessageContentException)
	}
	
}
