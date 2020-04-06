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


public class MonitoringPointSpec extends Specification {

	@Test
	def "Test MonitoringPoint constructors"(){
		when:
		MonitoringPoint mp = new MonitoringPoint("somemonitoringid",new Date(123L), HealthStatus.OK, "somedescription", 1, 2, "someunit")
		then:
		assert mp.getMonitoringPointId() == "somemonitoringid"
		assert mp.getTimestamp() == new Date(123L)
		assert mp.getStatus() == HealthStatus.OK
		assert mp.getDescription() == "somedescription"
		assert mp.getCurrentThroughput() == 1
		assert mp.getMaxThroughput() == 2
		assert mp.getThroughputUnits() == "someunit"
		
		when:
		new MonitoringPoint(null, new Date(123L), HealthStatus.OK)
		then:
		thrown(MessageContentException)
		
		when:
		new MonitoringPoint("",  new Date(123L), HealthStatus.OK)
		then:
		thrown(MessageContentException)
		
		when:
		new MonitoringPoint("somemonitoringid", null, HealthStatus.OK)
		then:
		thrown(MessageContentException)
		
		when:
		new MonitoringPoint("somemonitoringid", new Date(123L), null)
		then:
		thrown(MessageContentException)
	
	}
	
}
