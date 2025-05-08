/************************************************************************
 *                                                                       *
 *  Signature Service - Messages                                         *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.messages.csmessages


import spock.lang.Specification;

public class CSMessageVersionSpec extends Specification{
	

	
	def "Test constructor and getter and setters"(){
		when:
		CSMessageVersion v = new CSMessageVersion("1.0", "2.0")
		
		then:
		v.messageVersion == "1.0"
		v.payLoadVersion == "2.0"
		
		when:
		v.messageVersion = "1.1"
		v.payLoadVersion = "2.1"
		
		then:
		v.messageVersion == "1.1"
		v.payLoadVersion == "2.1"
	}
	
	def "Test equals and hashCode is calculated depending on both version values"(){
		setup:
		CSMessageVersion v1 = new CSMessageVersion("1.0", "2.0")
		CSMessageVersion v2 = new CSMessageVersion("1.0", "2.0")
		CSMessageVersion v3 = new CSMessageVersion("1.1", "2.0")
		CSMessageVersion v4 = new CSMessageVersion("1.0", "2.1")
		expect:
		v1 == v2
		v1 != v3
		v1 != v4
		v1.hashCode() == v2.hashCode()
		v1.hashCode() != v3.hashCode()
		v1.hashCode() != v4.hashCode()
	}

}
