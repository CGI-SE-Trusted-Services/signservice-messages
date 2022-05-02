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
package org.certificateservices.messages.utils


import spock.lang.Specification

import javax.xml.datatype.DatatypeConstants
import javax.xml.datatype.XMLGregorianCalendar

class MessageGenerateUtilsSpec extends Specification{


	def "Test that generateRandomUUID generates UUID that matches the pattern."(){

		when:
		String uuid = MessageGenerateUtils.generateRandomUUID()

		then:
		assert uuid.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[8-9a-bA-B][0-9a-fA-F]{3}-[0-9a-fA-F]{12}");
	}

	def "Generate 1000 UUIDs and check that they all are unique."(){
		setup:
		HashSet<String> generated = []
		when:
		for(int i=0; i<1000;i++){
			String uuid = MessageGenerateUtils.generateRandomUUID()
			assert uuid.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[8-9a-bA-B][0-9a-fA-F]{3}-[0-9a-fA-F]{12}")
			assert !generated.contains(uuid)
			generated.add(uuid)
		}
		then:
		assert true
	}

	def "Test dateToXMLGregorianCalendar method converts date correctly"(){
		when: " date is null should result be null"
		XMLGregorianCalendar result = MessageGenerateUtils.dateToXMLGregorianCalendar(null);
		then:
		result == null
		when: " date is set should a XML gregorian calendar be returned."
		result = MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(0L));
		then:
		println result.toString()
		result.toString().startsWith("1970")
		result.timezone != DatatypeConstants.FIELD_UNDEFINED
	}

	def "Test dateToXMLGregorianCalendarNoTimeZone method converts date correctly"(){
		when: " date is null should result be null"
		XMLGregorianCalendar result = MessageGenerateUtils.dateToXMLGregorianCalendar(null);
		then:
		result == null
		when: " date is set should a XML gregorian calendar be returned."
		result = MessageGenerateUtils.dateToXMLGregorianCalendarNoTimeZone(new Date(0L));
		then:
		println result.toString()
		result.timezone == 0
		result.toString().startsWith("1970")
	}

	def "Test xMLGregorianCalendarToDate method converts date correctly"(){
		when: " calendarDate is null should result be null"
		Date result = MessageGenerateUtils.xMLGregorianCalendarToDate(null);
		then:
		result == null
		when: " calendarDate should generate a date if XMLGregorianCalendarToDate is valid."
		result = MessageGenerateUtils.xMLGregorianCalendarToDate(MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(0L)))
		then:
		result.getTime() == 0L
	}

	def "Test bytesToHex converts to hex encoding correclty"(){
		expect:
		MessageGenerateUtils.bytesToHex(null) == null
		MessageGenerateUtils.bytesToHex("123".getBytes()) == "313233"
	}

}