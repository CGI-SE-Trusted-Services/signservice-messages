package org.certificateservices.messages.pkimessages

import javax.xml.datatype.XMLGregorianCalendar
import spock.lang.Specification

class PKIMessageGenerateUtilsSpec extends Specification{
		
	 def "Test that generateRandomUUID generates UUID that matches the pattern."(){

		 when:
         String uuid = PKIMessageGenerateUtils.generateRandomUUID()
		 
		 then:		 
		 assert uuid.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[8-9a-bA-B][0-9a-fA-F]{3}-[0-9a-fA-F]{12}");
	 }
	 
	 def "Generate 1000 UUIDs and check that they all are unique."(){
		 setup:
		 HashSet<String> generated = [];
		 when:
		 for(int i=0; i<1000;i++){
		   String uuid = PKIMessageGenerateUtils.generateRandomUUID()		   
		   assert uuid.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[8-9a-bA-B][0-9a-fA-F]{3}-[0-9a-fA-F]{12}");
		   assert !generated.contains(uuid);
		   generated.add(uuid);
		 }
		 then:
		 assert true;
	 }
	
	 def "Test dateToXMLGregorianCalendar method converts date correctly"(){
		 when: " date is null should result be null"
		 XMLGregorianCalendar result = PKIMessageGenerateUtils.dateToXMLGregorianCalendar(null);
		 then:
		 result == null
		 when: " date is set should a XML gregorian calendar be returned."
		 result = PKIMessageGenerateUtils.dateToXMLGregorianCalendar(new Date(0L));
		 then:
		 result.toString().startsWith("1970")
	 }
	 
	 def "Test xMLGregorianCalendarToDate method converts date correctly"(){
		 when: " calendarDate is null should result be null"
		 Date result = PKIMessageGenerateUtils.xMLGregorianCalendarToDate(null);
		 then:
		 result == null
		 when: " calendarDate should generate a date if XMLGregorianCalendarToDate is valid."
		 result = PKIMessageGenerateUtils.xMLGregorianCalendarToDate(PKIMessageGenerateUtils.dateToXMLGregorianCalendar(new Date(0L)))
		 then:
		 result.getTime() == 0L
	 }
	 
	 def "Test bytesToHex converts to hex encoding correclty"(){
		 expect:
		 PKIMessageGenerateUtils.bytesToHex(null) == null
		 PKIMessageGenerateUtils.bytesToHex("123".getBytes()) == "313233"
	 }

}
