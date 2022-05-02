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

import org.certificateservices.messages.MessageProcessingException
import spock.lang.Specification
import spock.lang.Unroll

class SettingsUtilsSpec extends Specification{
		

	 @Unroll
	 def "Test that parseBoolean returns #expected for setting #value when not required."(){
		 setup:
		 Properties config = new Properties()
		 if(value != null)
		   config.setProperty("somekey",value)

		 when:
         Boolean result =SettingsUtils.parseBoolean(config,"somekey", false)
		 Boolean altResult = SettingsUtils.parseBoolean(config,"nonexisting", "somekey", false)
		 then:		 
		 assert result == expected
		 assert altResult == expected
		 
		 where:
		 value     | expected
		 "true"    | true
		 "tRue"    | true
		 "FALSE"   | false
		 "false"   | false
		 ""        | null
		 null      | null
	 }
	 
	 
	 @Unroll
	 def "Test that parseBoolean throws exception for invalid setting value #value and required."(){
		 setup:
		 Properties config = new Properties()
		 if(value != null)
		   config.setProperty("somekey",value)

		 when:
		 Boolean result =SettingsUtils.parseBoolean(config,"somekey", true)
		 
		then:
		  thrown(MessageProcessingException)
		 
		 where:
		 value     << ["untrue","maybe","", null]

	 }
	 
	 @Unroll
	 def "Test that parseBooleanWithDefault returns #expected for setting #value with default value #defaultVal"(){
		 setup:
		 Properties config = new Properties()
		 if(value != null)
		   config.setProperty("somekey",value)

		 when:
		 Boolean result =SettingsUtils.parseBooleanWithDefault(config,"somekey", defaultVal)
		 Boolean altResult =SettingsUtils.parseBooleanWithDefault(config,"nonexisting","somekey", defaultVal)
		 
		 then:
		 assert result == expected
		 assert altResult == expected
		 
		 where:
		 value     | expected | defaultVal
		 "true"    | true     | false
		 "tRue"    | true     | false
		 "FALSE"   | false    | true
		 "false"   | false    | true
		 ""        | true     | true
		 null      | false    | false
	 }
	 
	 @Unroll
	 def "Test that parseStringArray returns #expected for setting #value with default value #defaultVal and delimiter #delimiter"(){
		 setup:
		 Properties config = new Properties()
		 if(value != null)
		   config.setProperty("somekey",value)

		 when:
		 String[] result =SettingsUtils.parseStringArray(config,"somekey", delimiter, defaultVal)
		 String[] altResult =SettingsUtils.parseStringArray(config,"nonexisting","somekey", delimiter, defaultVal)
		 
		 then:
		 assert Arrays.equals(result, expected)
		 assert Arrays.equals(altResult, expected)
		 
		 where:
		 value                | expected                       | defaultVal             | delimiter
		 "someval"            | (String[]) ["someval"]         | (String[]) []          | ","
		 "someval , other  "  | (String[]) ["someval","other"] | (String[]) []          | ","
		 null                 | (String[]) ["someval"]         | (String[]) ["someval"] | ","
		"someval , other  "   | (String[]) ["someval , other"] | (String[]) []          | ";"		 
		 
	 }
	 
	 @Unroll
	 def "Test that parseStringArray returns #expected for setting #value and required  #required and delimiter #delimiter"(){
		 setup:
		 Properties config = new Properties()
		 if(value != null)
		   config.setProperty("somekey",value)

		 when:
		 String[] result =SettingsUtils.parseStringArray(config,"somekey", delimiter, required)
		 String[] altResult =SettingsUtils.parseStringArray(config,"nonexisting","somekey", delimiter, required)
		 
		then:
         assert Arrays.equals(result, expected)
		 assert Arrays.equals(altResult, expected)
			
		 
		 where:
		 value                | expected                       | required | delimiter
		 "someval"            | (String[]) ["someval"]         | true     | ","
		 "someval , other  "  | (String[]) ["someval","other"] | true     | ","		
		 "someval , other  "  | (String[]) ["someval , other"] | true     | ";"
		 null                 | (String[]) []                  | false    | ";"
		 
	 }
	 
	 def "Test that parseStringArray throws and exception when required value isn't set"(){
		setup:
		Properties config = new Properties()

		when:
		String[] result =SettingsUtils.parseStringArray(config,"somekey", ",", true)
		
		then:
		thrown(MessageProcessingException)
		
		when:
		String[] altResult =SettingsUtils.parseStringArray(config,"nonexisting", "somekey", ",", true)
		then:
		thrown(MessageProcessingException)
		
	 }
	 
	 def "Test that getRequiredProperty throws and exception when required value isn't set"(){
		setup:
		Properties config = new Properties()

		when:
		SettingsUtils.getRequiredProperty(config,"somekey")

		then:
		thrown(MessageProcessingException)
		
		when:
		config.setProperty("somekey"," ")
		SettingsUtils.getRequiredProperty(config,"somekey")

		then:
		thrown(MessageProcessingException)
		
		when:
		SettingsUtils.getRequiredProperty(config,"somekey", "someotherkey")

		then:
		thrown(MessageProcessingException)
		
		when:
		config.setProperty("someotherkey"," ")
		SettingsUtils.getRequiredProperty(config,"somekey", "someotherkey")

		then:
		thrown(MessageProcessingException)
				 
	 }
	 
	 
	 def "Test that getRequiredProperty fetches value as expected"(){
		setup:
		Properties config = new Properties()
		config.setProperty("somekey","somevalue")
		when:
		String value = SettingsUtils.getRequiredProperty(config,"somekey")

		then:
		assert value == "somevalue"
				 
	 }
	 
	 def "Test that getRequiredProperty fetches alternative value as expected"(){
		 setup:
		 Properties config = new Properties()
		 config.setProperty("somekey","somevalue")
		 when:
		 String value = SettingsUtils.getRequiredProperty(config,"nonexisting","somekey")
 
		 then:
		 assert value == "somevalue"
				  
	  }
	 
	 def "Test that getProperty fetches alternative key if not first key is set"(){
		 setup:
		 Properties config = new Properties()
		 config.setProperty("somekey","somevalue")
		 expect:
		 SettingsUtils.getProperty(config,"somekey","someotherkey") == "somevalue"
		 SettingsUtils.getProperty(config,"notexists","somekey") == "somevalue"
		 SettingsUtils.getProperty(config,"notexists","someotherkey") == null
	 }

	

}
