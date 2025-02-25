package org.signatureservice.messages.pkimessages

import org.signatureservice.messages.MessageException;
import spock.lang.Specification;
import spock.lang.Unroll;

@SuppressWarnings("deprecation")
class PKISettingsUtilsSpec extends Specification{
		

	 @Unroll
	 def "Test that parseBoolean returns #expected for setting #value when not required."(){
		 setup:
		 Properties config = new Properties()
		 if(value != null)
		   config.setProperty("somekey",value)

		 when:
         Boolean result =PKISettingsUtils.parseBoolean(config,"somekey", false)
		 Boolean altResult = PKISettingsUtils.parseBoolean(config,"nonexisting", "somekey", false)
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
		 Boolean result =PKISettingsUtils.parseBoolean(config,"somekey", true)
		 
		then:
		  thrown(MessageException)
		 
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
		 Boolean result =PKISettingsUtils.parseBooleanWithDefault(config,"somekey", defaultVal)
		 Boolean altResult =PKISettingsUtils.parseBooleanWithDefault(config,"nonexisting","somekey", defaultVal)
		 
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
		 String[] result =PKISettingsUtils.parseStringArray(config,"somekey", delimiter, defaultVal)
		 String[] altResult =PKISettingsUtils.parseStringArray(config,"nonexisting","somekey", delimiter, defaultVal)
		 
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
		 String[] result =PKISettingsUtils.parseStringArray(config,"somekey", delimiter, required)
		 String[] altResult =PKISettingsUtils.parseStringArray(config,"nonexisting","somekey", delimiter, required)
		 
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
		String[] result =PKISettingsUtils.parseStringArray(config,"somekey", ",", true)
		
		then:
		thrown(MessageException)
		
		when:
		String[] altResult =PKISettingsUtils.parseStringArray(config,"nonexisting", "somekey", ",", true)
		then:
		thrown(MessageException)
		
	 }
	 
	 def "Test that getRequiredProperty throws and exception when required value isn't set"(){
		setup:
		Properties config = new Properties()

		when:
		PKISettingsUtils.getRequiredProperty(config,"somekey")

		then:
		thrown(MessageException)
		
		when:
		config.setProperty("somekey"," ")
		PKISettingsUtils.getRequiredProperty(config,"somekey")

		then:
		thrown(MessageException)
		
		when:
		PKISettingsUtils.getRequiredProperty(config,"somekey", "someotherkey")

		then:
		thrown(MessageException)
		
		when:
		config.setProperty("someotherkey"," ")
		PKISettingsUtils.getRequiredProperty(config,"somekey", "someotherkey")

		then:
		thrown(MessageException)
				 
	 }
	 
	 
	 def "Test that getRequiredProperty fetches value as expected"(){
		setup:
		Properties config = new Properties()
		config.setProperty("somekey","somevalue")
		when:
		String value = PKISettingsUtils.getRequiredProperty(config,"somekey")

		then:
		assert value == "somevalue"
				 
	 }
	 
	 def "Test that getRequiredProperty fetches alternative value as expected"(){
		 setup:
		 Properties config = new Properties()
		 config.setProperty("somekey","somevalue")
		 when:
		 String value = PKISettingsUtils.getRequiredProperty(config,"nonexisting","somekey")
 
		 then:
		 assert value == "somevalue"
				  
	  }
	 
	 def "Test that getProperty fetches alternative key if not first key is set"(){
		 setup:
		 Properties config = new Properties()
		 config.setProperty("somekey","somevalue")
		 expect:
		 PKISettingsUtils.getProperty(config,"somekey","someotherkey") == "somevalue"
		 PKISettingsUtils.getProperty(config,"notexists","somekey") == "somevalue"
		 PKISettingsUtils.getProperty(config,"notexists","someotherkey") == null
	 }

	

}
