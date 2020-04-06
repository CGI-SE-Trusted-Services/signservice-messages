package org.certificateservices.messages.csmessages.examples

import java.util.Properties;

import org.certificateservices.messages.assertion.AssertionPayloadParser;
import org.certificateservices.messages.csmessages.PayloadParserRegistry;
import org.certificateservices.messages.utils.DefaultSystemTime;

import spock.lang.Specification



class ExampleSpecification extends Specification {

	def setup(){
		PayloadParserRegistry.payloadParserCache.clear();
		// This only needed for the unit test to work.
		PayloadParserRegistry.getParser(AssertionPayloadParser.NAMESPACE).systemTime = new DefaultSystemTime()
		
	}
	
	def cleanup(){
		PayloadParserRegistry.payloadParserCache.clear();
	}
	
	
	protected Properties getConfig(String config){
		config = config.replace("KEYSTORELOCATION", this.getClass().getResource("/dummykeystore.jks").getPath())
		config = config.replace("TRUSTSTORELOCATION", this.getClass().getResource("/testtruststore.jks").getPath())
		Properties retval = new Properties();
		retval.load(new StringReader(config))
		return retval;
	}


}
