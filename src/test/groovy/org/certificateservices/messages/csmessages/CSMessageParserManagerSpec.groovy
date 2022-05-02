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
package org.certificateservices.messages.csmessages;


import org.certificateservices.messages.DummyMessageSecurityProvider;
import org.certificateservices.messages.MessageProcessingException
import org.certificateservices.messages.credmanagement.CredManagementPayloadParser
import org.certificateservices.messages.csmessages.jaxb.CSMessage
import org.certificateservices.messages.utils.MessageGenerateUtils;
import spock.lang.Specification;

public class CSMessageParserManagerSpec extends Specification{
	
	Properties config = new Properties();
	DummyMessageSecurityProvider secprov = new DummyMessageSecurityProvider();
	
	
	def "Verify that with no configuration is DefaultCSMessageParser returned and initialized."(){
		setup:
		config.setProperty(DefaultCSMessageParser.SETTING_SOURCEID, "SOMESOURCEID")

		when:
		def mp = CSMessageParserManager.initCSMessageParser(secprov, config)
		
		then:
		mp instanceof DefaultCSMessageParser
		mp.securityProvider == secprov
		mp.sourceId == "SOMESOURCEID"
		
		when:
		def mp2 = CSMessageParserManager.getCSMessageParser()
		
		then:
		mp == mp2
		
	}
	
	def "Verify that custom CSMessageParser is returned if configured"(){
		setup:
		config.setProperty(CSMessageParserManager.SETTING_CSMESSAGEPARSER_IMPL, TestCSMessageParser.class.getName())
		
		when:
		def mp = CSMessageParserManager.initCSMessageParser(secprov, config)
		
		then:
		mp instanceof TestCSMessageParser
	}

	def "Verify that MessageProcessingException is thrown if invalid class path was given"(){
		setup:
		config.setProperty(CSMessageParserManager.SETTING_CSMESSAGEPARSER_IMPL, Integer.class.getName())
		
		when:
		CSMessageParserManager.initCSMessageParser(secprov, config)
		then:
		thrown MessageProcessingException
		
		when:
		config.setProperty(CSMessageParserManager.SETTING_CSMESSAGEPARSER_IMPL, "notvalid.Invalid")
		CSMessageParserManager.initCSMessageParser(secprov, config)
		then:
		thrown MessageProcessingException
	}
	
	def "Verify that uninitialized CSMessageParser throws MessageProcessingException when calling getCSMessageParser"(){
		setup:
		CSMessageParserManager.parser = null
		when:
		CSMessageParserManager.getCSMessageParser()
		then:
		thrown MessageProcessingException
	}
	
	def "Verify that isInitialized() returns false for uninitialized and true for initialized CSMessageParserManger"(){
		setup:
		CSMessageParserManager.parser = null
		config.setProperty(DefaultCSMessageParser.SETTING_SOURCEID, "SOMESOURCEID")
		
		expect:
		!CSMessageParserManager.isInitialized()
		
		when:
		CSMessageParserManager.initCSMessageParser(secprov, config)
		then:
		CSMessageParserManager.isInitialized()
	}

	def "Verify that same instance is returned when same thread is calling"(){
		setup:
		config.setProperty(DefaultCSMessageParser.SETTING_SOURCEID, "SOMESOURCEID")
		CSMessageParserManager.initCSMessageParser(secprov, config)
		when:
		def p1 = CSMessageParserManager.getCSMessageParser()
		def p2 = CSMessageParserManager.getCSMessageParser()

		then:
		p1 == p2
	}

	def "Verify that same instance is returned when another thread is calling"(){
		setup:
		config.setProperty(DefaultCSMessageParser.SETTING_SOURCEID, "SOMESOURCEID")
		CSMessageParserManager.initCSMessageParser(secprov, config)

		when:
		def p1 = CSMessageParserManager.getCSMessageParser()
		def p2 = null

		Thread t = new Thread(new Runnable() {
			@Override
			void run() {
				p2 = CSMessageParserManager.getCSMessageParser()
			}
		})
		t.start()

		t.join()

		then:
		p2 != null
		p1 == p2
	}

	def "Verify that several threads can parse CS Messages without SAX Parse Exception is thrown."(){
		setup:
		config.setProperty(DefaultCSMessageParser.SETTING_SOURCEID, "SOMESOURCEID")
		CSMessageParser parser = CSMessageParserManager.initCSMessageParser(secprov, config)
		parser.getMessageSecurityProvider().getSigningCertificate() // Initialize dummy keystore to avoid concurrent problem with dummy message security provider.


		when:
		Thread t1 = new Thread(new SaxParseExceptionRunnable())
		Thread t2 = new Thread(new SaxParseExceptionRunnable())
		Thread t3 = new Thread(new SaxParseExceptionRunnable())

		t1.start()
		t2.start()
		t3.start()

		then:
		t1.join()
		t2.join()
		t3.join()
	}

	private class SaxParseExceptionRunnable implements Runnable{
		@Override
		void run() {
			for(int i=0;i<100;i++) {
				CredManagementPayloadParser pp = PayloadParserRegistry.getParser(CredManagementPayloadParser.NAMESPACE)
				byte[] data = pp.genIsIssuerRequest(MessageGenerateUtils.generateRandomUUID(), "SOMEDEST","SOMEORG","CN=Test", null,null)
				CSMessage msg = pp.parseMessage(data)
				assert msg != null
			}
		}
	}

}
