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
package org.signatureservice.messages.csmessages


import org.signatureservice.messages.MessageProcessingException;
import org.signatureservice.messages.csmessages.PayloadParserRegistry.ConfigurationCallback
import org.signatureservice.messages.dummy.DummyPayloadParser;
import org.signatureservice.messages.sysconfig.SysConfigPayloadParser
import spock.lang.Specification;

public class PayloadParserRegistrySpec extends Specification{
	

	def cleanup(){
		PayloadParserRegistry.configurationCallback = null;
		PayloadParserRegistry.payloadParserCache.clear();
		PayloadParserRegistry.payloadParserRegistry.clear();
	}
	
	def "Test that configure configures the callback and registers all default payload parsers if registerBuiltInPayloads is true "(){
		when:
		PayloadParserRegistry.configure(Mock(ConfigurationCallback), true)
		then:
		PayloadParserRegistry.configurationCallback != null
		PayloadParserRegistry.payloadParserRegistry.get(SysConfigPayloadParser.NAMESPACE) != null
	}
	
	def "Test that configure configures the callback and doesn't register default payload parsers if registerBuiltInPayloads is false "(){
		when:
		PayloadParserRegistry.configure(Mock(ConfigurationCallback), false)
		then:
		PayloadParserRegistry.configurationCallback != null
		PayloadParserRegistry.payloadParserRegistry.size() == 0
	}
	
	def "Verify that register adds payload parser to registry and call updateContext on callback and that deregisters removes the payload parser again."(){
		setup:
		def cb = Mock(ConfigurationCallback)
		2 * cb.updateContext()
		PayloadParserRegistry.configure(cb, true)
		
		DummyPayloadParser pp = new DummyPayloadParser();
		
		when:
		PayloadParserRegistry.register(DummyPayloadParser.NAMESPACE,DummyPayloadParser.class)
		then:
		PayloadParserRegistry.payloadParserRegistry.get(DummyPayloadParser.NAMESPACE) == DummyPayloadParser.class
		PayloadParserRegistry.payloadParserCache.size() == 0
		
		when:
		def namespaces = PayloadParserRegistry.getRegistredNamespaces()
		
		then:
		namespaces.contains(SysConfigPayloadParser.NAMESPACE)
		namespaces.contains(DummyPayloadParser.NAMESPACE)
		
		when:
		PayloadParserRegistry.deregister(DummyPayloadParser.NAMESPACE)
		then:
		PayloadParserRegistry.payloadParserRegistry.get(DummyPayloadParser.NAMESPACE) == null
		PayloadParserRegistry.payloadParserCache.get(DummyPayloadParser.NAMESPACE) == null
	}
	
	def "Verify that register adds payload parser to registry and deregisters doesn't call updateContext on callback  if no callback is configured yet."(){
		setup:
		PayloadParserRegistry.configure(null, true)
		
		DummyPayloadParser pp = new DummyPayloadParser();
		
		when:
		PayloadParserRegistry.register(DummyPayloadParser.NAMESPACE,DummyPayloadParser.class)
		PayloadParserRegistry.deregister(DummyPayloadParser.NAMESPACE)
		then:
		true
	}
	
	def "Verify that getParser first initializes the configured payload parser and then calls the initizalise method to the callback."(){
		setup:
		def cb = Mock(ConfigurationCallback)
		2 * cb.updateContext()
		1 * cb.needReinitialization(DummyPayloadParser.NAMESPACE) >> { return true}
		2 * cb.configurePayloadParser(DummyPayloadParser.NAMESPACE, _ as DummyPayloadParser)
		PayloadParserRegistry.configure(cb, true)
		
		DummyPayloadParser pp = new DummyPayloadParser();
		PayloadParserRegistry.register(DummyPayloadParser.NAMESPACE,DummyPayloadParser.class)
		
		when:
		def pp1 = PayloadParserRegistry.getParser(DummyPayloadParser.NAMESPACE)
		def pp2 = PayloadParserRegistry.getParser(DummyPayloadParser.NAMESPACE)
		
		then:
		pp1 == pp2
		PayloadParserRegistry.payloadParserCache.get(DummyPayloadParser.NAMESPACE) != null
		
		when:
		PayloadParserRegistry.deregister(DummyPayloadParser.NAMESPACE)
		
		then:
		PayloadParserRegistry.payloadParserRegistry.get(DummyPayloadParser.NAMESPACE) == null
		PayloadParserRegistry.payloadParserCache.get(DummyPayloadParser.NAMESPACE) == null
		
	}

	
	def "Verify that getParser throws MessageProcessingException if namespace isn't registerd"(){
		when:
		PayloadParserRegistry.getParser("notexist")
		then:
		thrown MessageProcessingException
	}

}
