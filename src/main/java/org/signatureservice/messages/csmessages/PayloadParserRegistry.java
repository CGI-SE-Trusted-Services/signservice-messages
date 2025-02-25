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
package org.signatureservice.messages.csmessages;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.signatureservice.messages.MessageProcessingException;
import org.signatureservice.messages.assertion.AssertionPayloadParser;
import org.signatureservice.messages.authorization.AuthorizationPayloadParser;
import org.signatureservice.messages.autoenroll.AutoEnrollPayloadParser;
import org.signatureservice.messages.credmanagement.CredManagementPayloadParser;
import org.signatureservice.messages.csagent.CSAgentProtocolPayloadParser;
import org.signatureservice.messages.csexport.protocol.CSExportProtocolPayloadParser;
import org.signatureservice.messages.encryptedcsmessage.EncryptedCSMessagePayloadParser;
import org.signatureservice.messages.keystoremgmt.KeystoreMgmtPayloadParser;
import org.signatureservice.messages.signrequest.SignRequestPayloadParser;
import org.signatureservice.messages.sysconfig.SysConfigPayloadParser;
import org.signatureservice.messages.v2x.backend.V2XBackendPayloadParser;
import org.signatureservice.messages.v2x.registration.V2XPayloadParser;

/**
 * Class in charge of maintaining available PayLoadParsers for different pay load content in CS Messages.
 * <p>
 * It contains methods for plug-ins of new pay load to register and de-register its handlers.
 * <p>
 * <b>Important:</b> before any call to getParser() is done must configure() with an appropriate callback implementation 
 * be called.
 * 
 * @author Philip Vendil
 *
 */
public class PayloadParserRegistry {
		
	private static Map<String, Class<? extends PayloadParser>> payloadParserRegistry = new HashMap<String, Class<? extends PayloadParser>>();
	private static Map<String,PayloadParser> payloadParserCache = new HashMap<String, PayloadParser>(); 
	private static ConfigurationCallback configurationCallback = null;
	
	/**
	 * Setup method that should be called from the CSMessageParser or eqvivalent, and set a ConfigurationCallback implementation
	 * in charge of initializing respective payload parser.
	 * 
	 * <b>Important:</b> This method must be called before any getParser() calls are performed.
	 * 
	 * @param callback the configuration callback to use when initializing created payload providers.
	 * @param registerBuiltInPayloads if build in payload parsers should be registered when configuring.
	 */
	public static void configure(ConfigurationCallback callback, boolean registerBuiltInPayloads) {
		configurationCallback = callback;

		// Register built in payload parsers here.
		if(registerBuiltInPayloads){
		  payloadParserRegistry.put(SysConfigPayloadParser.NAMESPACE, SysConfigPayloadParser.class);
		  payloadParserRegistry.put(KeystoreMgmtPayloadParser.NAMESPACE, KeystoreMgmtPayloadParser.class);
		  payloadParserRegistry.put(CredManagementPayloadParser.NAMESPACE, CredManagementPayloadParser.class);
		  payloadParserRegistry.put(AssertionPayloadParser.NAMESPACE, AssertionPayloadParser.class);
		  payloadParserRegistry.put(EncryptedCSMessagePayloadParser.NAMESPACE, EncryptedCSMessagePayloadParser.class);
		  payloadParserRegistry.put(AuthorizationPayloadParser.NAMESPACE, AuthorizationPayloadParser.class);
		  payloadParserRegistry.put(CSExportProtocolPayloadParser.NAMESPACE, CSExportProtocolPayloadParser.class);
		  payloadParserRegistry.put(AutoEnrollPayloadParser.NAMESPACE, AutoEnrollPayloadParser.class);
		  payloadParserRegistry.put(CSAgentProtocolPayloadParser.NAMESPACE, CSAgentProtocolPayloadParser.class);
		  payloadParserRegistry.put(SignRequestPayloadParser.NAMESPACE, SignRequestPayloadParser.class);
		  payloadParserRegistry.put(V2XPayloadParser.NAMESPACE, V2XPayloadParser.class);
		  payloadParserRegistry.put(V2XBackendPayloadParser.NAMESPACE, V2XBackendPayloadParser.class);
		}
	}
	
	/**
	 * Method to fetch a initialized PayloadParser for a given name space.
	 * 
	 * @param namespace the name space to fetch PayloadParser for.
	 * @return related PayloadParser, never null.
	 * @throws MessageProcessingException if parser for given name space couldn't be found or internal problems occurred generating the parser.
	 */
	public static PayloadParser getParser(String namespace) throws MessageProcessingException{
		PayloadParser retval = payloadParserCache.get(namespace);
		if(retval == null){
			Class<? extends PayloadParser> registeredClass = payloadParserRegistry.get(namespace);
			if(registeredClass == null){
				throw new MessageProcessingException("Error no parser registered for payload with namespace: " + namespace);
			}
			try {
				retval = registeredClass.getDeclaredConstructor().newInstance();
			} catch (Exception e) {
			  throw new MessageProcessingException("Error occurred creating a payload parser implementation: " + registeredClass + " : " + e.getMessage(),e);
			}
			configurationCallback.configurePayloadParser(namespace, retval);
			payloadParserCache.put(namespace, retval);
		}else{
			if(configurationCallback.needReinitialization(namespace)){
				configurationCallback.configurePayloadParser(namespace, retval);
			}
		}
		return retval;
	}
	
	/**
	 * Method to fetch a set of registered name spaces.
	 * @return set of registered name spaces.
	 */
	public static Set<String> getRegistredNamespaces(){
		return payloadParserRegistry.keySet();
	}
	
	/**
	 * Method to register a pay load parser as available for processing.
	 * 
	 * @param namespace the name space of the payLoadParser to 
	 * @param payLoadParser the class path of the pay load parser to register.
	 * @throws MessageProcessingException 
	 */
	public static void register(String namespace, Class<? extends PayloadParser> payLoadParser) throws MessageProcessingException{
		payloadParserRegistry.put(namespace, payLoadParser);
		if(configurationCallback != null){
		  configurationCallback.updateContext();
		}
	}
	
	/**
	 * Method to remove a given pay load parser from the registry along with cached instance of the parser.
	 * 
	 * @param namespace pay load parser to remove.
	 * @throws MessageProcessingException 
	 */
	public static void deregister(String namespace) throws MessageProcessingException{
		payloadParserCache.remove(namespace);
		payloadParserRegistry.remove(namespace);
		if(configurationCallback != null){
		  configurationCallback.updateContext();
		}
	}
	
	
	/**
	 * Configuration Callback that should be implemented by CSMessageParser that is in charge of managing
	 * all registrered pay load parsers.
	 * 
	 * @author Philip Vendil
	 *
	 */
	public interface ConfigurationCallback{
		
		/**
		 * Method to determine if a parser needs to be reinitized with a new configuration.
		 * 
		 * 
		 * @throws MessageProcessingException if internal exception occurred checking configuration update.
		 */
		public boolean needReinitialization(String namespace) throws MessageProcessingException;

		/**
		 * Method called by the registry when a payload parser is initialized and needs current
		 * active configuration.
		 *
		 * @throws MessageProcessingException if internal exception occurred providing configuration data.
		 */
		public void configurePayloadParser(String namespace, PayloadParser payloadParser) throws MessageProcessingException;
		
		/**
		 * Method called by PayloadParserRegistry when a new payload parser have be registered or
		 * de-registered and the configuration manager might need to update it's context.
		 */
		public void updateContext() throws MessageProcessingException;
		
	}

}
