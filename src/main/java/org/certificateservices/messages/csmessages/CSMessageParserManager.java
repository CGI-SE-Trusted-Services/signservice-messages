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

import java.util.Properties;

import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.MessageSecurityProvider;

/**
 * Factory class in charge of creating and initializing a CS Message Parser from
 * a given configuration.
 * 
 * @author Philip Vendil
 *
 */
public class CSMessageParserManager {
	
	/**
	 * Setting indicating which implementation of CS Message Parser that 
	 * should be used. By default is the Default Message Parser used.
	 */
	public static final String SETTING_CSMESSAGEPARSER_IMPL = "csmessage.parser.impl";
	
	private static final String DEFAULT_IMPLEMENTATION = DefaultCSMessageParser.class.getName();

	private static CSMessageParser parser;
	private static MessageSecurityProvider securityProvider;
	private static Properties config;

	/**
	 * Method to generate a new CSMessageParser from the configuration, if setting "csmessage.parser.impl"
	 * isn't set will the default message parser be created.
	 * 
	 * @param securityProvider the security provider used for the message parser.
	 * @param config the configuration context.
	 * @return a newly created CS Message parser
	 * @throws MessageProcessingException if problems occurred creating a message parser.
	 */
	public static CSMessageParser initCSMessageParser(MessageSecurityProvider securityProvider, Properties config) throws MessageProcessingException{
		CSMessageParserManager.securityProvider = securityProvider;
		CSMessageParserManager.config = config;

		parser = newCSMessageParser();

		return parser;
	}
	
	/**
	 * 
	 * @return true if CSMessageParser have been initialized.
	 */
	public static boolean isInitialized(){
		return parser != null;
	}

	/**
	 * Method to fetch an initialized CSMessageParser.
	 * 
	 * @return the CSMessageParser singleton, initialized.
	 * @throws MessageProcessingException if no initialized CSMessageParser exists.
	 */
	public static CSMessageParser getCSMessageParser() throws MessageProcessingException{
		if(config == null){
			throw new MessageProcessingException("Error CS Message parser haven't been initialized, make sure initCSMessageParser() is called before getCSMessageParser");
		}

		if(parser == null){
			parser = newCSMessageParser();
		}
		return parser;
	}

	private static CSMessageParser newCSMessageParser() throws MessageProcessingException{
		String cp = config.getProperty(SETTING_CSMESSAGEPARSER_IMPL, DEFAULT_IMPLEMENTATION);
		try{
			Class<?> c = CSMessageParserManager.class.getClassLoader().loadClass(cp);
			CSMessageParser parser = (CSMessageParser) c.getDeclaredConstructor().newInstance();
			parser.init(securityProvider, config);
			return parser;
		}catch(Exception e){
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageProcessingException("Error creating CS Message Parser: " + e.getMessage(),e);
		}
	}


}
