/************************************************************************
*                                                                       *
*  Certificate Service - PKI Messages                                   *
*                                                                       *
*  This software is free software; you can redistribute it and/or       *
*  modify it under the terms of the GNU Affero General Public License   *
*  License as published by the Free Software Foundation; either         *
*  version 3   of the License, or any later version.                    *
*                                                                       *
*  See terms of license at gnu.org.                                     *
*                                                                       *
*************************************************************************/
package org.certificateservices.messages.pkimessages;

import java.util.Properties;

import org.certificateservices.messages.MessageException;
import org.certificateservices.messages.MessageSecurityProvider;

/**
 * Factory class in charge of creating and initializing a PKI Message Parser from
 * a given configuration.
 * 
 * @author Philip Vendil
 *
 */
@SuppressWarnings({ "deprecation" })
public class PKIMessageParserFactory {
	
	/**
	 * Setting indicating which implementation of PKI Message Parser that 
	 * should be used. By default is the Default Message Parser used.
	 */
	public static final String SETTING_PKIMESSAGEPARSER_IMPL = "pkimessage.parser.impl";
	
	private static final String DEFAULT_IMPLEMENTATION = DefaultPKIMessageParser.class.getName();
	

	/**
	 * Method to generate a new PKIMessageParser from the configuration, if setting "pkimessage.parser.impl"
	 * isn't set will the default message parser be created.
	 * 
	 * @param securityProvider the security provider used for the message parser.
	 * @param config the configuration context.
	 * @return a newly created PKI Message parser
	 * @throws MessageException if problems occurred creating a message parser.
	 */
	public static PKIMessageParser genPKIMessageParser(MessageSecurityProvider securityProvider, Properties config) throws MessageException{
		String cp = config.getProperty(SETTING_PKIMESSAGEPARSER_IMPL, DEFAULT_IMPLEMENTATION);
		try{
			Class<?> c = PKIMessageParserFactory.class.getClassLoader().loadClass(cp);
			PKIMessageParser retval = (PKIMessageParser) c.newInstance();
			retval.init(securityProvider, config);
			return retval;
		}catch(Exception e){
			if(e instanceof MessageException){
				throw (MessageException) e;
			}			
			throw new MessageException("Error creating PKI Message Parser: " + e.getMessage(),e);			
		}
	}

}
