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
package org.certificateservices.messages.pkimessages;

import java.util.Properties;

import org.certificateservices.messages.MessageException;



/**
 * Class in charge of looking up the name of a specific PKI messages.  
 * <p>
 * The main method is lookupName and by default is the simple name of the payload class (with the exception if a PKIResponse object which 
 * generates a name of "FailureResponse").
 * returned. But this can be overloaded by the setting  "pkimessage.name" + the name of the payload element in lowercase. 
 * <p>
 * For example to overload the name of a message with payload isIssuerRequest should the setting
 * be "pkimessage.name.isissuerrequest"
 * @author Philip Vendil
 *
 */
@SuppressWarnings({ "deprecation" })
public class DefaultMessageNameCatalogue implements MessageNameCatalogue {
	
	private Properties properties;
	
	/**
	 * The prefix for overloading pkimessage names, all settings should start with this and append
	 * the name of the payload element in lowercase. 
	 * <p>
	 * For example to overload the name of a message with payload isIssuerRequest should the setting
	 * be "pkimessage.name.isissuerrequest"
	 */
	public static final String SETTING_MESSAGE_NAME_PREFIX = "pkimessage.name.";

	/**
	 * Default constructor
	 * @param properties the properties file of the PKI message parser.
	 */
	public void init(Properties properties){
		this.properties = properties;
	}
	
	/**
	 * Method that looks up the name for a specific setting used to populate the 'name' attribute
	 * in the header, the name is equivalent to the settings starting with "pkimessage.name.'messagename'"
	 *   
	 * @param requestName name
	 * @param payLoadObject the setting to look-up the name for.
	 * @return the name of the message to use.
	 * @throws MessageException if name lookup failed etc.
	 */
	public String lookupName(String requestName, Object payLoadObject) throws MessageException, IllegalArgumentException{
		if(payLoadObject == null){
			throw new MessageException("Payload element cannot be null.");
		}
		String retval =  payLoadObject.getClass().getSimpleName();
		if(retval.equals("PKIResponse")){
			retval = "FailureResponse";
		}
		String setting = SETTING_MESSAGE_NAME_PREFIX + payLoadObject.getClass().getSimpleName().toLowerCase();
		if(properties.getProperty(setting) != null){
			retval = properties.getProperty(setting);
		}
		
		return retval;
		
	}
}
