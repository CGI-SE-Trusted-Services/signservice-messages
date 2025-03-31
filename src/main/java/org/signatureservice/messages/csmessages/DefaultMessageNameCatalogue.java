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

import java.util.Properties;

import jakarta.xml.bind.JAXBElement;

import org.signatureservice.messages.MessageProcessingException;
import org.signatureservice.messages.utils.SettingsUtils;

/**
 * Class in charge of looking up the name of a specific PKI messages.  
 * <p>
 * The main method is lookupName and by default is the simple name of the payload class (with the exception if a PKIResponse object which 
 * generates a name of "FailureResponse").
 * returned. But this can be overloaded by the setting  "csmessage.name" + the name of the payload element in lowercase. 
 * <p>
 * For example to overload the name of a message with payload isIssuerRequest should the setting
 * be "csmessage.name.isissuerrequest"
 * @author Philip Vendil
 *
 */
public class DefaultMessageNameCatalogue implements MessageNameCatalogue {
	
	private Properties properties;
	
	/**
	 * The prefix for overloading pkimessage names, all settings should start with this and append
	 * the name of the payload element in lowercase. 
	 * <p>
	 * For example to overload the name of a message with payload isIssuerRequest should the setting
	 * be "pkimessage.name.isissuerrequest"
	 */
	public static final String SETTING_MESSAGE_NAME_PREFIX = "csmessage.name.";
	
	/**
	 * The prefix for overloading pkimessage names, all settings should start with this and append
	 * the name of the payload element in lowercase. 
	 * <p>
	 * For example to overload the name of a message with payload isIssuerRequest should the setting
	 * be "pkimessage.name.isissuerrequest"
	 */
	public static final String OLD_SETTING_MESSAGE_NAME_PREFIX = "pkimessage.name.";

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
	 * @throws MessageProcessingException if name lookup failed etc.
	 */
	public String lookupName(String requestName, Object payLoadObject) throws MessageProcessingException, IllegalArgumentException{
		if(payLoadObject == null){
			throw new MessageProcessingException("Payload element cannot be null.");
		}
		String retval =  payLoadObject.getClass().getSimpleName();
		if(payLoadObject instanceof JAXBElement<?>){
			retval = ((JAXBElement<?>) payLoadObject).getName().getLocalPart();
		}
		if(retval.equals("CSResponse")){
			retval = "FailureResponse";
		}
		
		String setting = SETTING_MESSAGE_NAME_PREFIX + payLoadObject.getClass().getSimpleName().toLowerCase();
		String altSetting = OLD_SETTING_MESSAGE_NAME_PREFIX + payLoadObject.getClass().getSimpleName().toLowerCase();
		String configuredValue = SettingsUtils.getProperty(properties, setting, altSetting);
		if( configuredValue!= null){
			retval = configuredValue;
		}
		
		return retval;
		
	}
}
