/************************************************************************
 *                                                                       *
 *  Signature Service - Messages                                         *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.messages.utils;

import java.util.Properties;

import se.signatureservice.messages.MessageProcessingException;



/**
 * Utils used for parsing settings in configuration.
 * 
 * @author Philip Vendil
 *
 */
public class SettingsUtils {
	
	/**
	 * Utility to parse a boolean "TRUE" or "FALSE" from the configuration file.
	 * 
	 * @param config the configuration to fetch setting from.
	 * @param setting the setting to fetch
	 * @param required if required is a MessageProcessingException thrown if setting isn't set.
	 * @return a boolean value of the setting.
	 * @throws MessageProcessingException if setting couldn't be read properly from the configuration file.
	 */
	public static Boolean parseBoolean(Properties config, String setting, boolean required) throws MessageProcessingException{
		return parseBoolean(config, setting, null, required);
	}
	
	/**
	 * Utility to parse a boolean "TRUE" or "FALSE" from the configuration file.
	 * 
	 * @param config the configuration to fetch setting from.
	 * @param setting the setting to fetch
	 * @param alternativeSetting for backward compability settings.
	 * @param required if required is a MessageProcessingException thrown if setting isn't set.
	 * @return a boolean value of the setting.
	 * @throws MessageProcessingException if setting couldn't be read properly from the configuration file.
	 */
	public static Boolean parseBoolean(Properties config, String setting, String alternativeSetting, boolean required) throws MessageProcessingException{
		String value = config.getProperty(setting, (alternativeSetting != null ? config.getProperty(alternativeSetting, "") : ""));

		if(value == null || value.trim().equals("")){
			if(required){
				throw new MessageProcessingException("Error parsing setting " + setting + ", a value must be set to either TRUE or FALSE");
			}
			return null;
		}
		value = value.trim().toUpperCase();
		if(value.equals("TRUE")){
			return true;
		}else{
			if(value.equals("FALSE")){
				return false;
			}else{
				throw new MessageProcessingException("Error parsing setting " + setting + ", value must be either TRUE or FALSE");
			}
		}
	}
	
	/**
	 * Utility to parse a boolean "TRUE" or "FALSE" from the configuration file with the option
	 * of a default value if not set. 
	 * 
	 * @param config the configuration to fetch setting from.
	 * @param setting the setting to fetch
	 * @param defaultValue value to return if not set.
	 * @return the boolean setting of the value of the default value if not set.
	 * @throws MessageProcessingException if setting couldn't be read properly from the configuration file.
	 */
	public static boolean parseBooleanWithDefault(Properties config, String setting, boolean defaultValue) throws MessageProcessingException{
		return parseBooleanWithDefault(config, setting, null, defaultValue);
	}
	
	/**
	 * Utility to parse a boolean "TRUE" or "FALSE" from the configuration file with the option
	 * of a default value if not set. 
	 * 
	 * @param config the configuration to fetch setting from.
	 * @param setting the setting to fetch
	 * @param alternativeSetting for backward compability settings.
	 * @param defaultValue value to return if not set.
	 * @return the boolean setting of the value of the default value if not set.
	 * @throws MessageProcessingException if setting couldn't be read properly from the configuration file.
	 */
	public static boolean parseBooleanWithDefault(Properties config, String setting,  String alternativeSetting, boolean defaultValue) throws MessageProcessingException{
		Boolean retval = parseBoolean(config, setting, alternativeSetting, false);
		if(retval == null){
			return defaultValue;
		}
		return retval;
	}
	
	/**
	 * Method to parse a string with the given deliminator into a String array, with every value trimmed.
	 * 
	 * @param config the configuration to read from.
	 * @param setting the setting to look-up.
	 * @param deliminator separator used to indicate where to split the string.
	 * @param defaulValue a default value if 
	 * @return and array of strings splitted and trimmed, never null.
	 */
	public static String[] parseStringArray(Properties config, String setting, String deliminator, String[] defaulValue){
		return parseStringArray(config, setting, null, deliminator, defaulValue);
	}

	/**
	 * Method to parse a string with the given deliminator into a String array, with every value trimmed.
	 * 
	 * @param config the configuration to read from.
	 * @param setting the setting to look-up.
	 * @param alternativeSetting for backward compability settings.
	 * @param deliminator separator used to indicate where to split the string.
	 * @param defaulValue a default value if 
	 * @return and array of strings splitted and trimmed, never null.
	 */
	public static String[] parseStringArray(Properties config, String setting, String alternativeSetting, String deliminator, String[] defaulValue){
		String value = config.getProperty(setting);
		if(value == null && alternativeSetting != null){
			value = config.getProperty(alternativeSetting);
		}
		if(value == null || value.trim().equals("")){
			return defaulValue;
		}
		String[] values = value.split(deliminator);
		for(int i=0; i< values.length; i++){
			values[i] = values[i].trim();
		}
		return values;
	}
	
	/**
	 * Method to parse a string with the given deliminator into a String array, with every value trimmed and
	 * a MessageProcessingException thrown if a required setting isn't set.
	 * 
	 * @param config the configuration to read from.
	 * @param setting the setting to look-up.
	 * @param deliminator separator used to indicate where to split the string.
	 * @param required if an exception should be thrown if setting isn't set.
	 * @return and array of strings splitted and trimmed, never null.
	 */
    public static String[] parseStringArray(Properties config, String setting, String deliminator, boolean required) throws MessageProcessingException{
		return parseStringArray(config, setting, null, deliminator, required);
	}
    
	/**
	 * Method to parse a string with the given deliminator into a String array, with every value trimmed and
	 * a MessageProcessingException thrown if a required setting isn't set.
	 * 
	 * @param config the configuration to read from.
	 * @param setting the setting to look-up.
	 * @param alternativeSetting for backward compability settings.
	 * @param deliminator separator used to indicate where to split the string.
	 * @param required if an exception should be thrown if setting isn't set.
	 * @return and array of strings splitted and trimmed, never null.
	 */
    public static String[] parseStringArray(Properties config, String setting, String alternativeSetting, String deliminator, boolean required) throws MessageProcessingException{
		String value = config.getProperty(setting);
		if(value == null && alternativeSetting != null){
			value = config.getProperty(alternativeSetting);
		}
		if(value == null || value.trim().equals("")){
			if(required){
			  throw new MessageProcessingException("Required setting " + setting + " not set.");
			}else{
				return new String[0];
			}
		}
		String[] values = value.split(deliminator);
		for(int i=0; i< values.length; i++){
			values[i] = values[i].trim();
		}
		return values;
	}
    
    /**
     * Looks up a required property and throws exception if not set.
     * 
     * @param config the configuration to read from.
	 * @param setting the setting to look-up.
     * @return the value if set.
     * @throws MessageProcessingException if setting wasn't set or set to ""
     */
	public static String getRequiredProperty(Properties config, String key) throws MessageProcessingException{
		return getRequiredProperty(config, key, null);
	}
	
    /**
     * Looks up a required property and throws exception if not set.
     * 
     * @param config the configuration to read from.
	 * @param setting the setting to look-up.
	 * @param alternativeSettings for backward compability settings.
     * @return the value if set.
     * @throws MessageProcessingException if setting wasn't set or set to ""
     */
	public static String getRequiredProperty(Properties config, String setting, String alternativeSettings) throws MessageProcessingException{
		String value = config.getProperty(setting, (alternativeSettings != null ? config.getProperty(alternativeSettings, "") : ""));
		if(value.trim().equals("")){
			throw new MessageProcessingException("Error required configuration property " + setting + " not set.");
		}
		return value;
	}
	
    /**
     * Looks up a required property and returns null if not set.
     * 
     * @param config the configuration to read from.
	 * @param setting the setting to look-up.
	 * @param alternativeSetting for backward compability settings.
     * @return the value if set.
	 */
	public static String getProperty(Properties config, String key, String alternativeSettings){
		return config.getProperty(key, (alternativeSettings != null ? config.getProperty(alternativeSettings, null) : null));
	}
}
