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

import java.io.InputStream;
import java.util.Properties;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.MessageSecurityProvider;


/**
 * Interface defining required method for a payload parser.
 * 
 * @author Philip Vendil
 *
 */
public interface PayloadParser {
	
	/**
	 * Method that initializes the CSMessage parser with properties.
	 * 
	 * <p>
	 * This method might be called more than once if configuration have been updated and the parser needs to be updated.
	 * 
	 * @param config the configuration of the parser.
	 * @param secProv the related message security provider.
	 * @throws MessageProcessingException if configuration contained bad configuration of security provider.
	 */
	void init(Properties config, MessageSecurityProvider secProv) throws MessageProcessingException;
	
	/**
	 * 
	 * @return the related pay load elements unique name space.
	 */
	String getNameSpace();
	
	/**
	 * Method that returns the JAXBPackage Name for the package name containing the JAXB classes. For multiple package names use a ':' without spaces.
	 */
	String getJAXBPackage();
	
	/**
	 * Method that should return the location of the schema for a given payLoadVersion, it should be accessable as a class resource using
	 * getClass().getResourceAsStream()
	 * 
	 * @throws MessageContentException if given version isn't supported.
	 * @throws MessageProcessingException if problems occurred setting up the stream.
	 */
	InputStream getSchemaAsInputStream(String payLoadVersion) throws MessageContentException,MessageProcessingException;

	/**
	 * Method that should return related schemas used during payload schema validation.
	 * @param payloadVersion payload version.
	 * @return an array of related schemas if no related schemas exists is empty array returned, never null.
	 */
	String[] getRelatedSchemas(String payloadVersion);

}
