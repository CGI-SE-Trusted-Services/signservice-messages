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
package se.signatureservice.messages.csmessages


import se.signatureservice.messages.MessageProcessingException;

public class TestMessageNameCatalogue implements MessageNameCatalogue{
	
	boolean initCalled = false

	@Override
	public void init(Properties config) throws MessageProcessingException {
		assert config != null
		initCalled = true
		
	}

	@Override
	public String lookupName(String requestName, Object payLoadObject)
			throws MessageProcessingException, IllegalArgumentException {
		return null
	}
	
}
