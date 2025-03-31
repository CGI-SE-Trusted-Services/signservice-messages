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
package org.signatureservice.messages.dummy;

import java.io.InputStream;
import java.util.Properties;

import org.signatureservice.messages.MessageContentException;
import org.signatureservice.messages.MessageProcessingException;
import org.signatureservice.messages.MessageSecurityProvider;
import org.signatureservice.messages.csmessages.PayloadParser;
import org.signatureservice.messages.dummy.jaxb.ObjectFactory;
import org.signatureservice.messages.dummy.jaxb.SomePayload;

/**
 * Dummy implementation of a PayloadParser
 * 
 * @author Philip Vendil
 *
 */
public class DummyPayloadParser implements PayloadParser{
	
	public static String NAMESPACE = "http://certificateservices.org/xsd/dummy2_0";

	Properties config = null;
	boolean initCalled = false;

	ObjectFactory of = new ObjectFactory();

	
	public void init(Properties config, MessageSecurityProvider secProv) throws MessageProcessingException {
		this.config = config;
		initCalled = true;
	}
	
	public SomePayload genSomePayload(String someValue){
		SomePayload retval = of.createSomePayload();
		retval.setSomeValue(someValue);
		return retval;
	}

	
	public String getNameSpace() {
		return NAMESPACE;
	}

	
	public String getJAXBPackage() {
		return "org.signatureservice.messages.dummy.jaxb";
	}

	
	public InputStream getSchemaAsInputStream(String payLoadVersion)
			throws MessageContentException, MessageProcessingException {
		return getClass().getResourceAsStream("/dummypayload_schema2_0.xsd");
	}

	/**
	 * Method that should return related schemas used during payload schema validation.
	 *
	 * @param payloadVersion payload version.
	 * @return an array of related schemas if no related schemas exists is empty array returned, never null.
	 */
	@Override
	public String[] getRelatedSchemas(String payloadVersion) {
		return new String[0];
	}


}
