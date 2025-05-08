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
package se.signatureservice.messages

import se.signatureservice.messages.csmessages.CSMessageParserManager
import se.signatureservice.messages.csmessages.CSMessageResponseData
import se.signatureservice.messages.csmessages.DefaultCSMessageParser
import se.signatureservice.messages.csmessages.jaxb.Attribute
import se.signatureservice.messages.utils.SystemTime

import groovy.xml.XmlSlurper
import groovy.xml.XmlUtil
import org.w3c.dom.Document

import java.text.SimpleDateFormat

class TestUtils {
	
	public static XmlSlurper xmlSlurper = new XmlSlurper()

	static def slurpXml(byte[] data){
		return xmlSlurper.parse(new ByteArrayInputStream(data))
	}

	static def slurpXml(String msg){
		return xmlSlurper.parse(new ByteArrayInputStream(msg.getBytes()))
	}

	static String prettyPrintXML(byte[] data){
		return prettyPrintXML(new String(data,"UTF-8"))
	}

	static String prettyPrintXML(String msg){
	    return XmlUtil.serialize(msg)
	}

	static String prettyPrintXML(Document doc){
		return XmlUtil.serialize(doc.getDocumentElement())
	}

	static void printXML(byte[] data){
		println prettyPrintXML(data)
	}

	static void printXML(String msg){
		println prettyPrintXML(msg)
    }

	static void messageContainsPayload(byte[] data, String payloadName){
		String msg = new  String(data, "UTF-8")
		assert msg =~ payloadName
	}

	static void verifyCSMessageResponseData(CSMessageResponseData rd, String expectedDest, String notExpectedMessageId, boolean isForwardable, String expectedMessageName, String expectedRelatedEndEntity){
		assert rd.destination == expectedDest
		assert rd.messageId != notExpectedMessageId && rd.messageId != null
		assert rd.isForwardableResponse == isForwardable
		assert rd.messageName == expectedMessageName
		assert rd.relatedEndEntity == expectedRelatedEndEntity
		assert rd.messageProperties != null
		assert rd.responseMessage != null
	}

	static void setupRegisteredPayloadParser(){
		DummyMessageSecurityProvider secprov = new DummyMessageSecurityProvider()
		Properties config = new Properties()
		config.setProperty(DefaultCSMessageParser.SETTING_SOURCEID, "SOMESOURCEID")
		CSMessageParserManager.initCSMessageParser(secprov,config)
	}

	static Attribute createAttribute(String key, String value){
		Attribute a = new Attribute()
		a.key = key
		a.value = value
		return a
	}
	
	/**
	 * Help method to mock a system time to return given date
	 * @param date in format YYYY-MM-dd
	 * @return a mocked system time
	 */
	static SystemTime mockSystemTime(String date){
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd")
		long time = sdf.parse(date).time
		SystemTime retval = [ getSystemTime : {new Date(time)}, getSystemTimeMS : {time} ] as SystemTime
		return retval
	}
}
