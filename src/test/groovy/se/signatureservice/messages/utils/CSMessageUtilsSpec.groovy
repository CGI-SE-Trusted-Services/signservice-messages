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
package se.signatureservice.messages.utils

import se.signatureservice.messages.DummyMessageSecurityProvider
import se.signatureservice.messages.credmanagement.CredManagementPayloadParser
import se.signatureservice.messages.credmanagement.CredManagementPayloadParserSpec
import se.signatureservice.messages.credmanagement.jaxb.FetchHardTokenDataRequest
import se.signatureservice.messages.csmessages.CSMessageParser
import se.signatureservice.messages.csmessages.CSMessageParserManager
import se.signatureservice.messages.csmessages.PayloadParserRegistry
import se.signatureservice.messages.csmessages.jaxb.CSMessage
import se.signatureservice.messages.csmessages.jaxb.Credential
import se.signatureservice.messages.csmessages.jaxb.IsApprovedRequest
import spock.lang.Specification


class CSMessageUtilsSpec extends Specification {

	CSMessageParser csMessageParser
	String messageId = MessageGenerateUtils.generateRandomUUID()
	Properties props = new Properties()
	
	CSMessage isApprovedRequestMessage
	CSMessage getApprovedRequestMessage
	CSMessage fetchHardTokenDataRequestMessage
	
	static def config = """
csmessage.sourceid=SomeClientSystem
"""
	def setupSpec(){
		CertUtils.installBCProvider()
	}

	def setup(){
		props.load(new StringReader(config))
		csMessageParser = CSMessageParserManager.initCSMessageParser(new DummyMessageSecurityProvider(), props)
		
		CredManagementPayloadParser credParser = PayloadParserRegistry.getParser(CredManagementPayloadParser.NAMESPACE)
		Credential adminCredential = CredManagementPayloadParserSpec.createCredential()
		isApprovedRequestMessage = csMessageParser.parseMessage(csMessageParser.generateIsApprovedRequest(messageId, "someid", "someorg", "1234", null, null))
		fetchHardTokenDataRequestMessage = csMessageParser.parseMessage(credParser.genFetchHardTokenDataRequest(messageId, "someid", "someorg", "1234","CN=Some Value", adminCredential, null, null))
		byte[] request =credParser.genIsIssuerRequest(messageId, "someid", "someorg", "CN=SomeIssuer", null, null)
		getApprovedRequestMessage = csMessageParser.parseMessage(csMessageParser.generateGetApprovalRequest(messageId, "someid", "someorg", request, null, null))
	}
	
	def "Verify that getPayload returns the payload of a CS Message"(){
		expect:
		CSMessageUtils.getPayload(isApprovedRequestMessage) instanceof IsApprovedRequest
		CSMessageUtils.getPayload(fetchHardTokenDataRequestMessage) instanceof FetchHardTokenDataRequest

	}
	
	def "Verify that getPayload returns null if cs message parser parameter is null"(){
		expect:
		CSMessageUtils.getPayload(null) == null
	}
}
