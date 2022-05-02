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
package org.certificateservices.messages.utils

import org.apache.xml.security.Init
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.certificateservices.messages.DummyMessageSecurityProvider
import org.certificateservices.messages.csmessages.CSMessageParserManager
import org.certificateservices.messages.csmessages.DefaultCSMessageParser
import org.certificateservices.messages.csmessages.jaxb.CSMessage
import org.certificateservices.messages.csmessages.jaxb.Credential
import org.ietf.jgss.GSSCredential
import org.ietf.jgss.GSSName
import spock.lang.Specification

import java.security.Security

import static org.certificateservices.messages.TestUtils.*

class KerberosUtilsSpec extends Specification{


	DefaultCSMessageParser mp = new DefaultCSMessageParser()
	DummyMessageSecurityProvider secprov = new DummyMessageSecurityProvider();

	def TimeZone currentTimeZone;
	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Init.init()
	}

	def setup() {
		currentTimeZone = TimeZone.getDefault()
		TimeZone.setDefault(TimeZone.getTimeZone("Europe/Stockholm"))

		Properties requestConfig = new Properties()
		requestConfig.setProperty(DefaultCSMessageParser.SETTING_SOURCEID, "SOMEREQUESTER")
		mp = CSMessageParserManager.initCSMessageParser(secprov, requestConfig)

		KerberosUtils.systemTime = Mock(SystemTime)
		KerberosUtils.systemTime.getSystemTime() >> new Date(1436279211000)
		KerberosUtils.systemTime.getSystemTimeMS() >> 1436279211000L
	}

	def cleanup(){
		TimeZone.setDefault(currentTimeZone);
	}

	def "Verify that generateKerberosOriginator generates kerberous XML that contains valid XML"(){
		setup:
		def gssCredMock = Mock(GSSCredential)
		gssCredMock.getName() >> {
			def nameMock = Mock(GSSName)
			nameMock.toString() >> "SomeGSSName"
			return nameMock
		}
		gssCredMock.getRemainingLifetime() >> 3600

		when:
		Credential originator = KerberosUtils.generateKerberosOriginator("KERBEROSTYPE", "KERBEROSSUBTYPE", "SomeIssuerId",
				gssCredMock,
				100, "SomeUserUniqueId", "SomeUserDisplayName")
		// Verify that the Originator can be written in XML
		byte[] req = mp.generateIsApprovedRequest(MessageGenerateUtils.generateRandomUUID(),"SomeDestination", "SomeOrganisation", "SomeApprovalId", originator, null);
		//printXML(req)
		def xml = slurpXml(req)
		def c = xml.originator.credential
		then:
		c.uniqueId == "kb:SomeUserUniqueId"
		c.displayName == "SomeGSSName"
		c.issuerId == "SomeIssuerId"
		c.status == 100
		c.credentialType == "KERBEROSTYPE"
		c.credentialSubType == "KERBEROSSUBTYPE"
		c.attributes.attribute.size() == 2
		c.attributes.attribute[0].key == "USER_UNIQUEID"
		c.attributes.attribute[0].value == "SomeUserUniqueId"
		c.attributes.attribute[1].key == "USER_USERDISPLAYNAME"
		c.attributes.attribute[1].value == "SomeUserDisplayName"
		c.issueDate == "2015-07-07T16:26:51.000+02:00"
		c.expireDate == "2015-07-07T17:26:51.000+02:00"
		c.validFromDate == "2015-07-07T16:26:51.000+02:00"

		// Then parse to check schema validation
		when:
		CSMessage m = mp.parseMessage(req)
		then:
		m.originator.credential.credentialData == new byte[0]

	}

	def "Verify that generateKerberosOriginator without GSS Credential generates kerberous XML that contains valid XML"(){
		when:
		Credential originator = KerberosUtils.generateKerberosOriginator("kerberostype", "kerberossubtype", "SomeIssuerId",
				36000000,
				100, "SomeUserUniqueId", "SomeUserDisplayName")
		// Verify that the Originator can be written in XML
		byte[] req = mp.generateIsApprovedRequest(MessageGenerateUtils.generateRandomUUID(),"SomeDestination", "SomeOrganisation", "SomeApprovalId", originator, null);
		//printXML(req)
		def xml = slurpXml(req)
		def c = xml.originator.credential
		then:
		c.uniqueId == "kb:SomeUserUniqueId"
		c.displayName== "SomeUserDisplayName"
		c.issuerId == "SomeIssuerId"
		c.status == 100
		c.credentialType == "kerberostype"
		c.credentialSubType == "kerberossubtype"
		c.attributes.attribute.size() == 2
		c.attributes.attribute[0].key == "USER_UNIQUEID"
		c.attributes.attribute[0].value == "SomeUserUniqueId"
		c.attributes.attribute[1].key == "USER_USERDISPLAYNAME"
		c.attributes.attribute[1].value == "SomeUserDisplayName"
		c.issueDate == "2015-07-07T16:26:51.000+02:00"
		c.expireDate == "2015-07-08T02:26:51.000+02:00"
		c.validFromDate == "2015-07-07T16:26:51.000+02:00"

		// Then parse to check schema validation
		when:
		CSMessage m = mp.parseMessage(req)
		then:
		m.originator.credential.credentialData == new byte[0]
	}

}
