package org.certificateservices.messages.csexport.data

import org.apache.xml.security.Init
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.certificateservices.messages.DummyMessageSecurityProvider
import org.certificateservices.messages.MessageContentException
import org.certificateservices.messages.csexport.data.CSExportDataParser
import org.certificateservices.messages.csexport.data.jaxb.CSExport
import org.certificateservices.messages.csexport.data.jaxb.Department
import org.certificateservices.messages.csexport.data.jaxb.FieldConstraint
import org.certificateservices.messages.csexport.data.jaxb.ObjectFactory
import org.certificateservices.messages.csexport.data.jaxb.Organisation
import org.certificateservices.messages.csexport.data.jaxb.TokenType
import org.certificateservices.messages.utils.MessageGenerateUtils
import spock.lang.Specification

import javax.xml.bind.JAXBContext
import javax.xml.bind.Marshaller
import javax.xml.bind.Unmarshaller
import javax.xml.validation.Schema
import java.security.Security

import static org.certificateservices.messages.TestUtils.*

class CSExportDataParserSpec extends Specification {
	
	CSExportDataParser p;
	static ObjectFactory of = new ObjectFactory()

	
	def setupSpec(){
		Security.addProvider(new BouncyCastleProvider())
		Init.init();
	}
	
	def setup(){
		DummyMessageSecurityProvider secprov = new DummyMessageSecurityProvider();
		p = new CSExportDataParser(secprov, true)
	}

	def "Verify that constructor sets all fields"(){
		expect:
		p.xmlSigner != null
		p.requireSignature
	}


	def "Verify that parse method validates against schema"(){
		setup:
		def exp = of.createCSExport()
		exp.setID(MessageGenerateUtils.generateRandomUUID())
		byte[] data = p.marshallAndSign(exp)
		when:
		p.parse(data)
		then:
		thrown MessageContentException
		
	}	
	
	def "Verify that marshall and parse generates and parser valid XML"(){
		setup:
		def org = genOrganisation()
		def tt = genTokenType()
		when:
		byte[] data = p.genCSExport_1_x("1.0",[org],[tt])
		String message = new String(data, "UTF-8")
		//printXML(message)
		def xml = slurpXml(message)
		then:
        message =~ 'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"'
        message =~ 'xmlns:csexd="http://certificateservices.org/xsd/csexport_data_1_0"'
		
		xml.@version == CSExportDataParser.VERSION_1_0
		def o = xml.organisations.organisation[0]
		o.shortName == "testorg1"
		o.displayName == "Test Org"
		o.matchAdminWith == "SomeMatch"
		o.issuerDistinguishedName == "CN=IssuerDistingueshedName"

		def t = xml.tokenTypes.tokenType[0]
		t.name == "tokentype1"
		t.displayName == "Token Type 1"

		when:
		CSExport exp = p.parse(data)
		
		then:
		exp != null

		when: "Verify that empty lists works as well"
		CSExport emptyListExp = p.parse(p.genCSExport_1_x("1.0",[],[]))
		then:
		emptyListExp.getOrganisations() == null
		emptyListExp.getTokenTypes() == null

		when: "Verify that  null lists works as well"
		CSExport nullListExp = p.parse(p.genCSExport_1_x("1.0",null,null))
		then:
		nullListExp.getOrganisations() == null
		nullListExp.getTokenTypes() == null

		when: "Verify that 1.1 generation is supported"
		def ttWithConditional = genTokenType("1.1")
		data = p.genCSExport_1_x("1.1",[org],[ttWithConditional])
		message = new String(data, "UTF-8")
		//printXML(message)
		xml = slurpXml(message)
		then:
		message =~ 'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"'
		message =~ 'xmlns:csexd="http://certificateservices.org/xsd/csexport_data_1_0"'

		xml.@version == CSExportDataParser.VERSION_1_1
		def o2 = xml.organisations.organisation[0]
		o2.shortName == "testorg1"

		def t2 = xml.tokenTypes.tokenType[0]
		t2.name == "tokentype1"
		t2.fieldConstraints.fieldConstraint[0].relatedField == "SomeRelatedField"
	}

	def "Verify that genCSExport_1_0AsObject generates a valid JAXB element with signature and i marshallable to byte[]"(){
		setup:
		def org = genOrganisation()
		def tt = genTokenType()
		when:
		CSExport csExport = p.genCSExport_1_xAsObject("1.0",[org],[tt])
		then:
		csExport.organisations.organisation.size() == 1
		csExport.tokenTypes.tokenType.size() == 1
		csExport.signature.keyInfo.content.size() == 1

		when:
		byte[] data = p.marshallCSExportData(csExport)
		String message = new String(data,"UTF-8")
		//printXML(message)
		def xml = slurpXml(message)
		then:
		message =~ 'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"'
		message =~ 'xmlns:csexd="http://certificateservices.org/xsd/csexport_data_1_0"'

		xml.@version == CSExportDataParser.VERSION_1_0
		def o = xml.organisations.organisation[0]
		o.shortName == "testorg1"
		o.displayName == "Test Org"
		o.matchAdminWith == "SomeMatch"
		o.issuerDistinguishedName == "CN=IssuerDistingueshedName"

		def t = xml.tokenTypes.tokenType[0]
		t.name == "tokentype1"
		t.displayName == "Token Type 1"

	}

	def "Verify that parser verifies signatures if required"(){
		setup:
		byte[] data = p.genCSExport_1_x("1.0",[genOrganisation()],[genTokenType()])
		String msg = new String(data,"UTF-8")
		boolean expectionThrown = false
		when:
		msg = msg.replace("<csexd:shortName>testorg1</csexd:shortName>","<csexd:shortName>testorg2</csexd:shortName>")

		def exp = p.parse(msg.getBytes("UTF-8"))
		then:
		thrown MessageContentException

		when:
		p.requireSignature = false
		then:
		p.parse(msg.getBytes("UTF-8")) != null
	}

	def "Verify that trying to parse a 1.1 xml using version 1.0 parser generates error"(){
		setup: // Generate 1.1 data with 1.0 version tag
		def org = genOrganisation()
		def tt = genTokenType("1.1")
		byte[] data = p.genCSExport_1_x("1.0",[org],[tt])

		when:
		p.parse(data)
		then:
		thrown MessageContentException

	}

	def "Verify that trying to parse a 1.3 xml using version 1.2 parser generates error"(){
		setup: // Generate 1.1 data with 1.0 version tag
		def org = genOrganisation("1.3")
		def tt = genTokenType("1.1")
		byte[] data = p.genCSExport_1_x("1.2",[org],[tt])

		when:
		p.parse(data)
		then:
		thrown MessageContentException

	}



	def "Verify that from 1.4 is capital letters in organisation shortname and spaces in field contraints allowed."(){
		setup:
		p = new CSExportDataParser(new DummyMessageSecurityProvider(), false)
		when:
		def o = p.parse(test)
		then:
		o  != null
	}

	def "Verify that JAXBContext is cached"(){
		setup:
		p = new CSExportDataParser(new DummyMessageSecurityProvider(), false)
		when:
		JAXBContext context1 = p.getJAXBContext()
		JAXBContext context2 = p.getJAXBContext()
		then:
		context1 == context2
	}

	def "Verify that Schema is cached"(){
		setup:
		p = new CSExportDataParser(new DummyMessageSecurityProvider(), false)
		when:
		Schema schema1 = p.getSchema("1.3")
		Schema schema2 = p.getSchema("1.3")
		then:
		schema1 == schema2
	}

	def "Verify that marshaller is not cached"(){
		setup:
		p = new CSExportDataParser(new DummyMessageSecurityProvider(), false)
		when:
		Marshaller marshaller1 = p.getMarshaller()
		Marshaller marshaller2 = p.getMarshaller()
		then:
		marshaller1 != marshaller2
	}

	def "Verify that unmarshaller is not cached"(){
		setup:
		p = new CSExportDataParser(new DummyMessageSecurityProvider(), false)
		when:
		Unmarshaller unmarshaller1 = p.getUnmarshaller("1.3")
		Unmarshaller unmarshaller2 = p.getUnmarshaller("1.3")
		then:
		unmarshaller1 != unmarshaller2
	}

	public static Organisation genOrganisation(String version="1.1"){
		Organisation o = of.createOrganisation()
		o.setShortName("testorg1")
		o.setDisplayName("Test Org")
		o.setMatchAdminWith("SomeMatch")
		o.setIssuerDistinguishedName("CN=IssuerDistingueshedName")
		o.setDepartments(of.createOrganisationDepartments())
		o.getDepartments().department.add(genDepartment(version))

		return o
	}

	public static Department genDepartment(String version="1.1"){
		Department d = of.createDepartment()
		d.name = "Name"
		d.description = "SomeDescription"
		if(version == "1.3"){
			d.setDomainNameRestrictions(of.createDepartmentDomainNameRestrictions())
			d.domainNameRestrictions.restriction << of.createDomainNameRestriction()
			d.domainNameRestrictions.restriction[0].domainNameValue = "test.org"
			d.domainNameRestrictions.restriction[0].allowSubDomains = false
			d.domainNameRestrictions.restriction[0].allowWildCard = true
			d.domainNameRestrictions.restriction[0].customRegexp = "abc"
		}
		return d
	}

	public static TokenType genTokenType(String version = "1.0"){
		TokenType tt = of.createTokenType()

		tt.setName("tokentype1")
		tt.setDisplayName("Token Type 1")

		if(version == "1.1"){
			FieldConstraint fc = of.createFieldConstraint()
			fc.relatedField = "SomeRelatedField"

			tt.fieldConstraints = new TokenType.FieldConstraints()
			tt.fieldConstraints.fieldConstraint.add(fc)
		}

		return tt
	}

	def test = """<csexd:CSExport xmlns:csexd="http://certificateservices.org/xsd/csexport_data_1_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="EDD2406B-B5A0-425F-b952-D8677DEA2446" timeStamp="2018-11-05T15:55:16.536+01:00" version="1.4"><csexd:organisations><csexd:organisation><csexd:shortName>CAPITAL</csexd:shortName><csexd:displayName>CAPITAL LETTERS</csexd:displayName><csexd:obfuscatedName>d9a38658</csexd:obfuscatedName><csexd:description></csexd:description><csexd:matchAdminWith>CERTSERIALNUMBER</csexd:matchAdminWith><csexd:issuerDistinguishedName>CN=Logica SE IM Certificate Service AT eIDCA,O=Logica SE IM Certificate Service AT</csexd:issuerDistinguishedName><csexd:useDepartments>true</csexd:useDepartments><csexd:departments><csexd:department><csexd:name>DEP</csexd:name><csexd:description>attest</csexd:description></csexd:department><csexd:department><csexd:name>DBS - ITSS - SECURITY</csexd:name><csexd:description>attest</csexd:description></csexd:department><csexd:department><csexd:name>DBSITSS SECURITY</csexd:name><csexd:description></csexd:description></csexd:department><csexd:department><csexd:name>DBS - ITSS - GA</csexd:name><csexd:description>attest</csexd:description></csexd:department><csexd:department><csexd:name>DBS - ITSS - GEMS</csexd:name><csexd:description>attest</csexd:description></csexd:department></csexd:departments></csexd:organisation></csexd:organisations><csexd:tokenTypes><csexd:tokenType><csexd:name>simplessl</csexd:name><csexd:displayName>Simple SSL</csexd:displayName><csexd:description></csexd:description><csexd:uniqueIdPrefix>SERVER_</csexd:uniqueIdPrefix><csexd:fieldUsedAsUserUniqueId>hostname</csexd:fieldUsedAsUserUniqueId><csexd:fieldUsedAsUserDisplayName>hostname</csexd:fieldUsedAsUserDisplayName><csexd:isMonitoredByDefault>false</csexd:isMonitoredByDefault><csexd:useDepartments>false</csexd:useDepartments><csexd:useExpireDateField>false</csexd:useExpireDateField><csexd:useValidFromDateField>false</csexd:useValidFromDateField><csexd:editableFields>false</csexd:editableFields><csexd:isSuspendable>false</csexd:isSuspendable><csexd:fieldConstraints><csexd:fieldConstraint><csexd:key>hostname with space</csexd:key><csexd:displayName>hostname</csexd:displayName><csexd:description></csexd:description><csexd:type>TEXT</csexd:type><csexd:required>true</csexd:required><csexd:minLength>0</csexd:minLength><csexd:maxLength>255</csexd:maxLength><csexd:minNumberOfFields>1</csexd:minNumberOfFields><csexd:maxNumberOfFields>1</csexd:maxNumberOfFields><csexd:customRegexp></csexd:customRegexp><csexd:isCustomTextResourceKey>false</csexd:isCustomTextResourceKey><csexd:relatedTokenAttributes><csexd:relatedTokenAttribute><csexd:key>x509dn_cn</csexd:key><csexd:displayName></csexd:displayName></csexd:relatedTokenAttribute><csexd:relatedTokenAttribute><csexd:key>x509altname_dnsname</csexd:key><csexd:displayName></csexd:displayName></csexd:relatedTokenAttribute></csexd:relatedTokenAttributes><csexd:allowOnlyTrustedData>false</csexd:allowOnlyTrustedData></csexd:fieldConstraint></csexd:fieldConstraints><csexd:credentialConstraints><csexd:credentialConstraint><csexd:credentialType>x509certificate</csexd:credentialType><csexd:credentialSubType>simplessl</csexd:credentialSubType><csexd:subTypeDisplayName>Simple SSL</csexd:subTypeDisplayName></csexd:credentialConstraint></csexd:credentialConstraints><csexd:keySpecConstraints><csexd:keySpecConstraint>rsa2048</csexd:keySpecConstraint></csexd:keySpecConstraints><csexd:tokenContainerConstraints><csexd:tokenContainerConstraint>softtoken</csexd:tokenContainerConstraint><csexd:tokenContainerConstraint>usergenerated</csexd:tokenContainerConstraint></csexd:tokenContainerConstraints><csexd:certificateChainOption>CLIENT_CERT_ONLY</csexd:certificateChainOption><csexd:keystoreTypes><csexd:keystoreType><csexd:type>PEM</csexd:type><csexd:resourceKey>keystore.type.pem</csexd:resourceKey><csexd:contentType>application/pkix-cert</csexd:contentType><csexd:fileNameSuffix>pem</csexd:fileNameSuffix></csexd:keystoreType></csexd:keystoreTypes></csexd:tokenType></csexd:tokenTypes></csexd:CSExport>""".getBytes("UTF-8")
}
