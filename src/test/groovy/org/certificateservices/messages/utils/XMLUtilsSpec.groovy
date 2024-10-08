package org.certificateservices.messages.utils

import org.w3c.dom.Document
import org.xml.sax.SAXParseException
import spock.lang.Specification

import javax.xml.parsers.DocumentBuilder

class XMLUtilsSpec extends Specification{

    def "Verify that createDocumentBuilderFactory creates a factory that prevents XXE"(){
        setup:
        String maliciousXML= "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/shadow'>]><root>&test;</root>"
        DocumentBuilder documentBuilder = XMLUtils.createSecureDocumentBuilderFactory().newDocumentBuilder()

        when:
        Document document = documentBuilder.parse(new ByteArrayInputStream(maliciousXML.bytes))

        then:
        def e = thrown(SAXParseException)
        e.message.contains("http://apache.org/xml/features/disallow-doctype-decl")
    }
}
