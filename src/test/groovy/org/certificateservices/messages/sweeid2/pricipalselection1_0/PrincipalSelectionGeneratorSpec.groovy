package org.certificateservices.messages.sweeid2.pricipalselection1_0

import org.certificateservices.messages.sweeid2.pricipalselection1_0.jaxb.MatchValueType
import org.certificateservices.messages.sweeid2.pricipalselection1_0.jaxb.ObjectFactory
import org.certificateservices.messages.sweeid2.pricipalselection1_0.jaxb.PrincipalSelectionType
import org.certificateservices.messages.sweeid2.pricipalselection1_0.jaxb.RequestedPrincipalSelectionType
import spock.lang.Specification

import javax.xml.bind.JAXBElement

/**
 * Unit tests for PrincipalSelectionGenerator
 *
 * @author Philip Vendil 2020-10-22
 */
class PrincipalSelectionGeneratorSpec extends Specification {

    ObjectFactory objectFactory = new ObjectFactory()
    PrincipalSelectionGenerator principalSelectionGenerator = new PrincipalSelectionGenerator()

    MatchValueType mv1
    MatchValueType mv2

    def setup(){
        mv1 = objectFactory.createMatchValueType()
        mv1.name = "test1"
        mv1.value = "value1"
        mv2 = objectFactory.createMatchValueType()
        mv2.name = "test2"
        mv2.value = "value2"
    }

    def "Verify that genPrincipalSelectionElement generates expected JAXBElement"(){
        when:
        JAXBElement<PrincipalSelectionType> psc = principalSelectionGenerator.genPrincipalSelectionElement([mv1,mv2])
        then:
        psc.value.matchValue.size() == 2
        psc.value.matchValue[0].name == "test1"
        psc.value.matchValue[0].value == "value1"
        psc.value.matchValue[1].name == "test2"
        psc.value.matchValue[1].value == "value2"
    }

    def "Verify that genRequestedPrincipalSelectionType generates expected JAXBElement"(){
        when:
        JAXBElement<RequestedPrincipalSelectionType> psc = principalSelectionGenerator.genRequestedPrincipalSelectionElement([mv1, mv2])
        then:
        psc.value.matchValue.size() == 2
        psc.value.matchValue[0].name == "test1"
        psc.value.matchValue[0].value == "value1"
        psc.value.matchValue[1].name == "test2"
        psc.value.matchValue[1].value == "value2"
    }
}
