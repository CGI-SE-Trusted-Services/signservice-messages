package se.signatureservice.messages

import spock.lang.Specification

/**
 * Unit tests for SpamProtectionException
 */
class SpamProtectionExceptionSpec extends Specification {

    def "Verify default constructor"(){
        when:
        def e = new SpamProtectionException("testmessage")
        then:
        e.message == "testmessage"
    }

}
