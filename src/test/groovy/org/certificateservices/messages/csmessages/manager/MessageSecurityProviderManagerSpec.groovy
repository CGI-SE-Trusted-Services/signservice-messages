package org.certificateservices.messages.csmessages.manager

import org.certificateservices.messages.DummyMessageSecurityProvider;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.SimpleMessageSecurityProvider;
import org.certificateservices.messages.csmessages.DefaultCSMessageParser;

import spock.lang.IgnoreRest;
import spock.lang.Specification
import spock.lang.Stepwise;


class MessageSecurityProviderManagerSpec extends Specification{

    Properties unsupportedConfig = new Properties()
    Properties dummyConfig = new Properties()

    Properties defaultsSimpleProviderConfig = new Properties()

    def setup(){
        unsupportedConfig.setProperty(MessageSecurityProviderManager.SETTING_MESSAGESECURITYPROVIDER_IMPL,"com.noexisting.NoExisting")

        dummyConfig.setProperty(MessageSecurityProviderManager.SETTING_MESSAGESECURITYPROVIDER_IMPL,DummyMessageSecurityProvider.class.getName())

        defaultsSimpleProviderConfig.setProperty(SimpleMessageSecurityProvider.SETTING_SIGNINGKEYSTORE_PATH, "src/test/resources/dummykeystore.jks")
        defaultsSimpleProviderConfig.setProperty(SimpleMessageSecurityProvider.SETTING_SIGNINGKEYSTORE_PASSWORD, "tGidBq0Eep")
        defaultsSimpleProviderConfig.setProperty(SimpleMessageSecurityProvider.SETTING_SIGNINGKEYSTORE_ALIAS, "test");
        defaultsSimpleProviderConfig.setProperty(SimpleMessageSecurityProvider.SETTING_TRUSTKEYSTORE_PATH, "src/test/resources/dummykeystore.jks");
        defaultsSimpleProviderConfig.setProperty(SimpleMessageSecurityProvider.SETTING_TRUSTKEYSTORE_PASSWORD, "tGidBq0Eep");

        MessageSecurityProviderManager.secProv = null
    }

    def "Verify that initMessageSecurityProvider returns a simple message provider by default."(){
        expect:
        MessageSecurityProviderManager.initMessageSecurityProvider(defaultsSimpleProviderConfig) instanceof SimpleMessageSecurityProvider
    }

    def "Verify that initMessageSecurityProvider sets the given message security provider as default."(){
        expect:
        MessageSecurityProviderManager.initMessageSecurityProvider(new DummyMessageSecurityProvider()) instanceof DummyMessageSecurityProvider
    }

    def "Verify that initMessageSecurityProvider throws MessageProcessingException if simple secrity provider is incomplete"(){
        setup:
        defaultsSimpleProviderConfig.remove(SimpleMessageSecurityProvider.SETTING_SIGNINGKEYSTORE_PATH)
        when:
        MessageSecurityProviderManager.initMessageSecurityProvider(defaultsSimpleProviderConfig) instanceof SimpleMessageSecurityProvider
        then:
        thrown MessageProcessingException
    }

    def "Verify that initMessageSecurityProvider creates a DummyMessageProvider if given implementation is set"(){
        expect:
        MessageSecurityProviderManager.initMessageSecurityProvider(dummyConfig) instanceof DummyMessageSecurityProvider
    }

    def "Verify that initMessageSecurityProvider throws MessageProcesingException if no supported MessageSecurityProvider could be found."(){
        when:
        MessageSecurityProviderManager.initMessageSecurityProvider(unsupportedConfig)
        then:
        thrown MessageProcessingException
    }


    def "Verify that uninitialized MessageSecurityProviderManager isInitialized() returns false and initialized returns true"(){
        when:
        MessageSecurityProviderManager.secProv = null
        then:
        MessageSecurityProviderManager.isInitialized() == false
        when:
        MessageSecurityProviderManager.initMessageSecurityProvider(defaultsSimpleProviderConfig)
        then:
        MessageSecurityProviderManager.isInitialized()
    }

    def "Verify that getMessageSecurityProvider() returns the initiated MessageSecurityProvider or throws MessageProcessingException"(){
        when:
        MessageSecurityProviderManager.secProv = null
        MessageSecurityProviderManager.getMessageSecurityProvider()
        then:
        thrown MessageProcessingException

        when:
        MessageSecurityProviderManager.initMessageSecurityProvider(defaultsSimpleProviderConfig)
        then:
        MessageSecurityProviderManager.getMessageSecurityProvider() instanceof SimpleMessageSecurityProvider
    }
}