package org.certificateservices.messages.csmessages.manager;

import java.util.Properties;

import org.certificateservices.messages.DummyMessageSecurityProvider;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.MessageSecurityProvider;
import org.certificateservices.messages.SimpleMessageSecurityProvider;


/**
 * Factory class in charge of creating and initializing a JMSMessageHandler from
 * a given configuration. And store it as a singleton
 *
 * @author Philip Vendil
 *
 */
public class MessageSecurityProviderManager {

    /**
     * Setting indicating which implementation of JMS Handler that
     * should be used. By default is the ActiveMQ Message Parser used.
     */
    public static final String SETTING_MESSAGESECURITYPROVIDER_IMPL = "messagesecurityprovider.impl";

    private static final String DEFAULT_IMPLEMENTATION = SimpleMessageSecurityProvider.class.getName();

    private static MessageSecurityProvider secProv = null;

    /**
     * Method to initialize the message security provider with a speicified message security provider
     *
     * @param messageSecurityProvider message security provider to initizialize the manager with.
     * @return a newly created MessageSecurityProvider
     * @throws MessageProcessingException if problems occurred creating a message handler.
     */
    public static MessageSecurityProvider initMessageSecurityProvider(MessageSecurityProvider messageSecurityProvider) throws MessageProcessingException{
        secProv = messageSecurityProvider;
        return secProv;
    }

    /**
     * Method to generate a new MessageSecurity configuration from the configuration, if setting "messagesecurityprovider.impl"
     * isn't set will the default message security provider (SimpleSecurityProvider) wihh be created.
     *
     * @param config the configuration context.
     * @return a newly created MessageSecurityProvider
     * @throws MessageProcessingException if problems occurred creating a message handler.
     */
    public static MessageSecurityProvider initMessageSecurityProvider(Properties config) throws MessageProcessingException{
        String cp = config.getProperty(SETTING_MESSAGESECURITYPROVIDER_IMPL, DEFAULT_IMPLEMENTATION).trim();
        try{
            if(cp.equalsIgnoreCase(SimpleMessageSecurityProvider.class.getName())){
                secProv =  new SimpleMessageSecurityProvider(config);
            }
            if(cp.equalsIgnoreCase(DummyMessageSecurityProvider.class.getName())){
                secProv = new DummyMessageSecurityProvider();
            }
            if(secProv == null){
                throw new MessageProcessingException("Error unsupported message security provider: " + cp);
            }
            return secProv;
        }catch(MessageProcessingException e){
            throw e;
        }catch(Exception e){
            throw new MessageProcessingException("Error creating JMS Message Handler: " + e.getMessage(),e);
        }
    }

    /**
     * @return true if this provider have been initialized.
     */
    public static boolean isInitialized(){
        return secProv != null;
    }

    /**
     * Method to fetch an initialized Message Security Provider.
     *
     * @return the MessageSecurityProvider singleton, initialized.
     * @throws MessageProcessingException if no initialized MessageSecurityProvider exists.
     */
    public static MessageSecurityProvider getMessageSecurityProvider() throws MessageProcessingException{
        if(secProv == null){
            throw new MessageProcessingException("Error Message Security Provider haven't been initialized, make sure initMessageSecurityProvider() is called before getMessageSecurityProvider");
        }
        return secProv;
    }

}
