package se.signatureservice.messages.metadata;

import se.signatureservice.messages.MessageProcessingException;
import se.signatureservice.messages.MessageSecurityProvider;
import se.signatureservice.messages.csmessages.manager.MessageSecurityProviderManager;
import se.signatureservice.messages.saml2.metadata.SAMLMetaDataMessageParser;

import java.util.concurrent.ConcurrentHashMap;


/**
 * To keep a pool of SAMLMetaDataMessageParser
 *
 * @author Fredrik 2025-09-04
 */
class MetadataMessageParserManager {
    private final ConcurrentHashMap<Long, SAMLMetaDataMessageParser> samlMetaDataMessageParserMap = new ConcurrentHashMap<>();

    /**
     *
     * @return an initialised SAMLMetaDataMessageParser singleton.
     */
    SAMLMetaDataMessageParser getSAMLMetaDataMessageParser() throws MessageProcessingException {
        Long threadId = Thread.currentThread().getId();

        if(!samlMetaDataMessageParserMap.containsKey(threadId)){
            MessageSecurityProvider securityProvider = MessageSecurityProviderManager.getMessageSecurityProvider();
            SAMLMetaDataMessageParser messageParser = new SAMLMetaDataMessageParser();
            messageParser.init(securityProvider, null);
            samlMetaDataMessageParserMap.putIfAbsent(threadId, messageParser);
        }

        return samlMetaDataMessageParserMap.get(threadId);
    }
}
