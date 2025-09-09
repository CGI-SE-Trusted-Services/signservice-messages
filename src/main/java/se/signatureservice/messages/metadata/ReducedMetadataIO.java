package se.signatureservice.messages.metadata;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import se.signatureservice.messages.ContextMessageSecurityProvider;
import se.signatureservice.messages.MessageContentException;
import se.signatureservice.messages.MessageProcessingException;
import se.signatureservice.messages.saml2.metadata.jaxb.EntitiesDescriptorType;
import se.signatureservice.messages.saml2.metadata.jaxb.EntityDescriptorType;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.LinkedList;
import java.util.List;

/**
 * Utility methods to parse bytes into ReducedMetadata, and output to json
 *
 * Created by fredrik 2025-08-28.
 */
public class ReducedMetadataIO {
    final static ObjectMapper objectMapper;
    final static MetadataMessageParserManager metadataMessageParserManager;
    static {
        objectMapper = JsonMapper.builder()
                .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
                .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
                .build();

        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        metadataMessageParserManager = new MetadataMessageParserManager();
    }

    /**
     * Method to serialize the ReducedMetadata object to json, using strict ordering of keys
     *
     * @param ReducedMetadata metadata
     * @return String
     */
    static String asJson(ReducedMetadata metadata) throws JsonProcessingException {
        return objectMapper.writeValueAsString(metadata);
    }

    /**
     * Method to parse file contents into a list of ReducedMetadata, when parsing an EntityDescriptor
     * it will be a list of one
     *
     * @param file with EntityDescriptor, or EntitiesDescriptor, content
     * @param verifySignature
     * @return List<ReducedMetadata>
     */
    public static List<ReducedMetadata> fromFile(File file, boolean verifySignature) throws MessageProcessingException, IOException, MessageContentException {
        var bytes = Files.readAllBytes(file.toPath());
        return fromBytes(bytes, verifySignature);
    }

    /**
     * Method to parse byte[] contents into a list of ReducedMetadata, when parsing an EntityDescriptor
     * it will be a list of one
     *
     * @param file with EntityDescriptor, or EntitiesDescriptor, content
     * @param verifySignature
     * @return List<ReducedMetadata>
     */
    public static List<ReducedMetadata> fromBytes(byte[] bytes, boolean verifySignature) throws MessageProcessingException, MessageContentException {
        Object o = metadataMessageParserManager.getSAMLMetaDataMessageParser().parseMessage(
                new ContextMessageSecurityProvider.Context(MetadataConstants.CONTEXT_USAGE_METADATA_SIGN),
                bytes, verifySignature
        );
        var list = new LinkedList<ReducedMetadata>();
        collectMetadata(o, list);
        return list;
    }

    private static void collectMetadata(Object metaData, List<ReducedMetadata> list) {
        if (metaData instanceof EntityDescriptorType) {
            list.add(new ReducedMetadataImpl(((EntityDescriptorType) metaData)));
        } else {
            if (metaData instanceof EntitiesDescriptorType) {
                for (Object edt : ((EntitiesDescriptorType) metaData).getEntityDescriptorOrEntitiesDescriptor()) {
                    collectMetadata(edt, list);
                }
            }
        }
    }
}
