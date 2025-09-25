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
import se.signatureservice.messages.MessageSecurityProvider;
import se.signatureservice.messages.csmessages.manager.MessageSecurityProviderManager;
import se.signatureservice.messages.saml2.metadata.SAMLMetaDataMessageParser;
import se.signatureservice.messages.saml2.metadata.jaxb.EntitiesDescriptorType;
import se.signatureservice.messages.saml2.metadata.jaxb.EntityDescriptorType;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.LinkedList;
import java.util.List;

/**
 * Utility methods to parse bytes into ReducedMetadata, and output to json
 * <p>
 * Created by fredrik 2025-08-28.
 */
public class ReducedMetadataIO {
    final static ObjectMapper objectMapper;
    final static SAMLMetaDataMessageParser samlMetaDataMessageParser;

    static {
        objectMapper = JsonMapper.builder()
                .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
                .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
                .build();
        objectMapper.setDefaultPropertyInclusion(JsonInclude.Include.NON_NULL);

        MessageSecurityProvider securityProvider;
        try {
            securityProvider = MessageSecurityProviderManager.getMessageSecurityProvider();
            samlMetaDataMessageParser = new SAMLMetaDataMessageParser();
            samlMetaDataMessageParser.init(securityProvider, null);
        } catch (MessageProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Serialize a {@link ReducedMetadata} object to JSON, using strict ordering of keys.
     *
     * @param metadata the metadata object to serialize
     * @return the JSON representation of the metadata
     * @throws JsonProcessingException if the object cannot be serialized
     */
    static String asJson(ReducedMetadata metadata) throws JsonProcessingException {
        return objectMapper.writeValueAsString(metadata);
    }

    /**
     * Read a {@link ReducedMetadata} instance from a JSON file.
     *
     * @param file the file containing JSON metadata
     * @return the deserialized {@link ReducedMetadata} object
     * @throws IOException if the file cannot be read or parsed
     */
    public static ReducedMetadata fromJson(File file) throws IOException {
        return fromJson(Files.readAllBytes(file.toPath()));
    }

    /**
     * Read a {@link ReducedMetadata} instance from a JSON byte array.
     *
     * @param json the JSON data as bytes
     * @return the deserialized {@link ReducedMetadata} object
     * @throws IOException if the data cannot be parsed
     */
    public static ReducedMetadata fromJson(byte[] json) throws IOException {
        return objectMapper.readValue(json, ReducedMetadataImpl.class);
    }

    /**
     * Parse a metadata file into a list of {@link ReducedMetadata}.
     * <p>
     * Supports both {@link EntityDescriptorType} (resulting in a list of one entry)
     * and {@link EntitiesDescriptorType} (resulting in multiple entries).
     * <p>
     * The XML signature will <strong>not</strong> be verified.
     *
     * @param file the metadata file containing an EntityDescriptor or EntitiesDescriptor
     * @return a list of parsed and reduced metadata entries
     * @throws IOException                if the file cannot be read
     * @throws MessageContentException    if the metadata content cannot be parsed
     * @throws MessageProcessingException if an error occurs during parsing
     */
    public static List<ReducedMetadata> fromFile(File file) throws MessageProcessingException, IOException, MessageContentException {
        return fromFile(file, false);
    }

    /**
     * Parse a metadata file into a list of {@link ReducedMetadata}.
     * <p>
     * Supports both {@link EntityDescriptorType} (resulting in a list of one entry)
     * and {@link EntitiesDescriptorType} (resulting in multiple entries).
     *
     * @param file            the metadata file containing an EntityDescriptor or EntitiesDescriptor
     * @param verifySignature whether to verify the XML signature in the metadata
     * @return a list of parsed and reduced metadata entries
     * @throws IOException                if the file cannot be read
     * @throws MessageContentException    if the metadata content cannot be parsed
     * @throws MessageProcessingException if an error occurs during parsing
     */
    public static List<ReducedMetadata> fromFile(File file, boolean verifySignature) throws MessageProcessingException, IOException, MessageContentException {
        var bytes = Files.readAllBytes(file.toPath());
        return fromBytes(bytes, verifySignature);
    }

    /**
     * Parse raw metadata bytes into a list of {@link ReducedMetadata} objects.
     * <p>
     * This method handles both single {@link EntityDescriptorType} objects
     * and nested {@link EntitiesDescriptorType} structures recursively.
     * <p>
     * Synchronized because {@link SAMLMetaDataMessageParser} is not guaranteed to be thread-safe.
     *
     * @param bytes           the raw metadata content
     * @param verifySignature whether to verify the XML signature in the metadata
     * @return a list of parsed and reduced metadata entries
     * @throws MessageContentException    if the metadata cannot be parsed
     * @throws MessageProcessingException if an error occurs while parsing
     */
    public static List<ReducedMetadata> fromBytes(byte[] bytes, boolean verifySignature) throws MessageProcessingException, MessageContentException {
        Object o = samlMetaDataMessageParser.parseMessage(
                new ContextMessageSecurityProvider.Context(MetadataConstants.CONTEXT_USAGE_METADATA_SIGN),
                bytes, verifySignature
        );
        var list = new LinkedList<ReducedMetadata>();
        collectMetadata(o, list);
        return list;
    }

    /**
     * Recursively collect {@link ReducedMetadata} objects from metadata structures.
     * <p>
     * Supports both single {@link EntityDescriptorType} and aggregated
     * {@link EntitiesDescriptorType}.
     *
     * @param metaData the metadata object to collect from
     * @param list     the target list of reduced metadata entries
     */
    private static void collectMetadata(Object metaData, List<ReducedMetadata> list) {
        if (metaData instanceof EntityDescriptorType) {
            list.add(new ReducedMetadataImpl(((EntityDescriptorType) metaData)));
        } else if (metaData instanceof EntitiesDescriptorType) {
            for (Object edt : ((EntitiesDescriptorType) metaData).getEntityDescriptorOrEntitiesDescriptor()) {
                collectMetadata(edt, list);
            }
        }
    }
}
