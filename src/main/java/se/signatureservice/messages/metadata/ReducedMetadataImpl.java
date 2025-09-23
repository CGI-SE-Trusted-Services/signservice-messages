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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.signatureservice.messages.ContextMessageSecurityProvider;
import se.signatureservice.messages.MessageContentException;
import se.signatureservice.messages.MessageProcessingException;
import se.signatureservice.messages.saml2.metadata.jaxb.EntityDescriptorType;
import se.signatureservice.messages.saml2.metadata.jaxb.SPSSODescriptorType;
import se.signatureservice.messages.saml2.metadata.jaxb.IDPSSODescriptorType;
import se.signatureservice.messages.utils.CertUtils;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

import static se.signatureservice.messages.metadata.ReducedMetadataUtils.isTruthyList;
import static se.signatureservice.messages.metadata.ReducedMetadataUtils.isTruthyString;

/**
 * Represents data extracted from a saml metadata EntityDescriptor
 *
 * Created by fredrik 2025-08-28.
 */
public class ReducedMetadataImpl implements ReducedMetadata {
    static Logger msgLog = LoggerFactory.getLogger(ReducedMetadataImpl.class);
    public static final ObjectMapper objectMapper;
    static {
        objectMapper = JsonMapper.builder()
                .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
                .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
                .build();

        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    @JsonIgnore
    String json;
    @Override
    public String asJson() throws JsonProcessingException {
        if(json == null) {
            json = objectMapper.writeValueAsString(this);
        }
        return json;
    }

    String entityID;
    @Override
    public String getEntityID() {
        return entityID;
    }

    // an entity is initially loaded from a file
    String fileName;
    public String getFileName() {
        return fileName;
    }

    // from EntityAttributes under entityDescriptor.extensions
    private Map<String, List<String>> entityAttributes;
    public Map<String, List<String>> getEntityAttributes() {
        return entityAttributes;
    }

    // from SingleSignOnService elements of the first IDPSSODescriptor encountered
    private List<SingleSignOnService> singleSignOnServices;
    public List<SingleSignOnService> getSingleSignOnServices() {
        return singleSignOnServices;
    }


    // from attributeConsumingServices of each encountered SPSSODescriptor
    private List<AttributeConsumingService> attributeConsumingServices;
    public List<AttributeConsumingService> getAttributeConsumingServices() {
        return attributeConsumingServices;
    }

    // from the first extensions.RequestedPrincipalSelection, of the first IDPSSODescriptor
    private List<String> requestedPrincipalSelection;
    public List<String> getRequestedPrincipalSelection() {
        return requestedPrincipalSelection;
    }

    // roleDescriptors, with any extension.uiInfo found
    // certs are only read for the first idp, and first sp
    private List<RoleDescriptor> roleDescriptors;
    public List<RoleDescriptor> getRoleDescriptors() {
        return roleDescriptors;
    }

    // from the organisation element of the entityDescriptor
    private Organisation organisation;
    public Organisation getOrganisation() {
        return organisation;
    }

    public ReducedMetadataImpl() {
        roleDescriptors = new ArrayList<>();
    }

    public ReducedMetadataImpl(EntityDescriptorType entityDescriptor, String fileName) {
        this.entityID = entityDescriptor.getEntityID();
        this.entityAttributes = ReducedMetadataUtils.getEntityAttributes(entityDescriptor);
        this.singleSignOnServices = ReducedMetadataUtils.getSingleSignOnServices(entityDescriptor);
        this.attributeConsumingServices = ReducedMetadataUtils.getAttributeConsumingServices(entityDescriptor);
        this.requestedPrincipalSelection = ReducedMetadataUtils.getRequestedPrincipalSelection(entityDescriptor);
        this.roleDescriptors = ReducedMetadataUtils.getRoleDescriptors(entityDescriptor);
        this.organisation = ReducedMetadataUtils.getOrganisation(entityDescriptor);
        this.fileName = fileName;
    }

    @Override
    public List<AttributeConsumingService> getAttributeConsumingServices(String serviceName) {
        return attributeConsumingServices.stream().filter( it -> it.names.contains(serviceName)).collect(Collectors.toList());
    }

    @Override
    public List<String> requestedPrincipalSelection() throws MessageContentException {
        if (!hasIDPSSODescriptor()) {
            throw new MessageContentException("No IDP SSO Descriptor found in meta data with id " + entityID);
        }
        return requestedPrincipalSelection;
    }

    @Override
    public List<X509Certificate> getSigningCertificates(ContextMessageSecurityProvider.Context context) throws MessageProcessingException {
        return getRoleDescriptor(context).getSigningCertObjects();
    }

    @Override
    public List<String> getAllSigningCertificateFingerprints() {
        return roleDescriptors.stream().flatMap( it -> it.getSigningCertFingerprints().stream()).collect(Collectors.toList());
    }

    @Override
    public List<String> getSigningCertificateFingerprints(ContextMessageSecurityProvider.Context context) throws MessageProcessingException {
        return getRoleDescriptor(context).getSigningCertFingerprints();
    }

    private RoleDescriptor getRoleDescriptor(ContextMessageSecurityProvider.Context context) throws MessageProcessingException {
        var expectedRole = Objects.equals(context.getUsage(), MetadataConstants.CONTEXT_USAGE_SIGNREQUEST) ? SPSSODescriptorType.class.getSimpleName() : IDPSSODescriptorType.class.getSimpleName();

        // get the first roleDescriptor of the right type, and return its certificates
        var rd = firstRoleDescriptor(expectedRole);
        if (rd == null) {
            throw new MessageProcessingException("Error no role of type " + expectedRole + " found in meta data");
        }

        // check for error messages, from certificate parsing
        if(!rd.errorMessages.isEmpty()) {
            throw new MessageProcessingException(String.join(", ", rd.errorMessages));
        }
        return rd;
    }

    @Override
    public boolean hasIDPSSODescriptor() {
        return roleDescriptors.stream().anyMatch(it -> Objects.equals(it.elementLocalName, IDPSSODescriptorType.class.getSimpleName()));
    }

    RoleDescriptor firstRoleDescriptor(String localName) {
        return this.roleDescriptors.stream().filter (it -> Objects.equals(it.elementLocalName, localName)).findFirst().orElse(null);
    }

    @Override
    public boolean hasEntityAttributeValue(String name, String value) {
        return entityAttributes.containsKey(name) && entityAttributes.get(name).contains(value);
    }

    @Override
    public boolean hasEntityAttributes() {
        return !entityAttributes.isEmpty();
    }

    @JsonIgnore
    @Override
    public List<String> getAuthnContextClassRefs() {
        for (final var e : entityAttributes.entrySet()) {
            if (Objects.equals(e.getKey(), MetadataConstants.DEFAULT_ASSURANCE_CERTIFICATION_NAME)) {
                return e.getValue();
            }
        }
        return Collections.emptyList();
    }

    public String getDestination(String authNProtocolBinding) throws MessageContentException {
        return singleSignOnServices.stream().filter(it -> Objects.equals(it.binding, authNProtocolBinding)).findFirst().map(it -> it.location).orElseThrow(
                () -> new MessageContentException("Error generating GetAuthNRequest from SignRequest, couldn't lookup Destination from Metadata with entityId: $entityID")
        );
    }

    public String getDisplayName(String lang, String defaultLang) {
        // Algo for finding a displayName ?!
        // tries UIInfos in the first roleDescriptor,
        // then organisation,
        // then certificates from first encounteredIDPSSODescriptor
        // then from the rest of the roleDescriptors

        String displayName = null;

        for (final var rd : roleDescriptors) {
            displayName = rd.getUIInfoDisplayName(lang, defaultLang).orElse(null);
            if (isTruthyString(displayName)) {
                msgLog.info("Setting displayName from MDIO metadata extension '${displayName}'");
                return displayName;
            }
            break;
        }

        displayName = Optional.ofNullable(organisation).flatMap(o -> o.getOrganisationDisplayName(lang, defaultLang)).orElse(null);
        if (isTruthyString(displayName)) {
            msgLog.info("Setting displayName from Organization metadata extension '$displayName'");
            return displayName;
        }

        var firstIDpRd = firstRoleDescriptor(IDPSSODescriptorType.class.getSimpleName());
        if (firstIDpRd != null) {
            displayName = firstIDpRd.getCNDisplayName().orElse(null);
            if (isTruthyString(displayName)) {
                return displayName;
            } else {
                msgLog.error("No Trusted X509 Signing Certificate found for EntityID '${entityID}' when trying to receive displayName from X509 certificate");
            }
        }

        for (final var rd : roleDescriptors) {
            displayName = rd.getUIInfoDisplayName(lang, defaultLang).orElse(null);
            if (isTruthyString(displayName)) {
                msgLog.info("Setting displayName from MDIO metadata extension '${displayName}'");
                return displayName;
            }
        }

        msgLog.error("No DisplayName found for EntityDescriptor with EntityID '${entityID}'");
        return displayName;
    }

    public static class SingleSignOnService {
        String binding;
        String location;

        public SingleSignOnService() {
        }

        public String getBinding() {
            return binding;
        }

        public String getLocation() {
            return location;
        }

        SingleSignOnService(String binding, String location) {
            this.binding = binding;
            this.location = location;
        }
    }

    public static class AttributeConsumingService {
        List<String> names;
        List<RequestedAttribute> requestedAttributes;

        public AttributeConsumingService() {
        }

        AttributeConsumingService(List<String> names, List<RequestedAttribute> requestedAttributes) {
            this.names = names;
            this.requestedAttributes = requestedAttributes;
        }

        public List<String> getNames() {
            return names;
        }

        public List<RequestedAttribute> getRequestedAttributes() {
            return requestedAttributes;
        }
    }

    public static class RequestedAttribute {
        String name;
        String friendlyName;
        private Boolean required;

        public RequestedAttribute() {
        }

        RequestedAttribute(String name) {
            this.name = name;
            this.required = Boolean.FALSE;
        }

        RequestedAttribute(String name, String friendlyName, Boolean required) {
            this.name = name;
            this.friendlyName = friendlyName;
            this.required = required;
        }

        public String getName() {
            return name;
        }

        public String getFriendlyName() {
            return friendlyName;
        }

        public Boolean isRequired() {
            return required;
        }
    }

    public static class RoleDescriptor {
        String elementLocalName;
        List<UIInfo> uiInfos;
        @JsonIgnore
        List<X509Certificate> signingCertObjects;
        @JsonIgnore
        List<String> signingCertFingerprints;
        List<String> signingCertificates;
        List<String> signingCertificatesCNs;
        List<String> errorMessages = new ArrayList<>();

        public RoleDescriptor() {
        }

        RoleDescriptor(String elementLocalName, List<UIInfo> uiInfos) {
            this.elementLocalName = elementLocalName;
            this.uiInfos = uiInfos;
        }

        public String getElementLocalName() {
            return elementLocalName;
        }

        public List<UIInfo> getUiInfos() {
            return uiInfos;
        }

        public List<String> getSigningCertificates() {
            return signingCertificates != null ? signingCertificates : new ArrayList<>();
        }

        @JsonIgnore
        private List<X509Certificate> getSigningCertObjects() {
            if (signingCertObjects == null) {
                signingCertObjects = getSigningCertificates().stream()
                        .map(c -> Base64.getDecoder().decode(c))
                        .map(b -> {
                                    try {
                                        return CertUtils.getCertfromByteArray(b);
                                    } catch (CertificateException e) {
                                        throw new RuntimeException(e);
                                    }
                                }
                        ).collect(Collectors.toList());
            }
            return signingCertObjects;
        }

        @JsonIgnore
        List<String> getSigningCertFingerprints() {
            if (signingCertFingerprints == null) {
                signingCertFingerprints = getSigningCertObjects().stream()
                        .map(c -> {
                            try {
                                return CertUtils.getCertFingerprint(c);
                            } catch (NoSuchAlgorithmException e) {
                                throw new RuntimeException(e);
                            } catch (CertificateEncodingException e) {
                                throw new RuntimeException(e);
                            } catch (UnsupportedEncodingException e) {
                                throw new RuntimeException(e);
                            }
                        }).collect(Collectors.toList());
            }
            return signingCertFingerprints;
        }

        public List<String> getSigningCertificatesCNs() {
            return signingCertificatesCNs;
        }

        public List<String> getErrorMessages() {
            return errorMessages;
        }

        Optional<String> getUIInfoDisplayName(String lang, String defaultLang) {
            // find matching lang in uiInfos
            if(isTruthyString(lang)) {
                for (final var uii : uiInfos) {
                    for (final var dn : uii.displayNames) {
                        if (Objects.equals(dn.lang, lang)) {
                            return Optional.ofNullable(dn.value);
                        }
                    }
                }
            }
            // find matching default lang in uiInfos
            for (final var uii : uiInfos) {
                for (final var dn : uii.displayNames) {
                    if (Objects.equals(dn.lang, defaultLang)) {
                        return Optional.ofNullable(dn.value);
                    }
                }
            }

            // try find any non null value
            for (final var uii : uiInfos) {
                for (final var dn : uii.displayNames) {
                    if (isTruthyString(dn.value)) {
                        return Optional.of(dn.value);
                    }
                }
            }

            return Optional.empty();
        }

        @JsonIgnore
        Optional<String> getCNDisplayName() {
            var signingCertObjects = getSigningCertObjects();
            if (isTruthyList(signingCertificatesCNs) && isTruthyList(signingCertObjects)) {
                for (int i = 0; i < signingCertificatesCNs.size(); i++) {
                    var v = signingCertificatesCNs.get(i);
                    if (isTruthyString(v)) {
                        var cert = signingCertObjects.get(i);
                        msgLog.info("Returning displayName from CommonName " + v + ", from X509 certificate with serial number: " + cert.getSerialNumber());
                        return Optional.of(v);
                    }
                }
            }
            return Optional.empty();
        }
    }

    public static class UIInfo {
        List<DisplayName> displayNames;

        public UIInfo() {
        }

        UIInfo(List<DisplayName> displayNames) {
            this.displayNames = displayNames;
        }

        public List<DisplayName> getDisplayNames() {
            return displayNames;
        }
    }

    public static class DisplayName {
        String value;
        String lang;

        public DisplayName() {
        }

        DisplayName(String value, String lang) {
            this.value = ReducedMetadataUtils.cleanWhitespace(value);
            this.lang = lang;
        }

        public String getValue() {
            return value;
        }

        public String getLang() {
            return lang;
        }
    }

    public static class Organisation {
        List<DisplayName> displayNames;

        public Organisation() {
        }

        Organisation(List<DisplayName> displayNames) {
            this.displayNames = displayNames;
        }

        public List<DisplayName> getDisplayNames() {
            return displayNames;
        }

        Optional<String> getOrganisationDisplayName(String lang, String defaultLang) {
            if(isTruthyString(lang)) {
                for (final var dn : displayNames) {
                    if (Objects.equals(dn.lang, lang)) {
                        return Optional.ofNullable(dn.value);
                    }
                }
            }

            for (final var dn : displayNames) {
                if (Objects.equals(dn.lang, defaultLang)) {
                    return Optional.ofNullable(dn.value);
                }
            }

            for (final var dn : displayNames) {
                if (isTruthyString(dn.value)) {
                    return Optional.of(dn.value);
                }
            }

            return Optional.empty();
        }
    }
}
