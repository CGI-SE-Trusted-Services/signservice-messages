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

import jakarta.xml.bind.JAXBElement;
import se.signatureservice.messages.saml2.assertion.jaxb.AttributeType;
import se.signatureservice.messages.saml2.metadata.attr.jaxb.EntityAttributesType;
import se.signatureservice.messages.saml2.metadata.jaxb.*;
import se.signatureservice.messages.saml2.metadata.ui.jaxb.UIInfoType;
import se.signatureservice.messages.sweeid2.pricipalselection1_0.jaxb.RequestedPrincipalSelectionType;

import java.security.cert.CertificateEncodingException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Helper methods used when converting saml metadata into ReducedMetadata
 *
 * Created by fredrik 2025-08-28.
 */
class ReducedMetadataUtils {

    static List<ReducedMetadataImpl.AttributeConsumingService> getAttributeConsumingServices(EntityDescriptorType entityDescriptor) {
        List<ReducedMetadataImpl.AttributeConsumingService> retVal = new ArrayList<>();
        for(Object roleDescriptor : entityDescriptor.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor()) {
            if(roleDescriptor instanceof SPSSODescriptorType) {
                ((SPSSODescriptorType) roleDescriptor).getAttributeConsumingService().forEach(it -> {
                    var attr = it.getRequestedAttribute().stream().map(itt -> new ReducedMetadataImpl.RequestedAttribute(
                            itt.getName(), itt.getFriendlyName(), itt.isIsRequired()
                    )).collect(Collectors.toList());


                    var names = it.getServiceName().stream().map(sn -> trimAndOneLine(sn.getValue())).collect(Collectors.toList());
                    retVal.add(new ReducedMetadataImpl.AttributeConsumingService(names, attr));
                });
            }
        }
        return retVal;
    }

    static List<String> getRequestedPrincipalSelection(EntityDescriptorType entityDescriptor) {
        List<String> retVal = new ArrayList<>();
        IDPSSODescriptorType idpssoDescriptorType = (IDPSSODescriptorType) entityDescriptor.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor()
                .stream().filter(it -> it instanceof IDPSSODescriptorType ).findFirst().orElse(null);

        if (idpssoDescriptorType != null) {
            if (idpssoDescriptorType.getExtensions() != null) {
                JAXBElement<RequestedPrincipalSelectionType> extensionElement = (JAXBElement<RequestedPrincipalSelectionType>) idpssoDescriptorType.getExtensions().getAny()
                        .stream().filter (it -> it instanceof JAXBElement && ((JAXBElement) it).getValue() instanceof RequestedPrincipalSelectionType)
                        .findFirst().orElse(null);
                if (extensionElement != null) {
                    var matchValues = extensionElement.getValue().getMatchValue();
                    for (final var mv : matchValues) {
                        retVal.add(mv.getName());
                    }
                }
            }
        }
        return retVal;
    }

    static Map<String, List<String>> getEntityAttributes(EntityDescriptorType entityDescriptor) {
        var retVal = new HashMap<String, List<String>>();
        if (entityDescriptor.getExtensions() != null) {
            for (Object o : entityDescriptor.getExtensions().getAny()) {
                if (o instanceof JAXBElement && ((JAXBElement) o).getValue() instanceof EntityAttributesType) {
                    EntityAttributesType eat = (EntityAttributesType) ((JAXBElement) o).getValue();
                    for (Object a : eat.getAttributeOrAssertion()) {
                        if (a instanceof AttributeType) {
                            AttributeType attribute = (AttributeType) a;
                            retVal.put(attribute.getName(), new ArrayList<>());
                            for (Object v : attribute.getAttributeValue()) {
                                if (v instanceof String) {
                                    String value = trimAndOneLine((String) v);
                                    retVal.get(attribute.getName()).add(value);
                                }
                            }
                        }
                    }
                }
            }
        }
        return retVal;
    }

    static List<ReducedMetadataImpl.SingleSignOnService> getSingleSignOnServices(EntityDescriptorType entityDescriptor) {
        var retVal = new ArrayList<ReducedMetadataImpl.SingleSignOnService>();
        for(Object o : entityDescriptor.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor()) {
            if(o instanceof IDPSSODescriptorType) {
                IDPSSODescriptorType idpDescriptor = (IDPSSODescriptorType) o;
                for(var endpoint: idpDescriptor.getSingleSignOnService()){
                    retVal.add(new ReducedMetadataImpl.SingleSignOnService(
                            endpoint.getBinding(), endpoint.getLocation()
                    ));
                }
            }
        }
        return retVal;
    }

    static ReducedMetadataImpl.Organisation getOrganisation(EntityDescriptorType entityDescriptor) {
        if (entityDescriptor.getOrganization() != null) {
            var dns = entityDescriptor.getOrganization().getOrganizationDisplayName().stream()
                    .map (it -> new ReducedMetadataImpl.DisplayName(it.getValue(), it.getLang()))
                    .collect(Collectors.toList());
            return new ReducedMetadataImpl.Organisation(dns);
        }
        return null;
    }

    static List<ReducedMetadataImpl.RoleDescriptor> getRoleDescriptors(EntityDescriptorType entityDescriptor) {
        List<ReducedMetadataImpl.RoleDescriptor> retVal = new ArrayList<>();

        boolean didReadIDPKeys = false;
        boolean didReadSPKeys = false;

        for (final RoleDescriptorType rd : entityDescriptor.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor()) {
            var descriptor = new ReducedMetadataImpl.RoleDescriptor(rd.getClass().getSimpleName(), getUIInfos(rd));

            // collect keys for first idp and sp
            if (rd.getClass() == IDPSSODescriptorType.class && !didReadIDPKeys) {
                collectCerts(rd, descriptor);
                didReadIDPKeys = true;
            }

            if (rd.getClass() == SPSSODescriptorType.class && !didReadSPKeys) {
                collectCerts(rd, descriptor);
                didReadSPKeys = true;
            }

            retVal.add(descriptor);
        }

        return retVal;
    }

    private static List<ReducedMetadataImpl.UIInfo> getUIInfos(RoleDescriptorType roleDescriptorType) {
        var retVal = new ArrayList<ReducedMetadataImpl.UIInfo>();

        var list = Optional.ofNullable(roleDescriptorType.getExtensions()).map(ExtensionsType::getAny).orElse(Collections.emptyList());

        var uis = list.stream().filter(it -> it instanceof JAXBElement && ((JAXBElement) it).getValue() instanceof UIInfoType)
                .map(it -> (JAXBElement) it).collect(Collectors.toList());

        for (final JAXBElement element : uis) {
            UIInfoType uiInfo = ((UIInfoType) element.getValue());
            var names = new ArrayList<ReducedMetadataImpl.DisplayName>();
            for (final var namesObj : uiInfo.getDisplayNameOrDescriptionOrKeywords()) {
                if (!(namesObj instanceof JAXBElement)) {
                    continue;
                }
                JAXBElement e = (JAXBElement) namesObj;
                if (!e.getName().getLocalPart().equalsIgnoreCase("DisplayName")) {
                    continue;
                }

                if (e.getValue() instanceof LocalizedNameType) {
                    LocalizedNameType localizedNames = (LocalizedNameType) e.getValue();
                    names.add(new ReducedMetadataImpl.DisplayName(localizedNames.getValue(), localizedNames.getLang()));
                }
            }
            retVal.add(new ReducedMetadataImpl.UIInfo(names));
        }
        return retVal;
    }

    private static void collectCerts(RoleDescriptorType rd, ReducedMetadataImpl.RoleDescriptor descriptor) {
        try {
            var certificates = MetaDataHelper.findCertificates(rd, KeyTypes.SIGNING);
            var signingCertificates = certificates.stream().map(it -> {
                try {
                    return new String(Base64.getEncoder().encode(it.getEncoded()));
                } catch (CertificateEncodingException e) {
                    throw new RuntimeException(e);
                }
            }).collect(Collectors.toList());
            var commonNames = certificates.stream().map(it -> MetaDataUtils.getCommonNameFromX509Certificate(it)).collect(Collectors.toList());
            descriptor.signingCertObjects = certificates;
            descriptor.signingCertificates = signingCertificates;
            descriptor.signingCertificatesCNs = commonNames;
        } catch (Exception e) {
            descriptor.errorMessages.add(e.getMessage());
        }
    }

    static String trimAndOneLine(String value) {
        return value != null ? value.replaceAll("\\n", " ").trim() : null;
    }

    static boolean isTruthyString(String value) {
        return value != null && !value.trim().isEmpty();
    }

    static boolean isTruthyList(List<?> list) {
        return list != null && !list.isEmpty();
    }
}
