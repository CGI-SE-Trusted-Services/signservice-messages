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

import se.signatureservice.messages.ContextMessageSecurityProvider;
import se.signatureservice.messages.MessageContentException;
import se.signatureservice.messages.MessageProcessingException;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Represents data extracted from a saml metadata Entity
 *
 * Created by fredrik 2025-08-28.
 */
public interface ReducedMetadata {

    /**
     * Method to return the entityID, of the saml metadata EntityDescriptor
     *
     * @return String entityID of the EntityDescriptor
     */
    String getEntityID();

    /**
     * Method to return the filename, from where the entity was loaded, may be null
     *
     * @return String fileName
     */
    String getFileName();

    /**
     * Method to return the Destination, based on binding specified in the input parameter
     *
     * @param String authNProtocolBinding
     * @return String destination
     */
    String getDestination(String authNProtocolBinding) throws MessageContentException;

    /**
     * Method to check if there is an entity attribute matching attributeName and value,
     * specified in extensions.EntityAttribute of the EntityDescriptor
     *
     * @param attributeName
     * @param attributeValue
     * @return boolean
     */
    boolean hasEntityAttributeValue(String attributeName, String attributeValue);

    /**
     * Method to find children of extensions.RequestedPrincipalSelection in the first IDPSSODescriptor
     *
     * @return List<String> of principal attributes
     * @throws MessageContentException if there is no IDPSSODescriptor in the EntityDescriptor.
     */
    List<String> requestedPrincipalSelection() throws MessageContentException;

    /**
     * Method to find the certificates specified for signing, from the first IDPSSODescriptor, or SPSSODescriptor,
     * depending on the input parameter
     *
     * @param context, specifies if we want IDPSSODescriptor-, or SPSSODescriptor certificates
     * @return List<X509Certificate>
     */
    List<X509Certificate> getSigningCertificates(ContextMessageSecurityProvider.Context context) throws MessageProcessingException;

    /**
     * Method to find the fingerprints of certificates specified for signing, from the first IDPSSODescriptor, or SPSSODescriptor,
     * depending on the input parameter
     *
     * @param context, specifies if we want IDPSSODescriptor-, or SPSSODescriptor certificates
     * @return List<X509Certificate>
     */
    List<String> getSigningCertificateFingerprints(ContextMessageSecurityProvider.Context context) throws MessageProcessingException;

    /**
     * Method to find out if this EntityDescriptor has an IDPSSODescriptor
     *
     * @return boolean
     */
    boolean hasIDPSSODescriptor();

    /**
     * Method to get a display name String, representing this entity.
     *
     * @param lang, the preferred language
     * @return String display name
     */
    String getDisplayName(String lang, String defaultLang) throws MessageContentException;

    /**
     * Method to get any SPSSODescriptor.attributeConsumingServices, that match the serviceName input
     *
     * @param serviceName, used to match attributeConsumingServices
     * @return List<ReducedMetadataImpl.AttributeConsumingService>
     */
    List<ReducedMetadataImpl.AttributeConsumingService> getAttributeConsumingServices(String serviceName);

    /**
     * Method to find out if this EntityDescriptor has any EntityAttributes
     *
     * @return boolean
     */
    boolean hasEntityAttributes();

    /**
     * Method to find values of extensions.EntityAttribute, in the EntityDescriptor, that specify AuthnContextClassRefs
     *
     * @return List<String> of AuthnContextClassRefs
     */
    List<String> getAuthnContextClassRefs();
}