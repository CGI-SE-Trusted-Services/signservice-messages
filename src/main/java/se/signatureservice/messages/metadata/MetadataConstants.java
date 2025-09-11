package se.signatureservice.messages.metadata;

/**
 * Constants used in the context of metadata processing. Moved up the dependency hierarchy to support metadata consumption in support-lib
 *
 * @author Fredrik
 *
 */
public class MetadataConstants {

    public final static String DEFAULT_ASSURANCE_CERTIFICATION_NAME = "urn:oasis:names:tc:SAML:attribute:assurance-certification";

    /**
     * Message Security Context used when processing Sign Requests
     */
    public static final String CONTEXT_USAGE_SIGNREQUEST = "SIGNREQUEST";

    /**
     * Message Security Context used when verifying and consuming assertions
     */
    public static final String CONTEXT_USAGE_ASSERTIONCONSUME = "ASSERTIONCONSUME";

    /**
     * Context used for meta data signing
     */
    public static final String CONTEXT_USAGE_METADATA_SIGN = "METADATASIGN";
}
