package org.signatureservice.messages.dss1.core;

/**
 * Class containing defined ResultMajor values defined in DSS 1.0 specification.
 *
 * Created by philip on 09/01/17.
 */
public class ResultMajorValues {

    /**
     * The protocol executed successfully.
     */
    public static final String  Success = "urn:oasis:names:tc:dss:1.0:resultmajor:Success";

    /**
     * The request could not be satisfied due to an error on the part of the requester.
     */
    public static final String  RequesterError = "urn:oasis:names:tc:dss:1.0:resultmajor:RequesterError";

    /**
     * The request could not be satisfied due to an error on the part of the responder.
     */
    public static final String  ResponderError = "urn:oasis:names:tc:dss:1.0:resultmajor:ResponderError";
    /**
     *The request could not be satisfied due to insufficient information.
     */
    public static final String  InsufficientInformation = "urn:oasis:names:tc:dss:1.0:resultmajor:InsufficientInformation";

    public static class SuccessResultMinorValues{
        /**
         * The signature or timestamp is valid.  Furthermore, the signature or timestamp covers all of the input documents just as they were passed in by the client.
         */
        public static final String  OnAllDocuments = "urn:oasis:names:tc:dss:1.0:resultminor:valid:signature:OnAllDocuments";

        /**
         * The signature or timestamp is valid.  However, the signature or timestamp does not cover all of the input documents that were passed in by the client.
         */
        public static final String  NotAllDocumentsReferenced = "urn:oasis:names:tc:dss:1.0:resultminor:valid:signature:NotAllDocumentsReferenced";

        /**
         * The signature fails to verify, for example due to the signed document being modified or the incorrect key being used.
         */
        public static final String  IncorrectSignature = "urn:oasis:names:tc:dss:1.0:resultminor:invalid:IncorrectSignature";

        /**
         * The signature is valid with respect to XML Signature core validation.  In addition, the message also contains VerifyManifestResults.
         * Note: In the case that the core signature validation failed no attempt is made to verify the manifest.
         */
        public static final String  HasManifestResults = "urn:oasis:names:tc:dss:1.0:resultminor:valid:signature:HasManifestResults";

        /**
         * The signature is valid however the timestamp on that signature is invalid.
         */
        public static final String  InvalidSignatureTimestamp = "urn:oasis:names:tc:dss:1.0:resultminor:valid:signature:InvalidSignatureTimestamp";

    }

    public static class RequesterErrorResultMinorValues{
        /**
         * A ds:Reference element is present in the ds:Signature containing a full URI, but the corresponding input document is not present in the request.
         */
        public static final String  ReferencedDocumentNotPresent = "urn:oasis:names:tc:dss:1.0:resultminor:ReferencedDocumentNotPresent";

        /**
         * The required key information was not supplied by the client, but the server expected it to do so.
         */
        public static final String  KeyInfoNotProvided = "urn:oasis:names:tc:dss:1.0:resultminor:KeyInfoNotProvided";

        /**
         * The server was not able to create a signature because more than one RefUriwas omitted.
         */
        public static final String  MoreThanOneRefUriOmitted = "urn:oasis:names:tc:dss:1.0:resultminor:MoreThanOneRefUriOmitted";

        /**
         * The value of the RefURIattribute included in an input document is not valid.
         */
        public static final String  InvalidRefURI = "urn:oasis:names:tc:dss:1.0:resultminor:InvalidRefURI";

        /**
         * The server was not able to parse a Document.
         */
        public static final String  NotParseableXMLDocument = "urn:oasis:names:tc:dss:1.0:resultminor:NotParseableXMLDocument";

        /**
         * The server doesn't recognize or can't handle any optional input.
         */
        public static final String  NotSupported = "urn:oasis:names:tc:dss:1.0:resultminor:NotSupported";

        /**
         * The signature or its contents are not appropriate in the current context.
         * For example, the signature may be associated with a signature policy and semantics which the DSS server considers unsatisfactory.
         */
        public static final String  InappropriateSignature = "urn:oasis:names:tc:dss:1.0:resultminor:Inappropriate:signature";
    }

    public static class ResponserErrorResultMinorValues{
        /**
         * The processing of the request failed due to an error not covered by the existing error codes. Further details should be given in the result message for the user which may be passed on to the relevant administrator.
         */
        public static final String  GeneralError = "urn:oasis:names:tc:dss:1.0:resultminor:GeneralError";

        /**
         * Locating the identified key failed (e.g. look up failed in directory or in local key file).
         */
        public static final String  KeyLookupFailed = "urn:oasis:names:tc:dss:1.0:resultminor:invalid:KeyLookupFailed";
    }

    public static class InsufficientInformationResultMinorValues{
        /**
         * The relevant certificate revocation list was not available for checking.
         */
        public static final String  CrlNotAvailiable = "urn:oasis:names:tc:dss:1.0:resultminor:CrlNotAvailiable";

        /**
         * The relevant revocation information was not available via the online certificate status protocol.
         */
        public static final String  OcspNotAvailiable = "urn:oasis:names:tc:dss:1.0:resultminor:OcspNotAvailiable";

        /**
         * The chain of trust could not be established binding the public key used for validation to a trusted root
         * certification authority via potential intermediate certification authorities.
         */
        public static final String  CertificateChainNotComplete = "urn:oasis:names:tc:dss:1.0:resultminor:CertificateChainNotComplete";
    }
}
