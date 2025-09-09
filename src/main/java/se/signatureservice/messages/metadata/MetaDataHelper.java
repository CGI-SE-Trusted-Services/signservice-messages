package se.signatureservice.messages.metadata;

import jakarta.xml.bind.JAXBElement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.signatureservice.messages.MessageContentException;
import se.signatureservice.messages.MessageProcessingException;
import se.signatureservice.messages.saml2.metadata.jaxb.KeyDescriptorType;
import se.signatureservice.messages.saml2.metadata.jaxb.KeyTypes;
import se.signatureservice.messages.saml2.metadata.jaxb.RoleDescriptorType;
import se.signatureservice.messages.utils.CertUtils;
import se.signatureservice.messages.xmldsig.jaxb.X509DataType;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Class containing help method for extracting information from MetaData.
 * Created by philip on 2017-07-28.
 */
class MetaDataHelper {
    static Logger log = LoggerFactory.getLogger(MetaDataHelper.class);

    /**
     * Method to find the certificate for the given keyType in a given MetaData role descriptor type
     * @param roleDescriptorType the role to extract trusted certificate from.
     * @param keyType either signing or encryption type to lookup
     * @return the roles trusted certificate, never null.
     * @throws MessageProcessingException if no trusted certificate could be found or problems occurred decoding the certificate.
     */
    static List<X509Certificate> findCertificates(RoleDescriptorType roleDescriptorType, KeyTypes keyType) throws MessageProcessingException, MessageContentException {
        List<X509Certificate> retval = new ArrayList<>();
        if(roleDescriptorType.getKeyDescriptor() != null){
            for(KeyDescriptorType kdt : roleDescriptorType.getKeyDescriptor()){
                if(kdt.getUse() == null || kdt.getUse() == keyType){
                    for(Object o : kdt.getKeyInfo().getContent()){
                        if(o instanceof JAXBElement && ((JAXBElement) o).getValue() instanceof X509DataType){
                            X509Certificate cert = getCertificateFromX509Data((X509DataType) ((JAXBElement) o).getValue());
                            if(cert != null){
                                retval.add(cert);
                            }
                        }
                    }
                }
            }
        }

        if(retval.isEmpty()){
            throw new MessageProcessingException("Error no trusted X509Certificate could be found in MetaData");
        }
        return retval;
    }

    /**
     * Method that traverses through all content of a X509Data type and returns the first X509Certificate found
     * @param x509DataType the X509DataType to traverse
     * @return the first X509Certificate or null if no was found.
     * @throws MessageProcessingException if problems occurred decoding the X509Certificate.
     */
    static X509Certificate getCertificateFromX509Data(X509DataType x509DataType) throws MessageProcessingException {
        if (x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName() != null) {
            // First check the number of certificates, if multiple assume chain and return end entity certificate
            // if only one return that certificate with a warning if it is self-signed.
            int numberOfCerts = 0;
            for (Object o : x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName()) {
                if (o instanceof JAXBElement && ((JAXBElement) o).getName().getNamespaceURI().equals("http://www.w3.org/2000/09/xmldsig#")
                        && ((JAXBElement) o).getName().getLocalPart().equals("X509Certificate")) {
                    numberOfCerts++;
                }
            }

            for (Object o : x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName()) {
                if (o instanceof JAXBElement && ((JAXBElement) o).getName().getNamespaceURI().equals("http://www.w3.org/2000/09/xmldsig#")
                        && ((JAXBElement) o).getName().getLocalPart().equals("X509Certificate")) {
                    try {
                        byte[] data = (byte[]) ((JAXBElement) o).getValue();
                        X509Certificate cert = CertUtils.getCertfromByteArray(data);
                        if (numberOfCerts == 1) {
                            if (cert.getBasicConstraints() != -1) {
                                log.warn("Warning, IDP uses CA certificate as signing or encryption certificate.");
                            }
                            return cert;
                        } else {
                            if (cert.getBasicConstraints() == -1) {
                                log.warn("Warning, a certificate chain is specified in the metadata, and use the end entity certificate as signing or encryption certificate.");
                                return cert;
                            }
                        }

                        // In future should chain verification be performed, etc.
                    } catch (Exception e) {
                        throw new MessageProcessingException("Error parsing X509 certificate from metadata: " + e.getMessage());
                    }
                }
            }
            if (numberOfCerts > 1) {
                log.warn("Warning, a certificate chain is specified in the metadata, but no end entity certificate.");
            }
        }

        return null;
    }
}