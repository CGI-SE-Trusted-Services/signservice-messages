package org.signatureservice.messages.utils;

import org.signatureservice.messages.MessageContentException;
import org.signatureservice.messages.MessageProcessingException;
import org.signatureservice.messages.csmessages.CSMessageParser;
import org.signatureservice.messages.csmessages.jaxb.CSMessage;
import org.signatureservice.messages.csmessages.jaxb.GetApprovalRequest;
import org.xml.sax.SAXParseException;

import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import java.security.cert.X509Certificate;

/**
 * Utility methods used when working with CS Messages
 * 
 * @author Philip Vendil
 *
 */
public class CSMessageUtils {

	/**
	 * Method to fetch the payload from a CSMessage
	 * @param csMessage the CSMessage to fetch payload from
	 * @return the related payload or null if no payload could be found.
	 */
	public static Object getPayload(CSMessage csMessage){
		if(csMessage == null){
			return null;
		}
		Object o = csMessage.getPayload().getAny();
		if(o instanceof JAXBElement){
			return ((JAXBElement) o).getValue();
		}
		return o;
	}
	
	/**
	 * Method returning the name of the payload object. i.e the simple name of the payload class.
	 * @param csMessage
	 * @return
	 * @throws MessageContentException if no payload name could be found.
	 */
	public static String getPayloadName(CSMessage csMessage) throws MessageContentException{
		Object payload = getPayload(csMessage);
		if(payload == null){
			throw new MessageContentException("Error no payload name could be found in CS Message");
		}
		return payload.getClass().getSimpleName();
	}
	
	/**
	 * Method returning the related payload object in from a GetApprovalRequest.
	 * @param csMessage the CS message to fetch related payload object, must contain a GetApprovalRequest payload
	 * @return the related payload
	 * @throws MessageContentException if csMessage didn't contain any GetApprovalRequest
	 */
	public static Object getRelatedPayload(CSMessage csMessage) throws MessageContentException{
		Object payload = getPayload(csMessage);
		if(payload instanceof GetApprovalRequest){
			return ((GetApprovalRequest) payload).getRequestPayload().getAny();
		}
		throw new MessageContentException("Error fetching related payload object from CS Message, message didn't contain any GetApprovalRequest payload.");
	}
	
	/**
	 * Method returning the related payload name in from a GetApprovalRequest. i.e the simple name of the payload class.
	 * @param csMessage the CS message to fetch related payload name, must contain a GetApprovalRequest payload
	 * @return the related payload name, 
	 * @throws MessageContentException if csMessage didn't contain any GetApprovalRequest
	 */
	public static String getRelatedPayloadName(CSMessage csMessage) throws MessageContentException{
		Object payload = getPayload(csMessage);
		if(payload instanceof GetApprovalRequest){
			return ((GetApprovalRequest) payload).getRequestPayload().getAny().getClass().getSimpleName();
		}
		throw new MessageContentException("Error fetching related payload name from CS Message, message didn't contain any GetApprovalRequest payload.");
	}

	/**
	 * Help method to extract a more descriptive error message than 'null' when error
	 * occurred in schema validation when unmarshalling and marshalling XML.
	 *
	 * @param e the exception to extracting exception from
	 * @return the exception message if exists, otherwise the cause message.
	 */
	public static String getMarshallingExceptionMessage(Exception e){
		if(e.getMessage() == null) {
			if (e.getCause() != null){
				if(e.getCause().getMessage() == null) {
					if (e instanceof JAXBException) {
						if (((JAXBException) e).getLinkedException() != null && ((JAXBException) e).getLinkedException().getMessage() != null) {
							return ((JAXBException) e).getLinkedException().getMessage();
						}
					}
					if (e instanceof SAXParseException) {
						if (((SAXParseException) e).getException() instanceof JAXBException) {
							JAXBException je = (JAXBException) ((SAXParseException) e).getException();
							if (je.getLinkedException() != null && je.getLinkedException().getMessage() != null) {
								return je.getLinkedException().getMessage();
							}
						}
					}
				}
				return e.getCause().getMessage();
			}
		}
		return e.getMessage();
	}

	/**
	 * Help method to parse a requester unique id from messageData used primarily for spam protection.
	 * @param parser the related CSMessageParser
	 * @param messageData the message data to extract unique id from.
	 * @return the requester id from the signer of the message.
	 * @throws MessageContentException if signer certificate data in message was invalid.
	 * @throws MessageProcessingException if internal problems occurred parsing the message data.
	 */
	public static String getRequesterUniqueId(CSMessageParser parser, byte[] messageData) throws MessageContentException, MessageProcessingException {
		X509Certificate signingCert = parser.getSigningCertificate(messageData);
		if (signingCert == null) {
			throw new MessageContentException("Error, no signing certificate found in CS Message Request");
		}
		// Reencode certificate with BC provider to ensure normalized issuer dn.
		try {
			return CertUtils.getCertificateUniqueId(CertUtils.getCertfromByteArray(signingCert.getEncoded()));
		}catch(Exception e){
			throw new MessageContentException("Error parsing certificate from CS Message: " + e.getMessage());
		}
	}
	
}
