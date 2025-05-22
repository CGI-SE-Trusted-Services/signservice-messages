package se.signatureservice.messages.utils;

import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import org.xml.sax.SAXParseException;
import se.signatureservice.messages.csmessages.jaxb.CSMessage;

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
}
