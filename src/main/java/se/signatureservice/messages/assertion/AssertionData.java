/************************************************************************
*                                                                       *
*  Certificate Service - Messages                                       *
*                                                                       *
*  This software is free software; you can redistribute it and/or       *
*  modify it under the terms of the GNU Lesser General Public License   *
*  License as published by the Free Software Foundation; either         *
*  version 3 of the License, or any later version.                      *
*                                                                       *
*  See terms of license at gnu.org.                                     *
*                                                                       *
*************************************************************************/
package se.signatureservice.messages.assertion;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Optional;

import jakarta.xml.bind.JAXBElement;

import se.signatureservice.messages.MessageContentException;
import se.signatureservice.messages.MessageProcessingException;
import se.signatureservice.messages.saml2.assertion.jaxb.AssertionType;
import se.signatureservice.messages.saml2.assertion.jaxb.NameIDType;
import se.signatureservice.messages.utils.MessageGenerateUtils;


/**
 * Abstract base class of an parsed Assertion containing ID and validity dates.
 * 
 * @author Philip Vendil
 *
 */
public abstract class AssertionData {
	
	protected String id;
	private Date notBefore;
	private Date notOnOrAfter;
	protected String subjectId;
	protected X509Certificate signCertificate;
	protected AssertionPayloadParser assertionPayloadParser;
	
	public AssertionData(AssertionPayloadParser assertionPayloadParser){
		this.assertionPayloadParser = assertionPayloadParser;	
	}
	

	/**
	 * Mehtod to parse a decrypted JAXBElement into an AssertionData
	 * 
	 * @param assertion the assertion to parse.
	 * @throws MessageContentException if content of the message was invalid.
	 * @throws MessageProcessingException in internal problems occurred parsing the data.
	 * 
	 */
	public abstract void parse(JAXBElement<AssertionType> assertion) throws MessageContentException, MessageProcessingException;
	
	/**
	 * Parses the base values.
	 * 
	 * @param assertion the assertion to parse.
	 * @throws MessageContentException if content of the message was invalid.
	 * @throws MessageProcessingException in internal problems occurred parsing the data.
	 */
	protected void parseCommonData(JAXBElement<AssertionType>  assertion) throws MessageContentException, MessageProcessingException{
		AssertionType assertionType = assertion.getValue();
		this.id = assertionType.getID();
		
	    this.notBefore = MessageGenerateUtils.xMLGregorianCalendarToDate(assertionType.getConditions().getNotBefore());
		this.notOnOrAfter = MessageGenerateUtils.xMLGregorianCalendarToDate(assertionType.getConditions().getNotOnOrAfter());
		
		for(Object subjectContent : assertionType.getSubject().getContent()){
			if(subjectContent instanceof JAXBElement<?> && ((JAXBElement<?>) subjectContent).getValue() instanceof NameIDType){
				this.subjectId = ((NameIDType) ((JAXBElement<?>) subjectContent).getValue()).getValue();
			}
		}
		this.signCertificate = assertionPayloadParser.getCertificateFromAssertion(assertion);
	}

	/**
	 * 
	 * @return unique id of assertion.
	 */
	public String getId() {
		return id;
	}

	/**
	 * 
	 * @return the not before date this assertions i valid, as an Optional<Date>.
	 */
	public Optional<Date> getNotBefore() {
		return Optional.ofNullable(notBefore);
	}

	/**
	 * 
	 * @return the date this assertion expires, as an Optional<Date>.
	 */
	public Optional<Date> getNotOnOrAfter() {
		return Optional.ofNullable(notOnOrAfter);
	}

	/**
	 * 
	 * @return the unique subject id of the related user.
	 */
	public String getSubjectId() {
		return subjectId;
	}
	
	/**
	 * @return the certificate that signed the assertion
	 */
	public X509Certificate getSignCertificate() {
		return signCertificate;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((id == null) ? 0 : id.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		AssertionData other = (AssertionData) obj;
		if (id == null) {
			if (other.id != null)
				return false;
		} else if (!id.equals(other.id))
			return false;
		return true;
	}


	

}
