/************************************************************************
*                                                                       *
*  Certificate Service - Messages                                       *
*                                                                       *
*  This software is free software; you can redistribute it and/or       *
*  modify it under the terms of the GNU Affero General Public License   *
*  License as published by the Free Software Foundation; either         *
*  version 3   of the License, or any later version.                    *
*                                                                       *
*  See terms of license at gnu.org.                                     *
*                                                                       *
*************************************************************************/
package org.certificateservices.messages.assertion;

import java.security.cert.X509Certificate;
import java.util.Date;

import javax.xml.bind.JAXBElement;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.saml2.assertion.jaxb.AssertionType;
import org.certificateservices.messages.saml2.assertion.jaxb.NameIDType;
import org.certificateservices.messages.utils.MessageGenerateUtils;


/**
 * Abstract base class of an parsed Assertion containing ID and validity dates.
 * 
 * @author Philip Vendil
 *
 */
public abstract class AssertionData {
	
	protected String id;
	protected Date notBefore;
	protected Date notOnOrAfter;
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
	 * @return the not before date this assertions i valid.
	 */
	public Date getNotBefore() {
		return notBefore;
	}

	/**
	 * 
	 * @return the date this assertion expires.
	 */
	public Date getNotOnOrAfter() {
		return notOnOrAfter;
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
