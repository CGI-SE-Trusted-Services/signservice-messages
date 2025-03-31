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

import java.util.ArrayList;
import java.util.List;

import jakarta.xml.bind.JAXBElement;

import se.signatureservice.messages.MessageContentException;
import se.signatureservice.messages.MessageProcessingException;
import se.signatureservice.messages.saml2.assertion.jaxb.AssertionType;
import se.signatureservice.messages.saml2.assertion.jaxb.AttributeStatementType;
import se.signatureservice.messages.saml2.assertion.jaxb.AttributeType;
import se.signatureservice.messages.credmanagement.jaxb.FieldValue;

/**
 * Value object containing information about and Approval Assertion.
 * 
 * @author Philip Vendil
 *
 */
public class UserDataAssertionData extends AssertionData {

	private String displayName;
	private List<FieldValue> fieldValues;
	private String tokenType;

	/**
	 * Main Constructor
	 */
	public UserDataAssertionData(AssertionPayloadParser assertionPayloadParser){
		super(assertionPayloadParser);
	}
	
	/**
	 * Main parser called by AssertionPayloadParser after decryption.
	 */
	@Override
	public void parse(JAXBElement<AssertionType> assertion)
			throws MessageContentException, MessageProcessingException {
		parseCommonData(assertion);
		
		try{
			for(Object nextStatement : assertion.getValue().getStatementOrAuthnStatementOrAuthzDecisionStatement()){
				if(nextStatement instanceof AttributeStatementType){
					for(Object attr : ((AttributeStatementType) nextStatement).getAttributeOrEncryptedAttribute()){
						if(attr instanceof AttributeType){
							if(((AttributeType) attr).getName().equals(AssertionPayloadParser.ATTRIBUTE_NAME_DISPLAYNAME)){
								displayName = (String) ((AttributeType) attr).getAttributeValue().get(0);
							}
							if(((AttributeType) attr).getName().equals(AssertionPayloadParser.ATTRIBUTE_NAME_TOKENTYPE)){
								tokenType = (String) ((AttributeType) attr).getAttributeValue().get(0);
							}
							if(((AttributeType) attr).getName().equals(AssertionPayloadParser.ATTRIBUTE_NAME_USERDATA)){
								fieldValues = new ArrayList<FieldValue>();
								for(Object next : ((AttributeType) attr).getAttributeValue()){
									if(next instanceof FieldValue){
										fieldValues.add((FieldValue) next);
									}
								}						
							}
						}
					}
				}
			}
		}catch(Exception e){
			throw new MessageContentException("Error parsing User Data Assertion: " + e.getMessage(), e);
		}	
	}


	/**
	 * @return display name of the related user (optional might be null if no display name could be sent).
	 */
	public String getDisplayName() {
		return displayName;
	}

	/**
	 * @return related token type of the data requested  (optional might be null if no token type exists).
	 */
	public String getTokenType() {
		return tokenType;
	}

	/**
	 * @return list of field values that will be used as a complement when generating credential for a user.
	 */
	public List<FieldValue> getFieldValues() {
		return fieldValues;
	}




	@Override
	public String toString() {
		return "ApprovalAssertionData [displayName=" + displayName 
				+ ", tokenType=" + tokenType 
				+ ", fieldValues=" + fieldValues + ", id="
				+ getId() + ", notBefore=" + getNotBefore()
				+ ", notOnOrAfter=" + getNotOnOrAfter()
				+ ", subjectId=" + getSubjectId()
				+ ", signCertificate=" + getSignCertificate().toString() + "]";
	}

	
	
}
