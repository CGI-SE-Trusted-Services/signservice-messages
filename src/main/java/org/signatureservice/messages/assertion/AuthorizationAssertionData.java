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
package org.signatureservice.messages.assertion;

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.JAXBElement;

import org.signatureservice.messages.MessageContentException;
import org.signatureservice.messages.MessageProcessingException;
import org.signatureservice.messages.saml2.assertion.jaxb.AssertionType;
import org.signatureservice.messages.saml2.assertion.jaxb.AttributeStatementType;
import org.signatureservice.messages.saml2.assertion.jaxb.AttributeType;

/**
 * Value object containing information about and Authorization Ticketr Assertion.
 * 
 * @author Philip Vendil
 *
 */
public class AuthorizationAssertionData extends AssertionData {

	private List<String> roles;
	private List<String> departments;

	/**
	 * Main Constructor
	 */
	public AuthorizationAssertionData(AssertionPayloadParser assertionPayloadParser){
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

							if(((AttributeType) attr).getName().equals(AssertionPayloadParser.ATTRIBUTE_NAME_ROLES)){
								roles = new ArrayList<String>();
								for(Object next : ((AttributeType) attr).getAttributeValue()){
									if(next instanceof String){
										roles.add((String) next);
									}
								}						
							}
							if(((AttributeType) attr).getName().equals(AssertionPayloadParser.ATTRIBUTE_NAME_DEPARTMENTS)){
								departments = new ArrayList<String>();
								for(Object next : ((AttributeType) attr).getAttributeValue()){
									if(next instanceof String){
										departments.add((String) next);
									}
								}
							}
						}
					}
				}
			}
		}catch(Exception e){
			throw new MessageContentException("Error parsing Authorization Assertion: " + e.getMessage(), e);
		}	
	}

	/**
	 * @return roles a list of roles the user has.
	 */
	public List<String> getRoles() {
		return roles;
	}

	/**
	 * @return roles a list of departments the user has.
	 */
	public List<String> getDepartments() {
		return departments;
	}

	@Override
	public String toString() {
		return "AuthorizationAssertionData [roles=" + roles
				+ ", departments=" + departments
				+ ", id="
				+ getId() + ", notBefore=" + getNotBefore()
				+ ", notOnOrAfter=" + getNotOnOrAfter()
				+ ", subjectId=" + getSubjectId()
				+ ", signCertificate=" + getSignCertificate().toString() + "]";
	}

	
	
}
