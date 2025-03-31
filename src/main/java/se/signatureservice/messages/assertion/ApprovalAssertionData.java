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
import se.signatureservice.messages.csmessages.jaxb.Approver;

/**
 * Value object containing information about and Approval Assertion.
 * 
 * @author Philip Vendil
 *
 */
public class ApprovalAssertionData extends AssertionData {

	private String approvalId;
	private List<String> approvalRequests;
	private String destinationId;
	private List<Approver> approvers;

	/**
	 * Main Constructor
	 */
	public ApprovalAssertionData(AssertionPayloadParser assertionPayloadParser){
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
							if(((AttributeType) attr).getName().equals(AssertionPayloadParser.ATTRIBUTE_NAME_APPROVALID)){
								approvalId = (String) ((AttributeType) attr).getAttributeValue().get(0);
							}
							if(((AttributeType) attr).getName().equals(AssertionPayloadParser.ATTRIBUTE_NAME_DESTINATIONID)){
								destinationId = (String) ((AttributeType) attr).getAttributeValue().get(0);
							}
							if(((AttributeType) attr).getName().equals(AssertionPayloadParser.ATTRIBUTE_NAME_APPROVEDREQUESTS)){
								approvalRequests = new ArrayList<String>();
								for(Object next : ((AttributeType) attr).getAttributeValue()){
									if(next instanceof String){
										approvalRequests.add((String) next);
									}
								}						
							}
							if(((AttributeType) attr).getName().equals(AssertionPayloadParser.ATTRIBUTE_NAME_APPROVERS)){
								approvers = new ArrayList<Approver>();
								for(Object next : ((AttributeType) attr).getAttributeValue()){
									if(next instanceof Approver){
										approvers.add((Approver) next);
									}
								}	
								if(approvers.size() == 0){
									approvers = null;
								}
							}
						}
					}
				}
			}
		}catch(Exception e){
			throw new MessageContentException("Error parsing Approval Assertion: " + e.getMessage(),e);
		}
		
	}

	/**
	 * 
	 * @return  the request unique approval id
	 */
	public String getApprovalId() {
		return approvalId;
	}

	/**
	 * @return list containing one or more AttributeValue with the digest values of the calculated request actions. 
	 * It's up to the approval workflow engine to determine how the digest is calculated from an approval request and how to verify that subsequent
	 * request matches the given approval.
	 */
	public List<String> getApprovalRequests() {
		return approvalRequests;
	}
	
	/**
	 * 
	 * @return the id to the target system processing the ticket. null for ANY destination.
	 */
	public String getDestinationId(){
		return destinationId;
	}
	
	/**
	 * 
	 * @return a list of approvers if available to the user, otherwise null.
	 */
	public List<Approver> getApprovers(){
		return approvers;
	}

	@Override
	public String toString() {
		return "ApprovalAssertionData [approvalId=" + approvalId
				+ ", approvalRequests=" + approvalRequests + ", destinationId=" + destinationId + ", id="
				+ getId() + ", notBefore=" + getNotBefore()
				+ ", notOnOrAfter=" + getNotOnOrAfter()
				+ ", subjectId=" + getSubjectId()
				+ ", signCertificate=" + getSignCertificate().toString() + "]";
	}


	
	
}
