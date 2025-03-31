/************************************************************************
*                                                                       *
*  Certificate Service - Messages                                       *
*                                                                       *
*  This software is free software; you can redistribute it and/or       *
*  modify it under the terms of the GNU Lesser General Public License   *
*  License as published by the Free Software Foundation; either         *
*  version 3   of the License, or any later version.                    *
*                                                                       *
*  See terms of license at gnu.org.                                     *
*                                                                       *
*************************************************************************/

package se.signatureservice.messages.csmessages;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Properties;

import jakarta.xml.bind.Marshaller;

import se.signatureservice.messages.MessageContentException;
import se.signatureservice.messages.MessageProcessingException;
import se.signatureservice.messages.MessageSecurityProvider;
import se.signatureservice.messages.csmessages.jaxb.ApprovalStatus;
import se.signatureservice.messages.csmessages.jaxb.CSMessage;
import se.signatureservice.messages.csmessages.jaxb.Credential;
import se.signatureservice.messages.csmessages.jaxb.RequestStatus;
import org.w3c.dom.Document;

public interface CSMessageParser {
	

	
	/**
	 * Method that initializes the CSMessage parser with a security provider and properties.
	 * 
	 * @param securityProvider the CSMessage security provider to use.
	 * @param config the configuration of the parser.
	 * @throws MessageProcessingException if configuration contained bad configuration of security provider.
	 */
	void init(MessageSecurityProvider securityProvider, Properties config) throws MessageProcessingException;
	
	/**
	 * Method to parse a message into a CSMessage and verify that it fulfills the registred schemas.
	 * <p>
	 *     This method always validates and authorizes the signing certificate.
	 * </p>
	 * @param messageData the data to parse into a CSMessage
	 * @return a parsed CS Message object.
	 * 
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	CSMessage parseMessage(byte[] messageData)
			throws MessageContentException, MessageProcessingException;

	/**
	 * Method to parse a message into a CSMessage and verify that it fulfills the registred schemas.
	 * <p>
	 *     Signatures are required.
	 * </p>
	 *
	 * @param messageData the data to parse into a CSMessage
	 * @param performValidation true if the message security provider should perform
	 * validate that the signing certificate is valid and authorized for related organisation.
	 * Otherwise must validation be performed manually after the message is parsed.
	 * @return a parsed CS Message object.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	CSMessage parseMessage(byte[] messageData, boolean performValidation)
			throws MessageContentException, MessageProcessingException;

	/**
	 * Method to parse a message into a CSMessage and verify that it fulfills the registred schemas.
	 *
	 * @param messageData the data to parse into a CSMessage
	 * @param performValidation true if the message security provider should perform
	 * validate that the signing certificate is valid and authorized for related organisation.
	 * Otherwise must validation be performed manually after the message is parsed.
	 * @param requireSignature if signature should be required.
	 * @return a parsed CS Message object.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	CSMessage parseMessage(byte[] messageData, boolean performValidation, boolean requireSignature)
			throws MessageContentException, MessageProcessingException;

	/**
	 * Method to parse a message into a CSMessage and verify that it fulfills the registred schemas.
	 * <p>
	 *     This method always validates and authorizes the signing certificate.
	 * </p>
	 * @param  doc The Document data to parse into a CSMessage
	 * @return a parsed CS Message object.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	CSMessage parseMessage(Document doc)
			throws MessageContentException, MessageProcessingException;

	/**
	 * Method to parse a message into a CSMessage and verify that it fulfills the registred schemas.
	 * <p>
	 *     Signatures are required.
	 * </p>
	 * @param doc The Document data to parse into a CSMessage
	 * @param performValidation true if the message security provider should perform
	 * validate that the signing certificate is valid and authorized for related organisation.
	 * Otherwise must validation be performed manually after the message is parsed.
	 * @return a parsed CS Message object.
	 * 
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	CSMessage parseMessage(Document doc, boolean performValidation)
			throws MessageContentException, MessageProcessingException;

	/**
	 * Method to parse a message into a CSMessage and verify that it fulfills the registred schemas.
	 * <p>
	 *     Signatures are required.
	 * </p>
	 * @param doc The Document data to parse into a CSMessage
	 * @param performValidation true if the message security provider should perform
	 * validate that the signing certificate is valid and authorized for related organisation.
	 * Otherwise must validation be performed manually after the message is parsed.
	 * @param requireSignature if signature should be required.
	 * @return a parsed CS Message object.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	CSMessage parseMessage(Document doc, boolean performValidation, boolean requireSignature)
			throws MessageContentException, MessageProcessingException;
	
	/**
	 * Method used to generate a CS Request message without any originator, i.e the signer of this message is the originator.
	 * 
	 * @param requestId id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param organisation the related organisation (short name)
	 * @param payLoadVersion version of the pay load structure.
	 * @param payload the pay load object 
	 * @param assertions a list of authorization assertions or null if no assertions should be inserted.
	 * @return a generated and signed (if configured) message. 
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	byte[] generateCSRequestMessage(String requestId, String destinationId, String organisation, String payLoadVersion, Object payload, List<Object> assertions)  throws MessageContentException, MessageProcessingException;
	
	
	/**
	 * Method used to generate a CS Request message with any originator, used with relying a request message from another system.
	 * 
	 * @param requestId id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param organisation the related organisation (short name)
	 * @param payLoadVersion version of the pay load structure.
	 * @param payload the payload object 
	 * @param originator the credential of the original requester.
	 * @param assertions a list of authorization assertions or null if no assertions should be inserted.
	 * @return a generated and signed (if configured) message. 
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	byte[] generateCSRequestMessage(String requestId, String destinationId, String organisation, String payLoadVersion, Object payload, Credential originator, List<Object> assertions)  throws MessageContentException, MessageProcessingException;
	
	
	/**
	 * Method that populates all fields except the signature of a CS message.
	 * 
	 * @param version, version of the CS Message
	 * @param payLoadVersion, version of the pay load structure.
	 * @param requestName the name in the a related request if this is a response message, or null if no related request exists
	 * @param messageId the id of the message, if null is a random id generated.
	 * @param destinationID the destination Id to use.
	 * @param organisation the related organisation
	 * @param originator the originator of the message if applicable.
	 * @param payload the payload object to set in the object
	 * @param assertions a list of authorization assertions used along with this message.
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	CSMessage genCSMessage(String version, String payLoadVersion, String requestName, String messageId, String destinationID, String organisation, Credential originator, Object payload, List<Object> assertions) throws MessageContentException, MessageProcessingException;
	
	/**
	 * Method to generate a CS Respone message from a request. CS Response message will be marked as non forwardable, which means not for use in data syncronization applications.
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request 
	 * @param payLoadVersion version of the pay load structure.
	 * @param payload the payload object 
	 * @return  a generated and signed (if configured) message.
	 *  
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	CSMessageResponseData generateCSResponseMessage(String relatedEndEntity, CSMessage request, String payLoadVersion, Object payload) throws MessageContentException, MessageProcessingException;
	
	/**
	 * Method to generate a CS Respone message from a request.
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request 
	 * @param payLoadVersion version of the pay load structure.
	 * @param payload the payload object 
	 * @param isForwarable if message will be marked as non forwardable, i.e. for use in data syncronization applications.
	 * @return  a generated and signed (if configured) message.
	 *  
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	CSMessageResponseData generateCSResponseMessage(String relatedEndEntity, CSMessage request, String payLoadVersion, Object payload, boolean isForwarable) throws MessageContentException, MessageProcessingException;
	
	
	/**
	 * Method generate a Get Approval Request, 
	 * 
	 * @param requestId  id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param organisation the related organisation (short name)
	 * @param requestMessage the request message to get approval for.
	 * @param originator the credential of the original requester, null if this is the origin of the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *  
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	byte[] generateGetApprovalRequest(String requestId, String destinationId, String organisation, byte[] requestMessage, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException;
	
	/**
	 * Method generate a Is Approved Request, 
	 * 
	 * @param requestId  id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param organisation the related organisation (short name)
	 * @param approvalId the approval id to check.
	 * @param originator the credential of the original requester, null if this is the origin of the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *  
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	byte[] generateIsApprovedRequest(String requestId, String destinationId, String organisation, String approvalId, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException;
	
	/**
	 * Method generate a Is Approved Response, 
	 *
	 * @param relatedEndEntity the user name of related user in system.
	 * @param request the request data.
	 * @param approvalStatus the status of the related approval Id.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *  
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	CSMessageResponseData generateIsApprovedResponse(String relatedEndEntity, CSMessage request, ApprovalStatus approvalStatus, List<Object> assertions) throws MessageContentException, MessageProcessingException;
	
	/**
	 * Method generate a Get Approved Response, 
	 *
	 * @param relatedEndEntity the user name of related user in system.
	 * @param request the request data.
	 * @param approvalId the approval id that was generated for the request
	 * @param approvalStatus the approval status
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *  
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	CSMessageResponseData generateGetApprovalResponse(String relatedEndEntity, CSMessage request, String approvalId, ApprovalStatus approvalStatus, List<Object> assertions) throws MessageContentException, MessageProcessingException;

	/**
	 * Method generate a Ping Request,
	 *
	 * @param requestId  id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param organisation the related organisation (short name).
	 * @param originator the credential of the original requester, null if this is the origin of the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	byte[] generatePingRequest(String requestId, String destinationId, String organisation, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException;

	/**
	 * Method to generate a Ping Response.
	 *
	 * @param request the request data.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return a generated and signed (if configured) message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	CSMessageResponseData generatePingResponse(CSMessage request, List<Object> assertions) throws MessageContentException, MessageProcessingException;

	/**
	 * Method to add an originator and assertions to a CSMessage and add a signature. If signature exists it is removed.
	 *
	 * @param message the message to populate.
	 * @param destinationId the updated destination, null for unchanged.
	 * @param originator the originator to add, null for no originator
	 * @param assertions the assertions to add, null for no assertions.
	 * @return a populated and signed CSMessage.
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
     */
	byte[] populateOriginatorAssertionsAndSignCSMessage(CSMessage message, String destinationId, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException;

	/**
	 * Method to generate a failure message response to a given request.
	 * @param relatedEndEntity the user name of related user in system.
	 * @param request the request data.
	 * @param status the request status of the response
	 * @param failureMessage a readable failure message.
	 * @param destinationID the destination id of the message. If null will destination id be extracted from request data.
	 * @param originator originator of the request, null if no originator could be found.
	 * @return
	 * @throws MessageContentException, if no signer certificate was found and parser required it.
	 * @throws MessageProcessingException if internal error occurred parsing the certificate.
	 */
	CSMessageResponseData genCSFailureResponse(String relatedEndEntity,byte[] request, RequestStatus status,
			String failureMessage, String destinationID, Credential originator) throws MessageContentException,
			MessageProcessingException;
	
	/**
	 * Fetches the signing certificate from the request.
	 * 
	 * @param request the request to parse the certificate from.
	 * @return the signer certificate of null if no certificate is required by the parser.
	 * @throws MessageContentException, if no signer certificate was found and parser required it.
	 * @throws MessageProcessingException if internal error occurred parsing the certificate.
	 */
	X509Certificate getSigningCertificate(byte[] request) throws MessageContentException, MessageProcessingException;

	/**
	 * Method that generates the signature and marshalls the message to byte array in UTF-8 format.
	 * @param csMessage the CSMessage to sign and marshall, never null.
	 * @return a marshalled and signed message.
	 * @throws MessageProcessingException if problems occurred when processing the message.
	 */
	byte[] marshallAndSignCSMessage(CSMessage csMessage) throws MessageProcessingException, MessageContentException;

	/**
	 * Method that marshalls the message to byte array in UTF-8 format without adding any signature.
	 * @param csMessage the CSMessage to marshall, never null.
	 * @return a marshalled message.
	 * @throws MessageProcessingException if problems occurred when processing the message.
	 */
	byte[] marshallCSMessage(CSMessage csMessage) throws MessageProcessingException, MessageContentException;


	/**
	 * Method to validate a payload object separately, used for special cases such when validating GetApprovalRequest requestData etc.
	 * 
	 * @param version the versions of a CS message.
	 * @param payLoadObject the pay load object to validate schema for.
	 * 
	 * @throws MessageProcessingException
	 * @throws MessageContentException if the message contained invalid XML.
	 */
    void validatePayloadObject(CSMessageVersion version, Object payLoadObject) throws MessageContentException;
    
    /**
     * Method that tries to parse the xml version from a message
     * @param messageData the messageData to extract version from.
     * @return the version in the version and payLoadVersion attributes of the message.
     * @throws MessageContentException didn't contains a valid version attribute.
     * @throws MessageProcessingException if internal problems occurred.
     */
    CSMessageVersion getVersionFromMessage(byte[] messageData) throws MessageContentException, MessageProcessingException;

    /**
     * Method to extract the originator credential from a message.
     * 
     * @param request the request message to extract the originator from.
     * @return the originator credential from the message or null if no originator was found.
     */
    Credential getOriginatorFromRequest(CSMessage request);
    
    /**
     * Help method to return the related message security provider.
     * 
     * @return the related message security provider, never null.
     */
    MessageSecurityProvider getMessageSecurityProvider();
    
    /**
     * Method that fetches the related marshaller for a given message.
     * 
     * @param message the message to fetch related marshaller for.
     * @return the marshaller
     * @throws MessageContentException if message content was faulty or no related marshaller could be found.
     * @throws MessageProcessingException if internal error occurred processing the message.
     */
    Marshaller getMarshaller(CSMessage message) throws MessageContentException, MessageProcessingException;
    
    

}
