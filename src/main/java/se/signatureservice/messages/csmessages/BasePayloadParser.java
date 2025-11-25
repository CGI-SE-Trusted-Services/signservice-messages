/**
 * 
 */
package se.signatureservice.messages.csmessages;

import java.util.List;
import java.util.Properties;

import jakarta.xml.bind.JAXBElement;

import se.signatureservice.messages.MessageContentException;
import se.signatureservice.messages.MessageProcessingException;
import se.signatureservice.messages.MessageSecurityProvider;
import se.signatureservice.messages.csmessages.jaxb.CSMessage;
import se.signatureservice.messages.csmessages.jaxb.CSResponse;
import se.signatureservice.messages.csmessages.jaxb.Credential;
import se.signatureservice.messages.csmessages.jaxb.IsApprovedResponseType;
import se.signatureservice.messages.csmessages.jaxb.ObjectFactory;
import se.signatureservice.messages.csmessages.jaxb.RequestStatus;

/**
 * Base implementation of a PayLoadParser that other implementations might inherit.
 * 
 * @author Philip Vendil
 *
 */
public abstract class BasePayloadParser implements PayloadParser {
	

	protected Properties config;
	protected MessageSecurityProvider secProv;
	protected CSMessageParser customCSMessageParser;
	
	protected ObjectFactory csMessageObjectFactory = new ObjectFactory();

	protected String payloadVersion = getDefaultPayloadVersion();
	
	/**
	 * Default initializer setting the parser and config properties.
	 * 
	 * @see PayloadParser#init(java.util.Properties, MessageSecurityProvider)
	 */
	public void init(Properties config, MessageSecurityProvider secProv)
			throws MessageProcessingException {
		this.config = config;
		this.secProv = secProv;
	}

	/**
	 * Alternativ initializer setting the parser and config properties and custom CSMessageParser.
	 * Usen mainly during testing.
	 *
	 * @see PayloadParser#init(java.util.Properties, MessageSecurityProvider)
	 */
	public void init(Properties config, MessageSecurityProvider secProv, CSMessageParser customCSMessageParser)
			throws MessageProcessingException {
		this.config = config;
		this.secProv = secProv;
		this.customCSMessageParser = customCSMessageParser;
	}

	protected CSMessageParser getCSMessageParser() throws MessageProcessingException {
		if(customCSMessageParser != null){
			return customCSMessageParser;
		}
		return CSMessageParserManager.getCSMessageParser();
	}

	/**
	 * Method to parse a message into a CSMessage and verify that it fulfills the registred schemas.
	 * <p>
	 * This method will parse all registered payloads and not only sys config payload messages.
	 * <p>
	 *     This method always validates and authorizes the signing certificate.
	 * </p>
	 * @param messageData the data to parse into a CSMessage
	 * @return a parsed CS Message object.
	 * 
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
    public CSMessage parseMessage(byte[] messageData) throws MessageContentException, MessageProcessingException{
    	return getCSMessageParser().parseMessage(messageData);
    }

	/**
	 * Method to parse a message into a CSMessage and verify that it fulfills the registred schemas.
	 * <p>
	 * This method will parse all registered payloads and not only sys config payload messages.
	 *
	 * @param messageData the data to parse into a CSMessage
	 * @param performValidation true if the message security provider should perform
	 * validate that the signing certificate is valid and authorized for related organisation.
	 * Otherwise must validation be performed manually after the message is parsed
	 * @return a parsed CS Message object.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public CSMessage parseMessage(byte[] messageData, boolean performValidation) throws MessageContentException, MessageProcessingException{
		return getCSMessageParser().parseMessage(messageData, performValidation);
	}

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
	public CSMessage parseMessage(byte[] messageData, boolean performValidation, boolean requireSignature)
			throws MessageContentException, MessageProcessingException{
		return getCSMessageParser().parseMessage(messageData, performValidation, requireSignature);
	}
    /**
     * Help method to get the request status from a CS response message.
     * @param csMessage containing a CS response message.
     * @return the request status.
     * 
     * @throws MessageContentException if message content was illegal.
     */
    @SuppressWarnings("unchecked")
	public RequestStatus getResponseStatus(CSMessage csMessage) throws MessageContentException{
    	try{
    	Object responsePayload =  csMessage.getPayload().getAny();
    	if(responsePayload instanceof JAXBElement<?> && ((JAXBElement<?>) responsePayload).getValue() instanceof CSResponse){
    		return ((JAXBElement<CSResponse>) responsePayload).getValue().getStatus();
    	}
    	if(responsePayload instanceof CSResponse){
    		return ((CSResponse) responsePayload).getStatus();
    	}
    	}catch(Exception e){
    		throw new MessageContentException("Error parsing CSResponse status from message: " + e.getMessage(),e);
    	}
    	throw new MessageContentException("Error parsing CSResponse status from message, make sure it is a CSResponse.");
    }
    
    /**
     * Help method to get the payload of a message.
     * @param csMessage containing a CS message payload.
     * @return the payload object
     * 
     * @throws MessageContentException if message content was illegal.
     */
	public Object getPayload(CSMessage csMessage) throws MessageContentException{
    	try{
    		Object responsePayload =  csMessage.getPayload().getAny();
    		if(responsePayload instanceof JAXBElement<?>){
    			return ((JAXBElement<?>) csMessage.getPayload().getAny()).getValue();
    		}
    	    return responsePayload;
    	}catch(Exception e){
    		throw new MessageContentException("Error parsing payload from message: " + e.getMessage(),e);
    	}
    }
	
	/**
	 * Help method to retrieve the assertions from an approved IsApprovedResponseType payload
	 * 
	 * @param isApprovedResponse the payload if a IsApprovedResponse or GetApprovedResponse
	 * @return the list of assertions or null if no assertions could be found.
	 */
	public List<Object> getAssertions(IsApprovedResponseType isApprovedResponse){
		if(isApprovedResponse.getAssertions() != null && isApprovedResponse.getAssertions().size() > 0){
			return isApprovedResponse.getAssertions().get(0).getAny();
		}
		
		return null;
	}
	
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
	public byte[] generateGetApprovalRequest(String requestId, String destinationId, String organisation, byte[] requestMessage, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		return getCSMessageParser().generateGetApprovalRequest(requestId, destinationId, organisation, requestMessage, originator, assertions);
	}
	
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
	public byte[] generateIsApprovedRequest(String requestId, String destinationId, String organisation, String approvalId, Credential originator, List<Object> assertions) throws MessageContentException, MessageProcessingException{
		return getCSMessageParser().generateIsApprovedRequest(requestId, destinationId, organisation, approvalId, originator, assertions);
	}
	
	
    /**
     * 
     * @return an array of version numbers of payload that is supported by this parser.
     */
	protected abstract String[] getSupportedVersions();
	
	/**
	 * 
	 * @return returns the payload version used by default when generating request messages.
	 */
	protected abstract String getDefaultPayloadVersion();
	
	/**
	 * Help method to determine if a payload version is supported by this parser.
	 * 
	 * @param payloadVersion the payload parser to check.
	 * @throws MessageContentException if unsupported version was found.
	 */
	protected void isPayloadVersionSupported(String payloadVersion) throws MessageContentException{
		for(String supportedVersion : getSupportedVersions()){
			if(supportedVersion.equals(payloadVersion)){
				return;
			}
		}
		throw new MessageContentException("Unsupported Payload version: " + payloadVersion + " for PayLoadParser " + this.getClass().getSimpleName());
	}

	/**
	 *
	 * @return Method to get the current payload version used when generating request messages.
	 * Response messages always use the same version as the request.
	 */
	public String getPayloadVersion(){
		return payloadVersion;
	}

	/**
	 * Method that only should be used under special purposes when generating request message, normally should default
	 * payload version be used that is set automatically.
	 * Response messages always use the same version as the request.
	 *
	 * @param payloadVersion method to set the payload version to use instead of the default one.
	 */
	public void setPayloadVersion(String payloadVersion){
		this.payloadVersion = payloadVersion;
	}


	/**
	 * Method that should return related schemas used during payload schema validation.
	 * @param payloadVersion payload version.
	 * @return an array of related schemas if no related schemas exists is empty array returned, never null.
	 */
	public String[] getRelatedSchemas(String payloadVersion){
		return new String[0];
	}
}
