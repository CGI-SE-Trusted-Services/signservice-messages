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

import org.certificateservices.messages.*;
import org.certificateservices.messages.credmanagement.CredManagementPayloadParser;
import org.certificateservices.messages.credmanagement.jaxb.FieldValue;
import org.certificateservices.messages.csmessages.BasePayloadParser;
import org.certificateservices.messages.csmessages.DefaultCSMessageParser;
import org.certificateservices.messages.csmessages.XSDLSInput;
import org.certificateservices.messages.csmessages.jaxb.Approver;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.saml2.BaseSAMLMessageParser;
import org.certificateservices.messages.saml2.assertion.SAMLAssertionMessageParser;
import org.certificateservices.messages.saml2.assertion.jaxb.*;
import org.certificateservices.messages.saml2.protocol.jaxb.AttributeQueryType;
import org.certificateservices.messages.saml2.protocol.jaxb.ResponseType;
import org.certificateservices.messages.saml2.protocol.jaxb.StatusCodeType;
import org.certificateservices.messages.saml2.protocol.jaxb.StatusType;
import org.certificateservices.messages.utils.*;
import org.certificateservices.messages.xenc.jaxb.EncryptedDataType;
import org.w3c.dom.Document;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.bind.*;
import javax.xml.bind.util.JAXBSource;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;

/**
 * Assertion Payload Parser used to parse and generate Assertion Tickets such as:
 * 
 * <li>Distributed Authorization Ticket
 * <li>User Data Ticket
 * <li>Approval Ticket
 * <p>
 * Uses SAML Core 2.0 and SAMLP 2.0 as underlying message structures.
 * 
 * @author Philip Vendil
 *
 */
public class AssertionPayloadParser extends BasePayloadParser {
	
	public static String NAMESPACE = "urn:oasis:names:tc:SAML:2.0:assertion";
	public static String SAMLP_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:protocol";
	
	public static String ANY_DESTINATION = "ANY";
	
	private static final String ASSERTION_XSD_SCHEMA_2_0_RESOURCE_LOCATION = "/cs-message-saml-schema-assertion-2.0.xsd";
	private static final String SAMLP_XSD_SCHEMA_2_0_RESOURCE_LOCATION = "/cs-message-saml-schema-protocol-2.0.xsd";

	private ObjectFactory of = new ObjectFactory();
	private org.certificateservices.messages.saml2.protocol.jaxb.ObjectFactory samlpOf = new org.certificateservices.messages.saml2.protocol.jaxb.ObjectFactory();
	
	private static final String[] SUPPORTED_ASSERTION_VERSIONS = {"2.0"};
	
	private static final String DEFAULT_ASSERTION_VERSION = "2.0";

    public static final String ATTRIBUTE_NAME_TYPE = "Type";
	public static final String ATTRIBUTE_NAME_DISPLAYNAME = "DisplayName";
	public static final String ATTRIBUTE_NAME_ROLES = "Roles";
	public static final String ATTRIBUTE_NAME_DEPARTMENTS = "Departments";
	public static final String ATTRIBUTE_NAME_USERDATA = "UserData";
	public static final String ATTRIBUTE_NAME_TOKENTYPE = "TokenType";
	public static final String ATTRIBUTE_NAME_DESTINATIONID = "DestinationId";
	public static final String ATTRIBUTE_NAME_APPROVALID = "ApprovalId";
	public static final String ATTRIBUTE_NAME_APPROVEDREQUESTS = "ApprovedRequests";
	public static final String ATTRIBUTE_NAME_APPROVERS = "Approvers";

	public static final String ALL_DEPARTMENTS_ATTRIBUTE_VALUE = "ALL_DEPARTMENTS";
	

	private SystemTime systemTime = new DefaultSystemTime();
	private XMLEncrypter xmlEncrypter;
	private XMLEncrypter userDataXmlEncrypter;
	private BaseSAMLMessageParser.EncryptedAttributeXMLConverter encryptedAttributeXMLConverter = new BaseSAMLMessageParser.EncryptedAttributeXMLConverter();
	private XMLSigner xmlSigner;
	private CertificateFactory cf;
	
	private Validator assertionSchemaValidator;
	private SAMLAssertionMessageParser samlAssertionMessageParser = new SAMLAssertionMessageParser();
	
	private BaseSAMLMessageParser.AssertionSignatureLocationFinder assertionSignatureLocationFinder = new BaseSAMLMessageParser.AssertionSignatureLocationFinder();

	@Override
	public void init(Properties config, MessageSecurityProvider secProv)
			throws MessageProcessingException {
		super.init(config, secProv);
		try {
			xmlEncrypter = new XMLEncrypter(secProv, getDocumentBuilder(), getAssertionMarshaller(), getAssertionUnmarshaller());
			userDataXmlEncrypter = new XMLEncrypter(secProv, getDocumentBuilder(), getUserDataMarshaller(), getUserDataUnmarshaller());
			xmlSigner = new XMLSigner(secProv,getDocumentBuilder(), true, assertionSignatureLocationFinder, new CSMessageOrganisationLookup());
			cf = CertificateFactory.getInstance("X.509");
			
			assertionSchemaValidator = generateUserDataSchema().newValidator();
			samlAssertionMessageParser.init(secProv, null);
		} catch (Exception e) {
			throw new MessageProcessingException("Error initializing JAXB in AssertionPayloadParser: " + e.getMessage(),e);
		}
	}

	/**
	 * @see org.certificateservices.messages.csmessages.PayloadParser#getNameSpace()
	 */
	public String getNameSpace() {
		return NAMESPACE;
	}

	/**
	 * @see org.certificateservices.messages.csmessages.PayloadParser#getJAXBPackage()
	 */
	public String getJAXBPackage() {
		return "org.certificateservices.messages.saml2.assertion.jaxb";
	}

	/**
	 * @see org.certificateservices.messages.csmessages.PayloadParser#getSchemaAsInputStream(java.lang.String)
	 */
	public InputStream getSchemaAsInputStream(String payLoadVersion)
			throws MessageContentException, MessageProcessingException {
    	if(payLoadVersion.equals("2.0")){
    		return getClass().getResourceAsStream(ASSERTION_XSD_SCHEMA_2_0_RESOURCE_LOCATION);
    	}
    	
    	throw new MessageContentException("Error unsupported Assertion version: " + payLoadVersion);
	}

	@Override
	protected String[] getSupportedVersions() {
		return SUPPORTED_ASSERTION_VERSIONS;
	}

	@Override
	protected String getDefaultPayloadVersion() {
		return DEFAULT_ASSERTION_VERSION;
	}
	
	/**
	 * Method to validate a JAXB Object against Assertion Schema.
	 */
	public void schemaValidateAssertion(Object assertion) throws MessageContentException{
		 try {
			assertionSchemaValidator.validate(new JAXBSource(getUserDataJAXBContext(),assertion));
		} catch (Exception e) {
			throw new MessageContentException("Error validating Assertion agains schema: " + e.getMessage(),e);
		}
	}
	
	/**
	 * Method to generate a Role Attribute Query message (Distributed Authorization Request) for given subject.
	 * <p>
	 * This method will generate an unsigned SAMLP Attribute Query Message
	 * 
	 * @param subjectId The unique id of the user to look-up, could be UPN or SAM account name depending on implementation.
	 * @return a generated SAMLP Attribute Query Message
	 * @throws MessageContentException if given parameters where invalid
	 * @throws MessageProcessingException if internal error occurred generating the message.
	 */
	public byte[] genDistributedAuthorizationRequest(String subjectId) throws MessageContentException, MessageProcessingException{
		return genAttributeQuery(subjectId, ATTRIBUTE_NAME_ROLES, null);
	}
	
	/**
	 * Method to generate a User Data Attribute Query message (User Data Request) for given subject.
	 * <p>
	 * This method will generate an unsigned SAMLP Attribute Query Message
	 * 
	 * @param subjectId The unique id of the user to look-up, could be UPN or SAM account name depending on implementation.
	 * @param tokenType token type of the related user data (optional)
	 * @return a generated SAMLP Attribute Query Message
	 * @throws MessageContentException if given parameters where invalid
	 * @throws MessageProcessingException if internal error occurred generating the message.
	 */
	public byte[] genUserDataRequest(String subjectId, String tokenType) throws MessageContentException, MessageProcessingException{
		return genAttributeQuery(subjectId, ATTRIBUTE_NAME_USERDATA, tokenType);
	}

	public byte[] genDistributedAuthorizationTicket(String inResponseTo, String issuer, Date notBefore, Date notOnOrAfter, String subjectId, List<String> roles, List<X509Certificate> receipients) throws MessageContentException, MessageProcessingException{
		return  genDistributedAuthorizationTicket(inResponseTo,issuer,notBefore,notOnOrAfter,subjectId,roles,null, receipients);
	}
	
	/**
	 * Method to generate a Distributed Authorization Ticket with an signed assertion containing the 
	 * subjects Roles encrypted enveloped into a successful SAMLP Response.
	 * 
	 * @param inResponseTo The ID of the attribute query request
	 * @param issuer the issuer of the assertion.
	 * @param notBefore beginning of the validity of the ticket.
	 * @param notOnOrAfter end validity of the ticket.
	 * @param subjectId the subject id string having the roles.
	 * @param roles a list of roles the user has.
	 * @param departments a list of departments the user belongs to, null for no departments attribute.
	 * @param receipients list of certificates the roles will be encrypted for.
	 * @return a generated and signed SAMLP message.
	 * @throws MessageContentException if parameters where invalid.
	 * @throws MessageProcessingException if internal problems occurred generated the message.
	 */
	public byte[] genDistributedAuthorizationTicket(String inResponseTo, String issuer, Date notBefore, Date notOnOrAfter, String subjectId, List<String> roles, List<String> departments,List<X509Certificate> receipients) throws MessageContentException, MessageProcessingException{
		try{
			List<Object> attributes = new ArrayList<Object>();
			AttributeType typeAttributeType = of.createAttributeType();
			typeAttributeType.setName(ATTRIBUTE_NAME_TYPE);
			typeAttributeType.getAttributeValue().add(AssertionTypeEnum.AUTHORIZATION_TICKET.getAttributeValue());
			attributes.add(typeAttributeType);

			attributes.add(createEncryptedAttribute(ATTRIBUTE_NAME_ROLES, roles, receipients));
			if(departments != null) {
				attributes.add(createEncryptedAttribute(ATTRIBUTE_NAME_DEPARTMENTS, departments, receipients));
			}
			return marshallAndSignAssertion(genSuccessfulSAMLPResponse(inResponseTo, generateAssertion(issuer, notBefore, notOnOrAfter, subjectId, attributes)));

		}catch(Exception e){
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageProcessingException("Error generation DistributedAuthorizationTicket: " + e.getMessage(),e);
		}
	}
	
	/**
	 * Method to generate a User Data Ticket with an signed assertion containing the 
	 * token request data encrypted enveloped into a successful SAMLP Response.
	 * 
	 * @param inResponseTo The ID of the attribute query request
	 * @param issuer the issuer of the assertion.
	 * @param notBefore beginning of the validity of the ticket.
	 * @param notOnOrAfter end validity of the ticket.
	 * @param subjectId the subject id string having the roles.
	 * @param tokenType the related token type associated with the user data. Unencrypted (optional, use null not to set this attribute).
	 * @param displayName unencrypted display name of the related user (optional, use null not to set this attribute).
	 * @param fieldValues list of field values that will be encrypted as UserData attribute.
	 * @param receipients list of certificates the roles will be encrypted for.
	 * @return a generated and signed SAMLP message.
	 * @throws MessageContentException if parameters where invalid.
	 * @throws MessageProcessingException if internal problems occurred generated the message.
	 */
	public byte[] genUserDataTicket(String inResponseTo, String issuer, Date notBefore, Date notOnOrAfter, String subjectId, String displayName, String tokenType, List<FieldValue> fieldValues, List<X509Certificate> receipients) throws MessageContentException, MessageProcessingException{
		try{
			List<Object> attributes = new ArrayList<Object>();
			
			AttributeType typeAttributeType = of.createAttributeType();
			typeAttributeType.setName(ATTRIBUTE_NAME_TYPE);
			typeAttributeType.getAttributeValue().add(AssertionTypeEnum.USER_DATA.getAttributeValue());
			attributes.add(typeAttributeType);
			
			if(displayName != null){
				AttributeType displayNameAttributeType = of.createAttributeType();
				displayNameAttributeType.setName(ATTRIBUTE_NAME_DISPLAYNAME);
				displayNameAttributeType.getAttributeValue().add(displayName);
				
				attributes.add(displayNameAttributeType);
			}
			
			if(tokenType != null){
				AttributeType tokenTypeAttributeType = of.createAttributeType();
				tokenTypeAttributeType.setName(ATTRIBUTE_NAME_TOKENTYPE);
				tokenTypeAttributeType.getAttributeValue().add(tokenType);
				
				attributes.add(tokenTypeAttributeType);
			}
			

			AttributeType userDataAttributeType = of.createAttributeType();
			userDataAttributeType.setName(ATTRIBUTE_NAME_USERDATA);
			for(FieldValue fieldValue : fieldValues){		
				userDataAttributeType.getAttributeValue().add(fieldValue);
			}
			JAXBElement<AttributeType> userDataAttribute = of.createAttribute(userDataAttributeType);
			
			@SuppressWarnings("unchecked")
			JAXBElement<EncryptedDataType> encryptedData = (JAXBElement<EncryptedDataType>) getAssertionUnmarshaller().unmarshal(userDataXmlEncrypter.encryptElement(userDataAttribute, receipients, true));
		    EncryptedElementType encryptedElementType1 = of.createEncryptedElementType();
			encryptedElementType1.setEncryptedData(encryptedData.getValue());
			
			attributes.add(encryptedElementType1);
			
			return marshallAndSignAssertion(genSuccessfulSAMLPResponse(inResponseTo, generateAssertion(issuer, notBefore, notOnOrAfter, subjectId, attributes)));

		}catch(Exception e){
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageProcessingException("Error generation DistributedAuthorizationTicket: " + e.getMessage(),e);
		}
	}
	
	/**
	 * Method to generate a Approval Ticket with an signed assertion containing the 
	 * approval id and related Approval Requests
	 *
	 * @param issuer the issuer of the assertion.
	 * @param notBefore beginning of the validity of the ticket.
	 * @param notOnOrAfter end validity of the ticket.
	 * @param subjectId the subject id string having the approval.
	 * @param approvalId  the request unique approval id
	 * @param approvalRequests containing one or more AttributeValue with the digest values of the calculated request actions. 
	 * It’s up to the approval workflow engine to to determine how the digest is calculated from an approval request and how to verify that subsequent 
	 * request matches the given approval.
	 * @param destinationId the id to the target system processing the ticket. null for ANY destination.
	 * @param approvers if encrypted approver data should be included, used to send information about an approval to more sensitive inner systems for audit purposes.
	 * @param receipients receiptents of the encrypted approvers data. null if approvers is null.
	 * @return a generated and signed SAMLP message.
	 * @throws MessageContentException if parameters where invalid.
	 * @throws MessageProcessingException if internal problems occurred generated the message.
	 */
	public byte[] genApprovalTicket(String issuer, Date notBefore, Date notOnOrAfter, String subjectId, String approvalId, List<String> approvalRequests, String destinationId, List<Approver> approvers, List<X509Certificate> receipients) throws MessageContentException, MessageProcessingException{
		try{
			List<Object> attributes = new ArrayList<Object>();
			
			AttributeType typeAttributeType = of.createAttributeType();
			typeAttributeType.setName(ATTRIBUTE_NAME_TYPE);
			typeAttributeType.getAttributeValue().add(AssertionTypeEnum.APPROVAL_TICKET.getAttributeValue());
			attributes.add(typeAttributeType);
			
			AttributeType destAttributeType = of.createAttributeType();
			destAttributeType.setName(ATTRIBUTE_NAME_DESTINATIONID);
			destAttributeType.getAttributeValue().add((destinationId != null ? destinationId : ANY_DESTINATION));
			attributes.add(destAttributeType);
			
			AttributeType approvalIdAttributeType = of.createAttributeType();
			approvalIdAttributeType.setName(ATTRIBUTE_NAME_APPROVALID);
			approvalIdAttributeType.getAttributeValue().add(approvalId);
			attributes.add(approvalIdAttributeType);

			AttributeType approvalRequestAttributeType = of.createAttributeType();
			approvalRequestAttributeType.setName(ATTRIBUTE_NAME_APPROVEDREQUESTS);
			for(String approvalRequest : approvalRequests){		
				approvalRequestAttributeType.getAttributeValue().add(approvalRequest);
			}
			attributes.add(approvalRequestAttributeType);
			
			if(approvers != null){
				AttributeType approversAttributeType = of.createAttributeType();
				approversAttributeType.setName(ATTRIBUTE_NAME_APPROVERS);
				for(Approver approver : approvers){		
					approversAttributeType.getAttributeValue().add(approver);
				}
				JAXBElement<AttributeType> approverAttribute = of.createAttribute(approversAttributeType);
				
				@SuppressWarnings("unchecked")
				JAXBElement<EncryptedDataType> encryptedData = (JAXBElement<EncryptedDataType>) getAssertionUnmarshaller().unmarshal(userDataXmlEncrypter.encryptElement(approverAttribute, receipients, true));
			    EncryptedElementType encryptedElementType1 = of.createEncryptedElementType();
				encryptedElementType1.setEncryptedData(encryptedData.getValue());
				
				attributes.add(encryptedElementType1);
			}
			
			return marshallAndSignAssertion(generateAssertion(issuer, notBefore, notOnOrAfter, subjectId, attributes));

		}catch(Exception e){
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageProcessingException("Error generation DistributedAuthorizationTicket: " + e.getMessage(),e);
		}
	}
	
	/**
	 * Method to generate a failure message to a attribute query message.
	 * @param inResponseTo the ID of the attribute query
	 * @param statusCode the failure code to respond to
	 * @param failureMessage a descriptive failure message, may be null.
	 * @return a SAMLP failure message.
	 * @throws MessageContentException if parameters where invalid.
	 * @throws MessageProcessingException if internal problems occurred generated the message.
	 */
	public byte[] genFailureMessage(String inResponseTo, ResponseStatusCodes statusCode, String failureMessage) throws MessageContentException, MessageProcessingException{
		try{
			StatusCodeType statusCodeType = samlpOf.createStatusCodeType();
			statusCodeType.setValue(statusCode.getURIValue());
			
			StatusType statusType = samlpOf.createStatusType();
			statusType.setStatusCode(statusCodeType);
			
			if(failureMessage != null){
			  statusType.setStatusMessage(failureMessage);
			}

			ResponseType responseType = samlpOf.createResponseType();
			responseType.setID("_" + MessageGenerateUtils.generateRandomUUID());
			responseType.setIssueInstant(MessageGenerateUtils.dateToXMLGregorianCalendar(systemTime.getSystemTime()));
			responseType.setVersion(DEFAULT_ASSERTION_VERSION);
			responseType.setInResponseTo(inResponseTo);
			responseType.setStatus(statusType);
			
			return marshall(samlpOf.createResponse(responseType));	
		}catch(Exception e){
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageProcessingException("Error generation DistributedAuthorizationTicket: " + e.getMessage(),e);
		}
	}
	
	
	
	/**
	 * Method to parse a response of a attribute query.
	 * 
	 * <b>Important, this method does not verify the signature of any included assertions, only parses the message.
	 * 
	 * @param response the attribute query response
	 * @return a parsed attirbute query response.
	 * @throws MessageContentException if response message data was invalid.
	 * @throws MessageProcessingException if internal problems occurred generated the message.
	 */
	public ResponseType parseAttributeQueryResponse(byte[] response) throws MessageContentException, MessageProcessingException{
		
		try {
			@SuppressWarnings("unchecked")
			JAXBElement<ResponseType> resp = (JAXBElement<ResponseType>) getUserDataUnmarshaller().unmarshal(new ByteArrayInputStream(response));
			return resp.getValue();
		} catch (Exception e) {

			throw new MessageContentException("Error parsing Attribute Query Response Data: " + e.getMessage(),e);
		}	
	}
	
	/**
	 * Method to parse and verify approval ticket
	 * <p>
	 * This method does the following checks:
	 * 
	 * <li>Verifies the signature of the assertion
	 * <li>XML data against XSD
	 * <li>Checks that the before and notafter dates are valid.
	 * <p>
	 * <b>Important this method doesn't check if the signature certificate is trusted to generate tickets, this have to be done manually. To get the signature certificate
	 * use the getAssertionSigner() help method.
	 * 
	 * @param response the attribute query response
	 * @return a parsed attirbute query response.
	 * @throws MessageContentException if response message data was invalid.
	 * @throws MessageProcessingException if internal problems occurred generated the message.
	 */
	public JAXBElement<AssertionType> parseApprovalTicket(byte[] response) throws MessageContentException, MessageProcessingException{
		
		try {
			xmlSigner.verifyEnvelopedSignature(response);
			@SuppressWarnings("unchecked")
			JAXBElement<AssertionType> resp = (JAXBElement<AssertionType>) getUserDataUnmarshaller().unmarshal(new ByteArrayInputStream(response));
			AssertionType assertionType = resp.getValue();
			verifyAssertionConditions(assertionType);
			return of.createAssertion(assertionType);
		} catch (Exception e) {
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageContentException("Error parsing Attribute Query Response Data: " + e.getMessage(),e);
		}	
	}

	/**
	 * Help method to get the first signing certificate from a digital signature.
	 * @param assertion to extract certificate from.
	 * @return the first found certificate in assertion.
	 * @throws MessageContentException if response message data was invalid.
	 * @throws MessageProcessingException if internal problems occurred generated the message.
	 */
	public X509Certificate getCertificateFromAssertion(JAXBElement<AssertionType> assertion) throws MessageContentException, MessageProcessingException{
		return samlAssertionMessageParser.getCertificateFromAssertion(assertion);
	}
	
	/**
	 * Help method to extract a Assertion to be included in a CSMessasge from a response type
	 * 
	 * @param responseType the response type to extract from, never null.
	 * @return the first assertion type of null if no assertion was found.
	 */
	public JAXBElement<AssertionType> getAssertionFromResponseType(ResponseType responseType){
		if(responseType.getAssertionOrEncryptedAssertion().size() == 0){
			return null;
		}
		return (JAXBElement<AssertionType>) of.createAssertion((AssertionType) responseType.getAssertionOrEncryptedAssertion().get(0));
	}

	/**
	 * Method to return a list of valid assertions from CSMessage. (Expired assertions are filtered out)
	 * @param csmessage the message to fetch assertions from.
	 * @return a list of valid assertions, never null.
	 * @throws MessageProcessingException, MessageContentException 
	 */
	@SuppressWarnings("unchecked")
	public List<JAXBElement<AssertionType>> getAssertionsFromCSMessage(CSMessage csmessage) throws MessageProcessingException, MessageContentException{
		List<JAXBElement<AssertionType>> retval = new ArrayList<JAXBElement<AssertionType>>();
		if(csmessage.getAssertions() != null && csmessage.getAssertions().getAny() != null){
			for(Object next : csmessage.getAssertions().getAny()){
				JAXBElement<AssertionType> assertion = (JAXBElement<AssertionType>) next;
				try{
					verifyAssertionSignature(assertion);
					verifyAssertionConditions(assertion.getValue());
					retval.add(assertion);
				}catch(MessageContentException e){}
			}
		}
		
		return retval;
	}
	


	/**
	 * Help method to get type of assertion from AssertionType saml attribute.
	 * @param assertion the assertion to lookup type for.
	 * @return the assertion type.
	 * @throws MessageContentException if no assertion type could be found.
	 */
	public AssertionTypeEnum getTypeOfAssertion(JAXBElement<AssertionType> assertion) throws MessageContentException{
		try{
		for(Object o : assertion.getValue().getStatementOrAuthnStatementOrAuthzDecisionStatement()){
			if(o instanceof AttributeStatementType){
				for(Object attr : ((AttributeStatementType) o).getAttributeOrEncryptedAttribute()){
					if(attr instanceof AttributeType){
						if(((AttributeType) attr).getName().equals(ATTRIBUTE_NAME_TYPE)){
							String attributeValue = (String) ((AttributeType) attr).getAttributeValue().get(0);
							for(AssertionTypeEnum next : AssertionTypeEnum.values()){
								if(next.getAttributeValue().equals(attributeValue)){
									return next;
								}
							}
						}
					}
				}
			}
		}
		
		}catch(Exception e){
			throw new MessageContentException("Error determining type of assertion " + e.getMessage(), e);
		}
		
		throw new MessageContentException("Error no Attribute type could be determined from assertion");
	}


	/**
	 * Method to parse an attribute query into a more manageable data structure.
	 * @param attributeQuery the attribute query to parse.
	 * @return a parsed AttributeQueryData structure.
	 * @throws MessageContentException if illegal message content was found.
	 * @throws MessageProcessingException if internal problems occurred processing the message.
	 */
	public AttributeQueryData parseAttributeQuery(byte[] attributeQuery) throws MessageContentException, MessageProcessingException{
		try {
			@SuppressWarnings("unchecked")
			JAXBElement<AttributeQueryType> attrQuery = (JAXBElement<AttributeQueryType>) getUserDataUnmarshaller().unmarshal(new ByteArrayInputStream(attributeQuery));
			AttributeQueryData aqd = new AttributeQueryData();
			aqd.parse(attrQuery);
			return aqd;
		} catch (Exception e) {
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageContentException("Error parsing Attribute Query: " + e.getMessage(),e);
		}
	}

	/**
	 * Method to parse (but not decrypt encrypted attributes) an assertion, usually used by clients of approval tickets, where the approvers data 
	 * cannot be read since it's probably only intended for more sensitive systems.
	 * 
	 * This method is intended to be used by clients and not server systems.
	 * 
	 * @param assertions a list of assertions to parse, UserData and Authorization assertions are skipped and not included.
	 * @return parsed assertions, not all types of assertions i possible to parse without decryption such as authorization and user data tickets.
	 * @throws MessageContentException if content of message was invalid.
	 * @throws MessageProcessingException if internal problems occurred parsing the assertions.
	 */
	public List<AssertionData> parseAssertions(List<JAXBElement<AssertionType>> assertions) throws MessageContentException, MessageProcessingException{
		try {
			List<AssertionData> retval = new ArrayList<AssertionData>();
			for(JAXBElement<AssertionType> assertion: assertions){
				AssertionTypeEnum assertionType = getTypeOfAssertion(assertion);
				if(assertionType != AssertionTypeEnum.AUTHORIZATION_TICKET && assertionType != AssertionTypeEnum.USER_DATA){
					schemaValidateAssertion(assertion);
					AssertionData ad = (AssertionData) assertionType.getAssertionDataClass().getConstructor(AssertionPayloadParser.class).newInstance(this);
					ad.parse(assertion);
					retval.add(ad);
				}
			}
			
			return retval;
		}  catch (InstantiationException e) {
			throw new MessageProcessingException("Internal error parsing assertion: " + e.getMessage(),e);
		} catch (IllegalAccessException e) {
			throw new MessageProcessingException("Internal error parsing assertion: " + e.getMessage(),e);
		} catch (IllegalArgumentException e) {
			throw new MessageProcessingException("Internal error parsing assertion: " + e.getMessage(),e);
		} catch (InvocationTargetException e) {
			throw new MessageProcessingException("Internal error parsing assertion: " + e.getMessage(),e);
		} catch (NoSuchMethodException e) {
			throw new MessageProcessingException("Internal error parsing assertion: " + e.getMessage(),e);
		} catch (SecurityException e) {
			throw new MessageProcessingException("Internal error parsing assertion: " + e.getMessage(),e);
		}
	}
	
	/**
	 * Method to parse and decrypt an assertion of any type.
	 * 
	 * @param assertion the assertion to decrypt and parse
	 * @return an assertion data implementation of the type of assertion.
	 * @throws MessageContentException if content of message was invalid.
	 * @throws MessageProcessingException if internal problems occurred parsing the assertions.
	 * @throws NoDecryptionKeyFoundException if no key could be found decrypting the assertion.
	 */
	public AssertionData parseAndDecryptAssertion(JAXBElement<AssertionType> assertion) throws MessageContentException, MessageProcessingException, NoDecryptionKeyFoundException{
		try {
			Document doc = getDocumentBuilder().newDocument();
			getUserDataMarshaller().marshal(assertion, doc);
			
			@SuppressWarnings("unchecked")
			JAXBElement<AssertionType> decryptedAssertion = (JAXBElement<AssertionType>) userDataXmlEncrypter.decryptDocument(doc, encryptedAttributeXMLConverter);
			
			schemaValidateAssertion(decryptedAssertion);
			
			AssertionTypeEnum assertionType = getTypeOfAssertion(decryptedAssertion);
			
			AssertionData retval = (AssertionData) assertionType.getAssertionDataClass().getConstructor(AssertionPayloadParser.class).newInstance(this);
			retval.parse(decryptedAssertion);

			return retval;
		} catch (ParserConfigurationException e) {
			throw new MessageProcessingException("Internal error parsing assertion: " + e.getMessage(),e);
		} catch (JAXBException e) {
			throw new MessageContentException("Error parsing assertion : " + e.getMessage(),e);
		} catch (InstantiationException e) {
			throw new MessageProcessingException("Internal error parsing assertion: " + e.getMessage(),e);
		} catch (IllegalAccessException e) {
			throw new MessageProcessingException("Internal error parsing assertion: " + e.getMessage(),e);
		} catch (IllegalArgumentException e) {
			throw new MessageProcessingException("Internal error parsing assertion: " + e.getMessage(),e);
		} catch (InvocationTargetException e) {
			throw new MessageProcessingException("Internal error parsing assertion: " + e.getMessage(),e);
		} catch (NoSuchMethodException e) {
			throw new MessageProcessingException("Internal error parsing assertion: " + e.getMessage(),e);
		} catch (SecurityException e) {
			throw new MessageProcessingException("Internal error parsing assertion: " + e.getMessage(),e);
		}
	}


	
	private BaseSAMLMessageParser.SimpleConditionLookup  simpleConditionLookup = new BaseSAMLMessageParser.SimpleConditionLookup();
	/**
	 * Method that verifies the notBefore and notOnOrAfter conditions, all other conditions set in an assertion
	 * is ignored.
	 * @param assertionType the assertion to verify
	 * @throws MessageContentException if conditions wasn't met.
	 */
	private void verifyAssertionConditions(AssertionType assertionType) throws MessageContentException {
		samlAssertionMessageParser.verifyAssertionConditions(assertionType, simpleConditionLookup);
		
	}
	
	private void verifyAssertionSignature(JAXBElement<AssertionType> assertion) throws MessageContentException, MessageProcessingException {
		DOMResult res = new DOMResult();
		try {
			getAssertionMarshaller().marshal(assertion, res);
		} catch (JAXBException e) {
			throw new MessageContentException("Error marshalling assertion: " + e.getMessage(),e);
		}
		
		xmlSigner.verifyEnvelopedSignature((Document) res.getNode(),false);
		
	}


	private JAXBElement<AssertionType> generateAssertion(String issuer, Date notBefore, Date notOnOrAfter, String subjectId, List<Object> attributes) throws MessageProcessingException{
		return samlAssertionMessageParser.generateSimpleAssertion(issuer,notBefore,notOnOrAfter,subjectId,attributes);
	}


	private JAXBElement<ResponseType> genSuccessfulSAMLPResponse(String inResponseTo, JAXBElement<AssertionType> assertion) throws MessageProcessingException{
		return samlAssertionMessageParser.genSuccessfulSAMLPResponse(inResponseTo,assertion);
	}
	
	/**
	 * This method will generate an unsigned SAMLP Attribute Query Message with a given attribute specified.
	 * 
	 * @param subjectId The unique id of the user to look-up, could be UPN or SAM account name depending on implementation.
	 * @param attributeName the name of the attribute to query.
	 * @param tokenType, value of TokenType attribute parameter, null if not used.
	 * @return a generated SAMLP Attribute Query Message
	 * @throws MessageContentException if given parameters where invalid
	 * @throws MessageProcessingException if internal error occurred generating the message.
	 */
	private byte[] genAttributeQuery(String subjectId, String attributeName, String tokenType) throws MessageContentException, MessageProcessingException{
		if(subjectId == null || subjectId.trim().equals("")){
			throw new MessageContentException("Error subject id cannot be null in attribute query");
		}
		AttributeQueryType attributeQueryType = samlpOf.createAttributeQueryType();
		attributeQueryType.setID("_" +MessageGenerateUtils.generateRandomUUID());
		attributeQueryType.setIssueInstant(MessageGenerateUtils.dateToXMLGregorianCalendar(systemTime.getSystemTime()));
		attributeQueryType.setVersion(DEFAULT_ASSERTION_VERSION);
		
		NameIDType nameIdType = of.createNameIDType();
		nameIdType.setValue(subjectId);
		
		SubjectType subjectType = of.createSubjectType();
		subjectType.getContent().add(of.createNameID(nameIdType));
		attributeQueryType.setSubject(subjectType);
		
		AttributeType attributeType = of.createAttributeType();
		attributeType.setName(attributeName);
		attributeQueryType.getAttribute().add(attributeType);
		
		if(tokenType != null){
			AttributeType tokenTypeAttributeType = of.createAttributeType();
			tokenTypeAttributeType.setName(ATTRIBUTE_NAME_TOKENTYPE);
			tokenTypeAttributeType.getAttributeValue().add(tokenType);
			attributeQueryType.getAttribute().add(tokenTypeAttributeType);
		}
		return marshall(samlpOf.createAttributeQuery(attributeQueryType));
	}
	
	
	/**
	 * Help method to marshall a message without signing it.
	 * @param message the message to marshall into a XML byte array.
	 * @return the marshalled byte array 
	 * @throws MessageProcessingException if problem occurred marshalling the message.
	 */
	private byte[] marshall(JAXBElement<?> message) throws MessageProcessingException{
		try{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		getAssertionMarshaller().marshal(message, baos);
		return baos.toByteArray();
		}catch(Exception e){
			throw new MessageProcessingException("Error occurred marshalling assertion object: " + e.getMessage(),e );
		}
	}

	
	/**
	 * Help method to marshall and sign an Assertion, either standalone or inside a SAMLP Response
	 * 
	 * Method that generates the signature and marshalls the message to byte array in UTF-8 format.
	 * @param message a Assertion or Response (SAMLP) structure.
	 * @return a marshalled and signed message.
	 * @throws MessageProcessingException if problems occurred when processing the message.
	 * @throws MessageContentException if unsupported version is detected in message.
	 */
	private byte[] marshallAndSignAssertion(JAXBElement<?> message) throws MessageProcessingException, MessageContentException{
		if(message == null){
			throw new MessageProcessingException("Error marshalling assertion, message cannot be null.");
		}

		try {
			Document doc = getDocumentBuilder().newDocument();
			getAssertionMarshaller().marshal(message, doc);
			return xmlSigner.marshallAndSign(ContextMessageSecurityProvider.DEFAULT_CONTEXT,doc,  assertionSignatureLocationFinder);
		} catch (JAXBException e) {
			throw new MessageProcessingException("Error marshalling message " + e.getMessage(), e);
		} catch (ParserConfigurationException e) {
			throw new MessageProcessingException("Error generating document builder " + e.getMessage(), e);
		}
	}

	private DocumentBuilder getDocumentBuilder() throws ParserConfigurationException {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);

		return dbf.newDocumentBuilder();
	}
	
	private Marshaller assertionMarshaller = null;
	Marshaller getAssertionMarshaller() throws JAXBException{
		if(assertionMarshaller == null){
			assertionMarshaller = getJAXBContext().createMarshaller();
			assertionMarshaller.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
		}
		return assertionMarshaller;
	}
	
	private Unmarshaller assertionUnmarshaller = null;
	Unmarshaller getAssertionUnmarshaller() throws JAXBException, SAXException{
		if(assertionUnmarshaller == null){
			assertionUnmarshaller = getJAXBContext().createUnmarshaller();
			assertionUnmarshaller.setSchema(generateAssertionSchema());
		}
		return assertionUnmarshaller;
	}
	
	private Marshaller userDataMarshaller = null;
	Marshaller getUserDataMarshaller() throws JAXBException{
		if(userDataMarshaller == null){
			userDataMarshaller = getUserDataJAXBContext().createMarshaller();
			userDataMarshaller.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
		}
		return userDataMarshaller;
	}
	
	private Unmarshaller userDataUnmarshaller = null;
	Unmarshaller getUserDataUnmarshaller() throws JAXBException, SAXException{
		if(userDataUnmarshaller == null){
			userDataUnmarshaller = getUserDataJAXBContext().createUnmarshaller();
			userDataUnmarshaller.setSchema(generateUserDataSchema());
		}
		return userDataUnmarshaller;
	}
	
	
	private JAXBContext jaxbContext = null;
    /**
     * Help method maintaining the Assertion JAXB Context.
     */
    private JAXBContext getJAXBContext() throws JAXBException{
    	if(jaxbContext== null){
    		String jaxbClassPath = "org.certificateservices.messages.saml2.assertion.jaxb:org.certificateservices.messages.saml2.protocol.jaxb:org.certificateservices.messages.xenc.jaxb:org.certificateservices.messages.xmldsig.jaxb";
    			    		
    		jaxbContext = JAXBContext.newInstance(jaxbClassPath);
    		
    	}
    	return jaxbContext;
    }
    
	private JAXBContext userDataJaxbContext = null;
    /**
     * Help method maintaining the Assertion JAXB Context.
     */
    private JAXBContext getUserDataJAXBContext() throws JAXBException{
    	if(userDataJaxbContext== null){
    		String jaxbClassPath = "org.certificateservices.messages.saml2.assertion.jaxb:org.certificateservices.messages.saml2.protocol.jaxb:org.certificateservices.messages.xenc.jaxb:org.certificateservices.messages.xmldsig.jaxb:org.certificateservices.messages.credmanagement.jaxb";
    			    		
    		userDataJaxbContext = JAXBContext.newInstance(jaxbClassPath);
    		
    	}
    	return userDataJaxbContext;
    }
    
    private Schema generateAssertionSchema() throws SAXException{
    	SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
    	
    	schemaFactory.setResourceResolver(new AssertionLSResourceResolver());
		
        Source[] sources = new Source[4];
        sources[0] = new StreamSource(getClass().getResourceAsStream(DefaultCSMessageParser.XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION));
        sources[1] = new StreamSource(getClass().getResourceAsStream(DefaultCSMessageParser.XMLENC_XSD_SCHEMA_RESOURCE_LOCATION));
        sources[2] = new StreamSource(getClass().getResourceAsStream(ASSERTION_XSD_SCHEMA_2_0_RESOURCE_LOCATION));
        sources[3] = new StreamSource(getClass().getResourceAsStream(SAMLP_XSD_SCHEMA_2_0_RESOURCE_LOCATION));
        
        Schema schema = schemaFactory.newSchema(sources);       
        
        return schema;
    }
    
    private Schema generateUserDataSchema() throws SAXException{
    	SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
		
    	schemaFactory.setResourceResolver(new AssertionLSResourceResolver());
    	
        Source[] sources = new Source[6];
        sources[0] = new StreamSource(getClass().getResourceAsStream(DefaultCSMessageParser.XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION));
        sources[1] = new StreamSource(getClass().getResourceAsStream(DefaultCSMessageParser.XMLENC_XSD_SCHEMA_RESOURCE_LOCATION));
        sources[2] = new StreamSource(getClass().getResourceAsStream(ASSERTION_XSD_SCHEMA_2_0_RESOURCE_LOCATION));
        sources[3] = new StreamSource(getClass().getResourceAsStream(SAMLP_XSD_SCHEMA_2_0_RESOURCE_LOCATION));
        sources[4] = new StreamSource(getClass().getResourceAsStream(DefaultCSMessageParser.CSMESSAGE_XSD_SCHEMA_2_0_RESOURCE_LOCATION));
        sources[5] = new StreamSource(getClass().getResourceAsStream(CredManagementPayloadParser.CREDMANAGEMENT_XSD_SCHEMA_2_0_RESOURCE_LOCATION));
        
        Schema schema = schemaFactory.newSchema(sources);       
        
        return schema;
    }

	private EncryptedElementType createEncryptedAttribute(String attributeName, List<String> attributeValues, List<X509Certificate> receipients) throws JAXBException, SAXException, MessageProcessingException {
		AttributeType roleAttributeType = of.createAttributeType();
		roleAttributeType.setName(attributeName);
		for(String value : attributeValues){
			roleAttributeType.getAttributeValue().add(value);
		}
		JAXBElement<AttributeType> roleAttribute = of.createAttribute(roleAttributeType);

		@SuppressWarnings("unchecked")
		JAXBElement<EncryptedDataType> encryptedData = (JAXBElement<EncryptedDataType>) getAssertionUnmarshaller().unmarshal(xmlEncrypter.encryptElement(roleAttribute, receipients, true));
		EncryptedElementType encryptedElementType1 = of.createEncryptedElementType();

		encryptedElementType1.setEncryptedData(encryptedData.getValue());
		return encryptedElementType1;
	}

	public static class AssertionLSResourceResolver implements LSResourceResolver {

		public LSInput resolveResource(String type, String namespaceURI,
									   String publicId, String systemId, String baseURI) {
			try {
				if(systemId != null && systemId.equals("http://www.w3.org/2001/XMLSchema.dtd")){
					return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream("/XMLSchema.dtd"));
				}
				if(systemId != null && systemId.equals("datatypes.dtd")){
					return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream("/datatypes.dtd"));
				}
				if(namespaceURI != null){
					if(namespaceURI.equals(DefaultCSMessageParser.XMLDSIG_NAMESPACE)){
						return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream(DefaultCSMessageParser.XMLDSIG_XSD_SCHEMA_RESOURCE_LOCATION));
					}
					if(namespaceURI.equals(DefaultCSMessageParser.XMLENC_NAMESPACE)){
						return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream(DefaultCSMessageParser.XMLENC_XSD_SCHEMA_RESOURCE_LOCATION));
					}
					if(namespaceURI.equals(SAMLP_NAMESPACE)){
						return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream(SAMLP_XSD_SCHEMA_2_0_RESOURCE_LOCATION));
					}
					if(namespaceURI.equals(NAMESPACE)){
						return new XSDLSInput(publicId, systemId, DefaultCSMessageParser.class.getResourceAsStream(ASSERTION_XSD_SCHEMA_2_0_RESOURCE_LOCATION));
					}
				}
			} catch (MessageProcessingException e) {
				throw new IllegalStateException("Error couldn't read XSD from class path: " + e.getMessage(), e);
			}
			return null;
		}
	}

}
