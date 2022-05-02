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
package org.certificateservices.messages.v2x.registration;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.csmessages.BasePayloadParser;
import org.certificateservices.messages.csmessages.CSMessageResponseData;
import org.certificateservices.messages.csmessages.PayloadParser;
import org.certificateservices.messages.csmessages.jaxb.CSMessage;
import org.certificateservices.messages.csmessages.jaxb.Credential;
import org.certificateservices.messages.utils.MessageGenerateUtils;
import org.certificateservices.messages.v2x.registration.jaxb.*;

import java.io.InputStream;
import java.util.Date;
import java.util.List;

/**
 * Payload Parser for generating V2X messages according to
 * v2x_registration_schema2_0.xsd
 * 
 * @author Philip Vendil
 *
 */
public class V2XPayloadParser extends BasePayloadParser {
	
	public static String NAMESPACE = "http://certificateservices.org/xsd/v2x_registration_2_0";
	
	public static final String V2X_XSD_SCHEMA_2_0_RESOURCE_LOCATION = "/v2x_registration_schema2_0.xsd";

	
	private ObjectFactory of = new ObjectFactory();
	
	private static final String[] SUPPORTED_V2X_VERSIONS = {"2.0"};
	
	private static final String DEFAULT_V2X_VERSION = "2.0";
	
	
	/**
	 * @see PayloadParser#getJAXBPackage()
	 */
	public String getJAXBPackage() {
		return "org.certificateservices.messages.v2x.registration.jaxb";
	}

	/**
	 * @see PayloadParser#getNameSpace()
	 */
	public String getNameSpace() {
		return NAMESPACE;
	}

	/**
	 * @see PayloadParser#getSchemaAsInputStream(String)
	 */
	public InputStream getSchemaAsInputStream(String payLoadVersion)
			throws MessageContentException, MessageProcessingException {
    	if(payLoadVersion.equals("2.0")){
    		return getClass().getResourceAsStream(V2X_XSD_SCHEMA_2_0_RESOURCE_LOCATION);
    	}
    	
    	throw new MessageContentException("Error unsupported SysConfig Payload version: " + payLoadVersion);
	}
	
	/**
	 * @see BasePayloadParser#getSupportedVersions()
	 */
	@Override
	protected String[] getSupportedVersions() {
		return SUPPORTED_V2X_VERSIONS;
	}

	/**
	 * @see BasePayloadParser#getDefaultPayloadVersion()
	 */
	@Override
	protected String getDefaultPayloadVersion() {
		return DEFAULT_V2X_VERSION;
	}
	
	
	/**
	 *
	 * Method generate a Register ITSS Request Message.
	 * 
	 * @param requestId  id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param organisation the related organisation (short name)
	 * @param ecuType Type of ECU used for the ITS station, used to verify against available values in profile and when
	 *                defining assurance level. (Required)
	 * @param canonicalId the canonical name of the ITS to register. Should be a unique identifier. (Required)
	 * @param canonicalSignPubKey the initial ec sign public key as a COER encoded PublicVerificationKey from ETSI 103 097.
	 * @param eaName name of EA that the ITSS should be associated with.
	 * @param ecProfile Name of profile to use for the enrollment credential. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default EA used.
	 * @param atProfile Name of profile to use for the authorization ticket. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default AA used.
	 * @param atAppPermissions list of app permissions to use in generate Authorization Tickets (Required).
	 * @param itssValidFrom The date time when the related ITS station will have it’s initial EC certificate start date.
	 *                     The start date of any EC or AT certificates cannot be before this date.
	 * @param itssValidTo Field to define an end life of an ITS station, no certificate (EC or AT) can have a validity after this date.
	 *                   Use case could be a test fleet where no vehicles should be used after a specific date.
	 * @param regions Defines specific regions for this vehicle. The defined regions is checked against the profile and only regions that are a subset of regions defined in related profile will be accepted.
	 *                If not set is the default regions set in related profile used.
	 * @param originator the credential of the original requester, null if this is the origin of the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *  
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public byte[] generateRegisterITSSRequest(String requestId, String destinationId, String organisation,
											 String ecuType, String canonicalId,
											 byte[] canonicalSignPubKey,  String eaName, String ecProfile,
											 String atProfile, List<AppPermissionsType> atAppPermissions,
											 Date itssValidFrom, Date itssValidTo, RegionsType regions,
											 Credential originator, List<Object> assertions)
			throws MessageContentException, MessageProcessingException{
		RegisterITSSRequest payload = of.createRegisterITSSRequest();
		payload.setEcuType(ecuType);
		payload.setCanonicalId(canonicalId);
		payload.setEaName(eaName);
		payload.setCanonicalPublicKey(createCanonicalKeyType(canonicalSignPubKey));
		ATAppPermissionsType atAppPermissionsType = of.createATAppPermissionsType();
		atAppPermissionsType.getAppPermission().addAll(atAppPermissions);
		payload.setAtPermissions(atAppPermissionsType);
		populateBaseRegisterRequestType(payload,canonicalId,ecProfile,atProfile,itssValidFrom,itssValidTo,regions);
		
		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(),
				payload, originator, assertions);
	}
	
	/**
	 * Method generate a Register ITSS Response Message.
	 * 
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param ecuType Type of ECU used for the ITS station, used to verify against available values in profile and when
	 *                defining assurance level.
	 * @param canonicalId the canonical name of the ITS to register. Should be a unique identifier.
	 * @param canonicalKey the initial ec public key type containing keys to update.
	 * @param eaName name of EA that the ITSS should be associated with.
	 * @param ecProfile Name of profile to use for the enrollment credential. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default EA used.
	 * @param atProfile Name of profile to use for the authorization ticket. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default AA used.
	 * @param atAppPermissions list of app permissions to use in generate Authorization Tickets.
	 * @param itssValidFrom The date time when the related ITS station will have it’s initial EC certificate start date.
	 *                     The start date of any EC or AT certificates cannot be before this date.
	 * @param itssValidTo Field to define an end life of an ITS station, no certificate (EC or AT) can have a validity after this date.
	 *                   Use case could be a test fleet where no vehicles should be used after a specific date.
	 * @param regions Defines specific regions for this vehicle. The defined regions is checked against the profile and only regions that are a subset of regions defined in related profile will be accepted.
	 *                If not set is the default regions set in related profile used.
	 * @param itsStatus the current status of the ITS Station.
	 * @return a generated and signed message.
	 *  
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
    public CSMessageResponseData generateRegisterITSSResponse(String relatedEndEntity, CSMessage request, String ecuType,
															 String canonicalId,
															 CanonicalKeyType canonicalKey,
															 String eaName,
															 String ecProfile, String atProfile,
															 List<AppPermissionsType> atAppPermissions, Date itssValidFrom,
															 Date itssValidTo, RegionsType regions, ITSSStatusType itsStatus)
			throws MessageContentException, MessageProcessingException{
    	RegisterITSSResponse payload = of.createRegisterITSSResponse();

		populateBaseV2XResponseType(payload,ecuType,canonicalId,canonicalKey,eaName,ecProfile,atProfile,
				atAppPermissions,itssValidFrom,itssValidTo,regions,itsStatus);
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), payload);
	}

	/**
	 * Method generate a Register ITSS Response Message from a pre-populated RegisterITSSResponse.
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param payload a pre-populated RegisterITSSResponse payload.
	 * @return a generated and signed message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public CSMessageResponseData generateRegisterITSSResponse(String relatedEndEntity, CSMessage request,
															  RegisterITSSResponse payload)
			throws MessageContentException, MessageProcessingException{
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), payload);
	}

	/**
	 * Method generate a Update ITSS Request Message. Fields that are null will not be updated.
	 *
	 * @param requestId  id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param ecuType Type of ECU used for the ITS station, used to verify against available values in profile and when
	 *                defining assurance level.
	 * @param canonicalId the canonical name of the ITS to register. Should be a unique identifier. (Required)
	 * @param canonicalSignPubKey the initial ec sign public key as a COER encoded PublicVerificationKey from ETSI 103 097.
	 * @param eaName name of EA that the ITSS should be associated with.
	 * @param ecProfile Name of profile to use for the enrollment credential. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default EA used.
	 * @param atProfile Name of profile to use for the authorization ticket. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default AA used.
	 * @param atAppPermissions list of app permissions to use in generate Authorization Tickets.
	 * @param itssValidFrom The date time when the related ITS station will have it’s initial EC certificate start date.
	 *                     The start date of any EC or AT certificates cannot be before this date.
	 * @param itssValidTo Field to define an end life of an ITS station, no certificate (EC or AT) can have a validity after this date.
	 *                   Use case could be a test fleet where no vehicles should be used after a specific date.
	 * @param regions Defines specific regions for this vehicle. The defined regions is checked against the profile and only regions that are a subset of regions defined in related profile will be accepted.
	 *                If not set is the default regions set in related profile used.
	 * @param originator the credential of the original requester, null if this is the origin of the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public byte[] generateUpdateITSSRequest(String requestId, String destinationId, String organisation, String ecuType,
											String canonicalId,
										   byte[] canonicalSignPubKey, String eaName, String ecProfile,
										   String atProfile, List<AppPermissionsType> atAppPermissions,
										   Date itssValidFrom, Date itssValidTo, RegionsType regions,
										   Credential originator, List<Object> assertions)
			throws MessageContentException, MessageProcessingException{
		UpdateITSSRequest payload = of.createUpdateITSSRequest();
		payload.setEaName(eaName);
		payload.setEcuType(ecuType);
		payload.setCanonicalPublicKey(createCanonicalKeyType(canonicalSignPubKey));
		if(atAppPermissions != null){
			ATAppPermissionsType atAppPermissionsType = of.createATAppPermissionsType();
			atAppPermissionsType.getAppPermission().addAll(atAppPermissions);
			payload.setAtPermissions(atAppPermissionsType);
		}
		populateBaseRegisterRequestType(payload,canonicalId,ecProfile,atProfile,itssValidFrom,itssValidTo,regions);

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(), payload, originator, assertions);
	}

	/**
	 * Method generate a Update ITSS Response Message.
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param ecuType Type of ECU used for the ITS station, used to verify against available values in profile and when
	 *                defining assurance level.
	 * @param canonicalId the canonical name of the ITS to register. Should be a unique identifier in hostname format.
	 * @param canonicalKey the initial ec public key type containing keys to update.
	 * @param eaName name of EA that the ITSS should be associated with.
	 * @param ecProfile Name of profile to use for the enrollment credential. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default EA used.
	 * @param atProfile Name of profile to use for the authorization ticket. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default AA used.
	 * @param atAppPermissions list of app permissions to use in generate Authorization Tickets.
	 * @param itssValidFrom The date time when the related ITS station will have it’s initial EC certificate start date.
	 *                     The start date of any EC or AT certificates cannot be before this date.
	 * @param itssValidTo Field to define an end life of an ITS station, no certificate (EC or AT) can have a validity after this date.
	 *                   Use case could be a test fleet where no vehicles should be used after a specific date.
	 * @param regions Defines specific regions for this vehicle. The defined regions is checked against the profile and only regions that are a subset of regions defined in related profile will be accepted.
	 *                If not set is the default regions set in related profile used.
	 * @param itsStatus the current status of the ITS Station.
	 * @return a generated and signed message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public CSMessageResponseData generateUpdateITSSResponse(String relatedEndEntity, CSMessage request,
														   String ecuType, String canonicalId,
														   CanonicalKeyType canonicalKey, String eaName,
															String ecProfile,
														   String atProfile, List<AppPermissionsType> atAppPermissions,
														   Date itssValidFrom, Date itssValidTo,
														   RegionsType regions, ITSSStatusType itsStatus)
			throws MessageContentException, MessageProcessingException{
		UpdateITSSResponse payload = of.createUpdateITSSResponse();
		populateBaseV2XResponseType(payload,ecuType,canonicalId,canonicalKey,eaName,
				ecProfile,atProfile,atAppPermissions, itssValidFrom,itssValidTo,regions,itsStatus);
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(),
				payload);
	}

	/**
	 * Method generate a Update ITSS Response Message from a pre-populated UpdateITSSResponse
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param payload a pre-populated UpdateITSSResponse payload.
	 * @return a generated and signed message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public CSMessageResponseData generateUpdateITSSResponse(String relatedEndEntity, CSMessage request,
															UpdateITSSResponse payload)
			throws MessageContentException, MessageProcessingException{
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(),
				payload);
	}

	/**
	 * Method generate a Get ITSS Data Request Message.
	 *
	 * @param requestId  id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param organisation the related organisation (short name)
	 * @param canonicalId the canonical name of the ITS to register. Should be a unique identifier.
	 * @param includeEC if issued enrolment credentials should be returned in the response.
	 * @param originator the credential of the original requester, null if this is the origin of the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public byte[] generateGetITSSDataRequest(String requestId, String destinationId, String organisation,
											 String canonicalId, boolean includeEC,
											Credential originator, List<Object> assertions)
			throws MessageContentException, MessageProcessingException{
		GetITSSDataRequest payload = of.createGetITSSDataRequest();
		payload.setCanonicalId(canonicalId);
		if(includeEC) {
			payload.setIncludeEC(includeEC);
		}

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(),
				payload, originator, assertions);
	}

	/**
	 * Method generate a Get ITSS Data Response Message.
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param ecuType Type of ECU used for the ITS station, used to verify against available values in profile and when
	 *                defining assurance level.
	 * @param canonicalId the canonical name of the ITS to register. Should be a unique identifier in hostname format.
	 * @param canonicalKeyType the initial ec public key type containing keys to update.
	 * @param eaName name of EA that the ITSS should be associated with.
	 * @param ecProfile Name of profile to use for the enrollment credential. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default EA used.
	 * @param atProfile Name of profile to use for the authorization ticket. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default AA used.
	 * @param atAppPermissions list of app permissions to use in generate Authorization Tickets.
	 * @param itssValidFrom The date time when the related ITS station will have it’s initial EC certificate start date.
	 *                     The start date of any EC or AT certificates cannot be before this date.
	 * @param itssValidTo Field to define an end life of an ITS station, no certificate (EC or AT) can have a validity after this date.
	 *                   Use case could be a test fleet where no vehicles should be used after a specific date.
	 * @param regions Defines specific regions for this vehicle. The defined regions is checked against the profile and only regions that are a subset of regions defined in related profile will be accepted.
	 *                If not set is the default regions set in related profile used.
	 * @param itsStatus the current status of the ITS Station.
	 * @return a generated and signed message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public CSMessageResponseData generateGetITSSDataResponse(String relatedEndEntity, CSMessage request,
															String ecuType, String canonicalId,
															CanonicalKeyType canonicalKeyType, String eaName,
															String ecProfile, String atProfile,
															List<AppPermissionsType> atAppPermissions, Date itssValidFrom,
															Date itssValidTo, RegionsType regions,
															ITSSStatusType itsStatus,
															List<EnrolmentCredentialType> enrolmentCredentials)
			throws MessageContentException, MessageProcessingException{
		GetITSSDataResponse payload = of.createGetITSSDataResponse();

		populateBaseV2XResponseType(payload,ecuType,canonicalId,canonicalKeyType,eaName,
				ecProfile,atProfile,atAppPermissions,itssValidFrom,itssValidTo,regions,itsStatus);
		if(enrolmentCredentials != null){
			EnrolmentCredentialsType enrolmentCredentialsType = of.createEnrolmentCredentialsType();
			enrolmentCredentialsType.getEc().addAll(enrolmentCredentials);
			payload.setEnrolmentCredentials(enrolmentCredentialsType);
		}
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), payload);
	}

	/**
	 * Method generate a Get ITSS Data Response Message from a pre-populated GetITSSDataResponse.
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param payload a pre-populated GetITSSDataResponse payload.
	 * @return a generated and signed message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public CSMessageResponseData generateGetITSSDataResponse(String relatedEndEntity, CSMessage request,
															GetITSSDataResponse payload)
			throws MessageContentException, MessageProcessingException{
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(), payload);
	}

	/**
	 * Method generate a Deactivate ITSS Request Message.
	 *
	 * @param requestId  id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param organisation the related organisation (short name)
	 * @param canonicalId the canonical name of the ITS to register. Should be a unique identifier.
	 * @param originator the credential of the original requester, null if this is the origin of the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public byte[] generateDeactivateITSSRequest(String requestId, String destinationId, String organisation, String canonicalId,
												Credential originator, List<Object> assertions)
			throws MessageContentException, MessageProcessingException{
		DeactivateITSSRequest payload = of.createDeactivateITSSRequest();
		payload.setCanonicalId(canonicalId);

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(),
				payload, originator, assertions);
	}

	/**
	 * Method generate a Deactivate ITSS Response Message.
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param ecuType Type of ECU used for the ITS station, used to verify against available values in profile and when
	 *                defining assurance level.
	 * @param canonicalId the canonical name of the ITS to register. Should be a unique identifier.
	 * @param canonicalKey the initial ec public key type containing keys to update.
	 * @param eaName name of EA that the ITSS should be associated with.
	 * @param ecProfile Name of profile to use for the enrollment credential. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default EA used.
	 * @param atProfile Name of profile to use for the authorization ticket. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default AA used.
	 * @param atAppPermissions list of app permissions to use in generate Authorization Tickets.
	 * @param itssValidFrom The date time when the related ITS station will have it’s initial EC certificate start date.
	 *                     The start date of any EC or AT certificates cannot be before this date.
	 * @param itssValidTo Field to define an end life of an ITS station, no certificate (EC or AT) can have a validity after this date.
	 *                   Use case could be a test fleet where no vehicles should be used after a specific date.
	 * @param regions Defines specific regions for this vehicle. The defined regions is checked against the profile and only regions that are a subset of regions defined in related profile will be accepted.
	 *                If not set is the default regions set in related profile used.
	 * @param itsStatus the current status of the ITS Station.
	 * @return a generated and signed message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public CSMessageResponseData generateDeactivateITSSResponse(String relatedEndEntity, CSMessage request,
																String ecuType, String canonicalId,
																CanonicalKeyType canonicalKey,
																String eaName,
																String ecProfile, String atProfile,
																List<AppPermissionsType> atAppPermissions, Date itssValidFrom,
																Date itssValidTo, RegionsType regions,
																ITSSStatusType itsStatus)
			throws MessageContentException, MessageProcessingException{
		DeactivateITSSResponse payload = of.createDeactivateITSSResponse();

		populateBaseV2XResponseType(payload,ecuType,canonicalId,canonicalKey,eaName,ecProfile,atProfile,
				atAppPermissions, itssValidFrom,itssValidTo,regions,itsStatus);
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(),
				payload);
	}

	/**
	 * Method generate a Deactivate ITSS Response Message from a pre-populated DeactivateITSSResponse.
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param payload a pre-populated DeactivateITSSResponse payload.
	 * @return a generated and signed message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public CSMessageResponseData generateDeactivateITSSResponse(String relatedEndEntity, CSMessage request,
																DeactivateITSSResponse payload)
			throws MessageContentException, MessageProcessingException{
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(),
				payload);
	}

	/**
	 * Method generate a Reactivate ITS Request Message.
	 *
	 * @param requestId  id of request to send.
	 * @param destinationId the destination Id to use.
	 * @param organisation the related organisation (short name)
	 * @param canonicalId the canonical name of the ITS to register. Should be a unique identifier.
	 * @param originator the credential of the original requester, null if this is the origin of the request.
	 * @param assertions a list of related authorization assertions, or null if no authorization assertions is available.
	 * @return  a generated and signed (if configured) message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public byte[] generateReactivateITSSRequest(String requestId, String destinationId, String organisation, String canonicalId,
												Credential originator, List<Object> assertions)
			throws MessageContentException, MessageProcessingException{
		ReactivateITSSRequest payload = of.createReactivateITSSRequest();
		payload.setCanonicalId(canonicalId);

		return getCSMessageParser().generateCSRequestMessage(requestId, destinationId, organisation, getPayloadVersion(),
				payload, originator, assertions);
	}

	/**
	 * Method generate a Reactivate ITS Response Message.
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param ecuType Type of ECU used for the ITS station, used to verify against available values in profile and when
	 *                defining assurance level.
	 * @param canonicalId the canonical name of the ITS to register. Should be a unique identifier.
	 * @param canonicalKey the initial ec public key type containing keys to update.
	 * @param eaName name of EA that the ITSS should be associated with.
	 * @param ecProfile Name of profile to use for the enrollment credential. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default EA used.
	 * @param atProfile Name of profile to use for the authorization ticket. The profile determines Service Permissions,
	 *                  default region and validity. If not set is default profile for default AA used.
	 * @param atAppPermissions list of app permissions to use in generate Authorization Tickets.
	 * @param itssValidFrom The date time when the related ITS station will have it’s initial EC certificate start date.
	 *                     The start date of any EC or AT certificates cannot be before this date.
	 * @param itssValidTo Field to define an end life of an ITS station, no certificate (EC or AT) can have a validity after this date.
	 *                   Use case could be a test fleet where no vehicles should be used after a specific date.
	 * @param regions Defines specific regions for this vehicle. The defined regions is checked against the profile and only regions that are a subset of regions defined in related profile will be accepted.
	 *                If not set is the default regions set in related profile used.
	 * @param itsStatus the current status of the ITS Station.
	 * @return a generated and signed message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public CSMessageResponseData generateReactivateITSSResponse(String relatedEndEntity, CSMessage request,
																String ecuType, String canonicalId,
																CanonicalKeyType canonicalKey, String eaName,
																String ecProfile, String atProfile,
																List<AppPermissionsType> atAppPermissions, Date itssValidFrom,
																Date itssValidTo, RegionsType regions, ITSSStatusType itsStatus)
			throws MessageContentException, MessageProcessingException{
		ReactivateITSSResponse payload = of.createReactivateITSSResponse();

		populateBaseV2XResponseType(payload,ecuType,canonicalId,canonicalKey,eaName,ecProfile,atProfile,
				atAppPermissions, itssValidFrom,itssValidTo,regions,itsStatus);
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(),
				payload);
	}

	/**
	 * Method generate a Reactivate ITS Response Message from a pre-populated ReactivateITSSResponse payload.
	 *
	 * @param relatedEndEntity the name of the related end entity (such as username of the related user)
	 * @param request the related request
	 * @param payload a pre-populated ReactivateITSSResponse payload.
	 * @return a generated and signed message.
	 *
	 * @throws MessageContentException if input data contained invalid format.
	 * @throws MessageProcessingException if internal problems occurred processing the cs message.
	 */
	public CSMessageResponseData generateReactivateITSSResponse(String relatedEndEntity, CSMessage request,
																ReactivateITSSResponse payload)
			throws MessageContentException, MessageProcessingException{
		return getCSMessageParser().generateCSResponseMessage(relatedEndEntity, request, request.getPayLoadVersion(),
				payload);
	}


	private void populateBaseV2XResponseType(BaseV2XResponseType payload,
											 String ecuType, String canonicalId,
											 CanonicalKeyType canonicalKeyType, String eaName,
											 String ecProfile, String atProfile,
											 List<AppPermissionsType> atAppPermissions,
											 Date itssValidFrom, Date itssValidTo, RegionsType regions,
											 ITSSStatusType itssStatus) throws MessageProcessingException {
		payload.setEcuType(ecuType);
		payload.setCanonicalId(canonicalId);
		payload.setCanonicalPublicKey(canonicalKeyType);
		payload.setEaName(eaName);
		payload.setEcProfile(ecProfile);
		payload.setAtProfile(atProfile);
		if(atAppPermissions != null){
			ATAppPermissionsType atAppPermissionsType = of.createATAppPermissionsType();
			atAppPermissionsType.getAppPermission().addAll(atAppPermissions);
			payload.setAtPermissions(atAppPermissionsType);
		}
		if(itssValidFrom != null) {
			payload.setItssValidFrom(MessageGenerateUtils.dateToXMLGregorianCalendar(itssValidFrom));
		}
		if(itssValidTo != null) {
			payload.setItssValidTo(MessageGenerateUtils.dateToXMLGregorianCalendar(itssValidTo));
		}
		payload.setRegions(regions);
		payload.setItssStatus(itssStatus);
	}

	private void populateBaseRegisterRequestType(BaseRegisterRequestType payload, String canonicalId,
                                                 String ecProfile, String atProfile, Date itssValidFrom, Date itssValidTo,
                                                 RegionsType regions) throws MessageProcessingException {
		payload.setCanonicalId(canonicalId);
		payload.setEcProfile(ecProfile);
		payload.setAtProfile(atProfile);
		if(itssValidFrom != null) {
			payload.setItssValidFrom(MessageGenerateUtils.dateToXMLGregorianCalendar(itssValidFrom));
		}
		if(itssValidTo != null) {
			payload.setItssValidTo(MessageGenerateUtils.dateToXMLGregorianCalendar(itssValidTo));
		}
		payload.setRegions(regions);
	}


	private CanonicalKeyType createCanonicalKeyType(byte[] canonicalSignPubKey){
		CanonicalKeyType canonicalKeyType = of.createCanonicalKeyType();
		canonicalKeyType.setPublicVerificationKey(canonicalSignPubKey);
		return canonicalKeyType;
	}



}
