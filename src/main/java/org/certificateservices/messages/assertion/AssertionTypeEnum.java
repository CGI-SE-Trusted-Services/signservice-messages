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
package org.certificateservices.messages.assertion;

/**
 * Defines available types of assertions.
 * 
 * @author Philip Vendil
 *
 */
public enum AssertionTypeEnum {

	AUTHORIZATION_TICKET("AUTHORIZATION_TICKET", AuthorizationAssertionData.class),
	USER_DATA("USER_DATA", UserDataAssertionData.class),
	APPROVAL_TICKET("APPROVAL_TICKET", ApprovalAssertionData.class);

	private String attributeValue;
	private Class<?> assertionDataClass;
	private AssertionTypeEnum(String attributeValue, Class<?> assertionDataClass){
		this.attributeValue = attributeValue;
		this.assertionDataClass = assertionDataClass;
	}
	
	/**
	 * @return the value of the AssertionType SAML Attribute
	 */
	public String getAttributeValue(){
		return attributeValue;
	}
	
	/**
	 * @return the related assertion data class.
	 */
	public Class<?> getAssertionDataClass(){
		return assertionDataClass;
	}
}
