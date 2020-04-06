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

/**
 * Defines available types of assertions.
 * 
 * @author Philip Vendil
 *
 */
public enum AttributeQueryTypeEnum {

	AUTHORIZATION_TICKET(AssertionPayloadParser.ATTRIBUTE_NAME_ROLES),
	USER_DATA(AssertionPayloadParser.ATTRIBUTE_NAME_USERDATA);

	private String attributeValue;
	private AttributeQueryTypeEnum(String attributeValue){
		this.attributeValue = attributeValue;
	}
	
	/**
	 * @return the value of the AssertionType SAML Attribute
	 */
	public String getAttributeValue(){
		return attributeValue;
	}
	
}
	

