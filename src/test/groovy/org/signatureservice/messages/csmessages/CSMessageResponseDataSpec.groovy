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
package org.signatureservice.messages.csmessages

import org.signatureservice.messages.csmessages.constants.Constants;
import spock.lang.Specification

class CSMessageResponseDataSpec extends Specification {
	
	
	def "Test isForwardable works correctly"(){
		setup:
		Set<String> excluded = ["DEST1", "DEST2"]
		expect:
		!new CSMessageResponseData(null,null,null, "DEST1", null, true).isForwardable(excluded)
		!new CSMessageResponseData(null,null,null, "DEST2", null, true).isForwardable(excluded)
		!new CSMessageResponseData(null,null,null, "DEST3", null, false).isForwardable(excluded)
		new CSMessageResponseData(null,null,null, "DEST3", null, true).isForwardable(excluded)
	}
	
	def "Test that getRelatedEndEntity returns UNKNOWN if not set"(){
		expect:
		new CSMessageResponseData(null,null,null, null, null, true).getRelatedEndEntity() == Constants.RELATED_END_ENTITY_UNKNOWN
		new CSMessageResponseData(null,null,"SomeEntity", null, null, true).getRelatedEndEntity() == "SomeEntity"
	}
	
	def "Test getMessageProperties doesn't return null"(){
		expect:
		new CSMessageResponseData(null,null,null, null, null, true).getMessageProperties() != null		
	}
	




}
