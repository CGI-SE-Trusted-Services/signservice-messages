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
package org.signatureservice.messages.utils

import spock.lang.Specification

class DefaultSystemTimeSpec extends Specification{

	 def "Test default system time works"(){
		 expect:
		 (new DefaultSystemTime()).getSystemTimeMS() != 0
		 (new DefaultSystemTime()).getSystemTime() != null
	 }
}
