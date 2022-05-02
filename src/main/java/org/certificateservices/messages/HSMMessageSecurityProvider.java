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
package org.certificateservices.messages;

/**
 * Extended ContextMessageSecurityProvider interface for allowing a HSM message security
 * provider to give information about the Java Security Provider that should be used
 * when performing cryptographic operations.
 *
 * @author Tobias Agerberg
 *
 */
public interface HSMMessageSecurityProvider extends ContextMessageSecurityProvider {

    /**
     * Get provider name to use when performing cryptographic operations.
     * @return
     */
    String getHSMProvider();
}
