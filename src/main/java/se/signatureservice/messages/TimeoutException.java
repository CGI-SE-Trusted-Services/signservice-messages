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
package se.signatureservice.messages;

/**
 * Exception thrown if timout problems was returned for server (HTTP Status 403).
 *
 * @author Philip Vendil 2020-12-09
 */
public class TimeoutException extends MessageProcessingException{

    public TimeoutException(String message){
        super(message);
    }

}
