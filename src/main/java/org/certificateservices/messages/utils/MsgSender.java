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
package org.certificateservices.messages.utils;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;

import java.io.IOException;

/**
 * Interface to send and receive request and response messages to an end point.
 *
 * Created by Philip Vendil on 16/06/16.
 */
public interface MsgSender {

    /**
     * Method to syncronically send a request and wait for a response. I.e the method
     * will wait for the response from the client.
     *
     * @param request the request message to send.
     * @return the response message to receive.
     * @throws MessageContentException if content of the request was illegal.
     * @throws MessageProcessingException if internal problems occurred processing the request.
     */
    byte[] sendMsg(byte[] request) throws MessageContentException, MessageProcessingException, IOException;

    /**
     * Method to asyncronically send a request and response (or error) is signaled through callback.
     *
     * @param request the request to send.
     * @param callback the callback to signal when the reply is recieved.
     */
    void sendMsg(byte[] request, MsgCallback callback);

    /**
     * Method to check the connection
     *
     * @return true, if connection works.
     */
    public boolean testConnection();

    /**
     * Message callback interface for receiving response data or errors.
     */
    interface MsgCallback{

        /**
         * Method called after a successful transport of the request and response message.
         *
         * @param responseData the response data from the call.
         */
        void responseReceived(byte[] responseData);

        /**
         * Method called if error occurred processing the request.
         *
         * @param e the exception thrown.
         */
        void errorOccurred(Exception e);
    }
}
