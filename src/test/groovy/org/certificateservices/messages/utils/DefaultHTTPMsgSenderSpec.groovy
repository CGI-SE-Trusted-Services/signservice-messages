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
package org.certificateservices.messages.utils

import org.certificateservice.testutils.TestHTTPServer
import org.certificateservices.messages.SpamProtectionException

import javax.servlet.ServletException
import javax.servlet.http.HttpServlet
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.certificateservices.messages.MessageContentException

import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

/**
 * Unit tests for DefaultHTTPMsgSender
 *
 * @author Philip Vendil
 */
class DefaultHTTPMsgSenderSpec extends Specification {

    @Shared DefaultHTTPMsgSender msgSender;
    @Shared TestHTTPServer server
    @Shared int defaultServerHTTPPort = 8089;

    def setupSpec(){
        // Here start a test server at some given port (not 8080) and add handlers that
        // verify it's a POST and the contenttype is text/xml and returns some byte data.
        String responseData = "Response data"
        server = new TestHTTPServer(defaultServerHTTPPort)
        server.addHandler(new HttpServlet() {
            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
                String requestURL = request.getRequestURL()
                if (requestURL.contains("/messageprocessor/spam")) {
                    response.sendError(429, "SPAM message detected.")
                    return
                }

                byte[] requestBodyInput =  request.getInputStream().getBytes()
                if (request.getMethod() != "POST") {
                    response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Only supporting POST request method.")
                } else if (request.getContentType().toLowerCase() != "text/xml; charset=utf-8") {
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Only supporting content type text/xml.")
                } else if (!requestBodyInput) {
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid message")
                } else {
                    response.setContentType("text/xml")
                    response.setStatus(HttpServletResponse.SC_OK)
                    response.getOutputStream().write(responseData.bytes)
                }
            }
        }, "/")
        server.start()
    }

    def setup(){
        // create msgSender poiting to the port of the jetty server.
        msgSender = new DefaultHTTPMsgSender("http://localhost:8089/messageprocessor")
    }


    def "Verify that synchronous msg sending works."(){
        when:
        def resp = msgSender.sendMsg("RequestData".getBytes())

        then:
        assert new String(resp, "UTF-8") == "Response data"
    }

    def "Verify that asynchronous msg sending works."(){
        setup:
        def asyncCallBack = new TestMsgCallback()

        when:
        msgSender.sendMsg("RequestData".getBytes(), asyncCallBack)
        int retries = 0
        while(!asyncCallBack.responseData && (retries++) < 50){
            Thread.sleep(100)
        }
        then:
        assert new String(asyncCallBack.responseData, "UTF-8") == "Response data"
    }

    @Unroll
    def "Verify that correct exception #exception is throws for error HTTP code #errocode "(){
        setup:
        def e
        when:
        // Verify that returning a specific error code results in an exception.
        if(errocode == "4"){
            msgSender = new DefaultHTTPMsgSender("http://localhost:8089/messageprocessors", "POST")
        }else{
            msgSender = new DefaultHTTPMsgSender("http://localhost:8099/messageprocessors", "POST")
        }
        def resp = msgSender.sendMsg("".getBytes())
        then:
        e = thrown (Exception)
        if(exception == "MessageContentException"){
            assert e instanceof MessageContentException
            assert e.message.startsWith("Error sending message to ")
        }else{
            assert e instanceof IOException
        }
        where:
        errocode | exception 					| description
        "4"		 | "MessageContentException"	| "wrong request is sent."
        "5"		 | "IOException"				| "wrong port is accessed."
    }

    def "Verify that SpamProtectionException is thrown if server returns 429 (Too many requests) response code for synchronous call."(){
        when:

        msgSender = new DefaultHTTPMsgSender("http://localhost:8089/messageprocessor/spam", "POST")
        msgSender.sendMsg("".getBytes())
        then:
        def e = thrown (SpamProtectionException)
        e.message =~ "Error sending message to http://localhost:8089/messageprocessor/spam, got response code :429"
    }

    def "Verify that SpamProtectionException is thrown if server returns 429 (Too many requests) response code for asynchronous call."(){
        setup:
        def asyncCallBack = new TestMsgCallback()

        when:
        msgSender = new DefaultHTTPMsgSender("http://localhost:8089/messageprocessor/spam", "POST")
        msgSender.sendMsg("".getBytes(), asyncCallBack)
        then:
        int retries = 0
        while(!asyncCallBack.error && (retries++) < 50){
            Thread.sleep(100)
        }
        asyncCallBack.error instanceof SpamProtectionException
        asyncCallBack.error.message =~ "Error sending message to http://localhost:8089/messageprocessor/spam, got response code :429"
    }


    def cleanupSpec(){
        if(server!=null && server.isRunning()){
            server.stop()
            server = null

        }
    }

    class TestMsgCallback implements MsgSender.MsgCallback {

        byte[] responseData
        Exception error
        @Override
        void responseReceived(byte[] responseData) {
            this.responseData = responseData
        }

        @Override
        void errorOccurred(Exception e) {
            this.error = e
        }
    }

}
