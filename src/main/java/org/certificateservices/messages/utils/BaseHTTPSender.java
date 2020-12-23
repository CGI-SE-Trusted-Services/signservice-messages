package org.certificateservices.messages.utils;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.SpamProtectionException;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;

/**
 * Abstract Base implementation of a MsgSender using HTTP.
 * Created by Philip Vendil on 23/06/16.
 */
public abstract class BaseHTTPSender {

    protected URL baseURL;
    protected String requestType;
    protected String outputContentType;

    /**
     * Main constructor where it is possible to specify request type.
     *
     * @param url the URL to connect to.
     * @param requestType the HTTP request type in upper case (For example POST, GET)
     * @param outputContentType the content type on the output data.
     * @throws MalformedURLException if URL was malformed.
     */
    public BaseHTTPSender(String url, String requestType, String outputContentType) throws MalformedURLException {
        this.baseURL = new URL(url);
        this.requestType = requestType;
        this.outputContentType = outputContentType;

    }

    /**
     * Synchronous call to test connection to the given url.
     *
     * @return true if connection is working, otherwise false.
     */
    public boolean testConnection(){
        boolean isConnected = false;
        HttpURLConnection connection = null;
        if(baseURL == null){
            return isConnected;
        }
        try {
            connection = (HttpURLConnection) baseURL.openConnection();
            connection.connect();
            isConnected = true;
        } catch (IOException e) {

        }finally{
            if(connection != null){
                connection.disconnect();
            }

        }

        return isConnected;
    }

    /**
     * Synchronous call for sending HTTP request sending data in the HTTP request body (usually using POST)
     * @param request the data to send.
     * @return the response data.
     * @throws MessageContentException if request contained illegal content.
     * @throws MessageProcessingException if internal problems occurred processing the request at the server.
     * @throws IOException if communication problems occurred.
     * @throws SpamProtectionException if server side regarded call as a SPAM request and denied it.
     */
    protected byte[] sendMsg(byte[] request) throws MessageContentException, MessageProcessingException, IOException, SpamProtectionException {
        BaseHTTPSender.SynchronousCallback callback = new BaseHTTPSender.SynchronousCallback();
        BaseHTTPSender.SendMsgRunnable sendMsgRunnable = new BaseHTTPSender.SendMsgRunnable(request, callback);
        sendMsgRunnable.run(); // Run syncronically
        if(callback.error != null){
            if(callback.error instanceof MessageContentException){
                throw (MessageContentException) callback.error;
            }
            if(callback.error instanceof MessageProcessingException){
                throw (MessageProcessingException) callback.error;
            }
            if(callback.error instanceof IOException){
                throw (IOException) callback.error;
            }
            if(callback.error instanceof SpamProtectionException){
                throw (SpamProtectionException) callback.error;
            }
            throw new MessageProcessingException("Error sending message to " + baseURL + " : " + callback.error.getMessage(), callback.error);
        }
        return callback.responseData;
    }

    /**
     * Asynchronous call for sending HTTP request sending data in the HTTP request body (usually using POST)
     * @param request the data to send.
     * @param callback the callback to signal the result to.
     * @return the response data.
     */
    protected void sendMsg(byte[] request, MsgSender.MsgCallback callback) {
        Thread t = new Thread(new BaseHTTPSender.SendMsgRunnable(request,callback));
        t.start();
    }

    /**
     * Asynchronous call for sending HTTP request with parameters in URL string (usually using GET)
     * @param parameters the parameter string to send (without ?)
     * @param callback the callback to signal the result to.
     * @return the response data.
     */
    protected void sendMsg(String parameters, MsgSender.MsgCallback callback) throws MessageContentException {
        Thread t = new Thread(new BaseHTTPSender.SendMsgRunnable(parameters,callback));
        t.start();
    }


    /**
     * Synchronous call for sending HTTP request with parameters in URL string (usually using GET)
     * @param parameters the parameter string to send (without ?)
     * @return the response data.
     * @throws MessageContentException if request contained illegal content.
     * @throws MessageProcessingException if internal problems occurred processing the request at the server.
     * @throws IOException if communication problems occurred.
     * @throws SpamProtectionException if server side regarded call as a SPAM request and denied it.
     */
    protected byte[] sendMsg(String parameters) throws MessageContentException, MessageProcessingException, IOException, SpamProtectionException {
        BaseHTTPSender.SynchronousCallback callback = new BaseHTTPSender.SynchronousCallback();
        BaseHTTPSender.SendMsgRunnable sendMsgRunnable = new BaseHTTPSender.SendMsgRunnable(parameters, callback);
        sendMsgRunnable.run(); // Run syncronically
        if(callback.error != null){
            if(callback.error instanceof MessageContentException){
                throw (MessageContentException) callback.error;
            }
            if(callback.error instanceof MessageProcessingException){
                throw (MessageProcessingException) callback.error;
            }
            if(callback.error instanceof IOException){
                throw (IOException) callback.error;
            }
            if(callback.error instanceof SpamProtectionException){
                throw (SpamProtectionException) callback.error;
            }
            throw new MessageProcessingException("Error sending message to " + baseURL + " : " + callback.error.getMessage(), callback.error);
        }
        return callback.responseData;
    }



    /**
     * Runnable that sends a HTTP call and wait for the response.
     */
    protected class SendMsgRunnable implements Runnable{

        byte[] request;
        String parameters = null;
        MsgSender.MsgCallback callback;
        boolean doOutput= false;
        URL url;


        /**
         * Constructor when sending a byte array output (Usually using POST)
         * @param request the request data to send.
         * @param callback the callback to signal result to.
         */
        protected SendMsgRunnable(byte[] request, MsgSender.MsgCallback callback){
            this.request = request;
            this.callback = callback;
            this.doOutput = true;
            url = baseURL;
        }

        /**
         * Constructor when sending data as parameters in the URL (Usually using GET)
         * @param parameters the parameters (excluding ?) to use in the request.
         * @param callback the callback to signal result to.
         */
        protected SendMsgRunnable(String parameters, MsgSender.MsgCallback callback)  throws MessageContentException{
            this.parameters = parameters;
            this.callback = callback;
            try {
                url = new URL(baseURL.toString() + "?" + parameters);
            }catch(MalformedURLException e){
                throw new MessageContentException("Error building GET request to server, invalid URL parameters: " + parameters, e);
            }
        }

        @Override
        public void run() {
            try {
                HttpURLConnection con = (HttpURLConnection) url.openConnection();
                con.setRequestMethod(requestType);
                con.setRequestProperty("content-type", outputContentType);
                if(doOutput && request != null) {
                    con.setDoOutput(true);
                    OutputStream os = con.getOutputStream();
                    os.write(request);
                    os.flush();
                    os.close();
                }

                int httpStatus = con.getResponseCode();
                int responseCode = httpStatus / 100;

                if(responseCode == 2){
                    DataInputStream inputStream = new DataInputStream(con.getInputStream());
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    byte[] buffer = new byte[0xFFFF];
                    int n;
                    while ((n = inputStream.read(buffer)) != -1) {
                        baos.write(buffer, 0, n);
                    }
                    inputStream.close();
                    callback.responseReceived(baos.toByteArray());
                }else {
                    if(httpStatus == 429){
                        callback.errorOccurred(new SpamProtectionException("Error sending message to " + url + ", got response code :" + con.getResponseCode() + " message: " + con.getResponseMessage()));
                    }else {
                        if (responseCode == 4) {
                            callback.errorOccurred(new MessageContentException("Error sending message to " + url + ", got response code :" + con.getResponseCode() + " message: " + con.getResponseMessage()));
                        } else {
                            callback.errorOccurred(new MessageProcessingException("Error sending message to " + url + ", got response code :" + con.getResponseCode() + " message: " + con.getResponseMessage()));
                        }
                    }
                }

            }catch(ProtocolException e){
                callback.errorOccurred(new MessageProcessingException("Error sending message to " + url + ": " + e.getMessage(),e));
            }catch(IOException e){
                callback.errorOccurred(e);
            }
        }
    }

    /**
     * Special case callback used for syncronious request calls.
     */
    protected class SynchronousCallback implements MsgSender.MsgCallback {

        byte[] responseData;
        Exception error;
        @Override
        public void responseReceived(byte[] responseData) {
            this.responseData = responseData;
        }

        @Override
        public void errorOccurred(Exception e) {
            this.error = e;
        }
    }
}
