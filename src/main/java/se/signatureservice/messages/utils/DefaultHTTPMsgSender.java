package se.signatureservice.messages.utils;

import se.signatureservice.messages.MessageContentException;
import se.signatureservice.messages.MessageProcessingException;
import se.signatureservice.messages.SpamProtectionException;
import se.signatureservice.messages.TimeoutException;

import java.io.IOException;
import java.net.MalformedURLException;

/**
 * DefaultHTTPMsgSender sending a byte[] array to a given URL.
 *
 * Created by Philip Vendil on 16/06/16.
 */
public class DefaultHTTPMsgSender extends BaseHTTPSender implements MsgSender {


    /**
     * Main constructor for POST requests
     *
     * @param url the URL to connect to.
     * @throws MalformedURLException if URL was malformed.
     */
    public DefaultHTTPMsgSender(String url) throws MalformedURLException {
        super(url, "POST", "text/xml; charset=utf-8");
    }

    /**
     * Main constructor where it is possible to specify request type.
     *
     * @param url the URL to connect to.
     * @param requestType the HTTP request type in upper case (For example POST, GET)
     * @throws MalformedURLException if URL was malformed.
     */
    public DefaultHTTPMsgSender(String url, String requestType) throws MalformedURLException {
        super(url, requestType, "text/xml; charset=utf-8");

    }

    @Override
    public byte[] sendMsg(byte[] request) throws MessageContentException, MessageProcessingException, IOException,
            SpamProtectionException, TimeoutException {
        return super.sendMsg(request);
    }

    @Override
    public void sendMsg(byte[] request, MsgCallback callback) {
        super.sendMsg(request,callback);
    }

}
