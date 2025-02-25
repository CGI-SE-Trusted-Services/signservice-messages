package org.signatureservice.messages.sweeid2.dssextenstions1_1;

/**
 * Enumerates available MimeType values for SignMessages.
 *
 * Created by philip on 10/01/17.
 */
public enum SignMessageMimeType {
    HTML("text/html"),
    TEXT("text"),
    MARKDOWN("text/markdown");

    private String mimeType;
    SignMessageMimeType(String mimeType){
        this.mimeType = mimeType;
    }

    public String getMimeType(){
        return mimeType;
    }
}
