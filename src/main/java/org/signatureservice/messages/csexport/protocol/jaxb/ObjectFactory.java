//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2017.01.04 at 02:14:36 PM MSK 
//


package org.signatureservice.messages.csexport.protocol.jaxb;

import jakarta.xml.bind.annotation.XmlRegistry;


/**
 * This object contains factory methods for each 
 * Java content interface and Java element interface 
 * generated in the org.certificateservices.messages.csexport.protocol.jaxb package.
 * <p>An ObjectFactory allows you to programatically 
 * construct new instances of the Java representation 
 * for XML content. The Java representation of XML 
 * content can consist of schema derived interfaces 
 * and classes representing the binding of schema 
 * type definitions, element declarations and model 
 * groups.  Factory methods for each of these are 
 * provided in this class.
 * 
 */
@XmlRegistry
public class ObjectFactory {


    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: org.certificateservices.messages.csexport.protocol.jaxb
     * 
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link GetCSExportRequest }
     * 
     */
    public GetCSExportRequest createGetCSExportRequest() {
        return new GetCSExportRequest();
    }

    /**
     * Create an instance of {@link GetCSExportRequest.QueryParameters }
     * 
     */
    public GetCSExportRequest.QueryParameters createGetCSExportRequestQueryParameters() {
        return new GetCSExportRequest.QueryParameters();
    }

    /**
     * Create an instance of {@link GetCSExportResponse }
     * 
     */
    public GetCSExportResponse createGetCSExportResponse() {
        return new GetCSExportResponse();
    }

    /**
     * Create an instance of {@link Result }
     * 
     */
    public Result createResult() {
        return new Result();
    }

    /**
     * Create an instance of {@link QueryParameter }
     * 
     */
    public QueryParameter createQueryParameter() {
        return new QueryParameter();
    }

}
