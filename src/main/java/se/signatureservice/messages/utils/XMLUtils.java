/************************************************************************
 *                                                                       *
 *  Signature Service - Messages                                         *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.messages.utils;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

/**
 * Class containing various utility methods when parsing, processing and working
 * with XML files.
 *
 * @author Tobias Agerberg
 */
public class XMLUtils {

    /**
     * Create new instance of a document builder factory with secure features
     * enabled. The document builder created by this method will not allow DOCTYPE or
     * external DTDs.
     *
     * @return New instance of DocumentBuilderFactory.
     * @throws ParserConfigurationException If DocumentBuilderFactory could not be created due to unsupported features.
     */
    public static DocumentBuilderFactory createSecureDocumentBuilderFactory() throws ParserConfigurationException {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        documentBuilderFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        documentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        documentBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        documentBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-dtd-grammar", false);
        return documentBuilderFactory;
    }
}
