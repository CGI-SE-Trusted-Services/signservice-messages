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
package org.certificateservices.messages.csmessages;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;

import org.certificateservices.messages.MessageProcessingException;
import org.w3c.dom.ls.LSInput;

/**
 * XSD Input implementation of a LSInput Interface used when resolving references inside XSD
 * schema to avoid external look-ups.
 * 
 * @author Philip Vendil
 *
 */
public class XSDLSInput implements LSInput {
	
	private String publicId;
	private String systemId;
	private String content;
	
	/**
	 * Default constructor.
	 * 
	 * @param publicId the publicId of the schema.
	 * @param systemId the systemId of the schema
	 * @param content the schema data.
	 */
	public XSDLSInput(String publicId, String systemId, String content){
	    this.publicId = publicId;
	    this.systemId = systemId;
	    this.content = content;

	}
	
	/**
	 * Alternate contructor with input stream of the schema as argument.
	 * 
	 * @param publicId the publicId of the schema.
	 * @param systemId the systemId of the schema
	 * @param resourceAsStream the input stream containing schema data.
	 * @throws MessageProcessingException if problems occurred reading the schema from class path
	 */
	public XSDLSInput(String publicId, String systemId, InputStream resourceAsStream) throws MessageProcessingException{
	    this.publicId = publicId;
	    this.systemId = systemId;
	    
		try {		
			synchronized (resourceAsStream) {
				byte[] i = new byte[resourceAsStream.available()];
				resourceAsStream.read(i);
				this.content = new String(i);
				resourceAsStream.close();
			}
		} catch (IOException e) {
			throw new MessageProcessingException("Error reading XSD " + systemId + " from jar or classpath.");
		}
	    
	}
	
	/**
	 * @see org.w3c.dom.ls.LSInput#getBaseURI()
	 */
	
	public String getBaseURI() {
	    return null;
	}

	/**
	 * @see org.w3c.dom.ls.LSInput#getByteStream()
	 */
	
	public InputStream getByteStream() {
		return null;
	}

	/**
	 * @see org.w3c.dom.ls.LSInput#getCertifiedText()
	 */
	
	public boolean getCertifiedText() {
		return false;
	}

	/**
	 * @see org.w3c.dom.ls.LSInput#getCharacterStream()
	 */
	
	public Reader getCharacterStream() {		
		return null;
	}

	/**
	 * @see org.w3c.dom.ls.LSInput#getEncoding()
	 */
	
	public String getEncoding() {
		return null;
	}

	/**
	 * @see org.w3c.dom.ls.LSInput#getPublicId()
	 */
	
	public String getPublicId() {
		return publicId;
	}

	/**
	 * @see org.w3c.dom.ls.LSInput#getStringData()
	 */
	
	public String getStringData() {
		return content;
	}

	/**
	 * @see org.w3c.dom.ls.LSInput#getSystemId()
	 */
	
	public String getSystemId() {
		return systemId;
	}

	/**
	 * @see org.w3c.dom.ls.LSInput#setBaseURI(java.lang.String)
	 */
	
	public void setBaseURI(String baseURI) {
	}

	/**
	 * @see org.w3c.dom.ls.LSInput#setByteStream(java.io.InputStream)
	 */
	
	public void setByteStream(InputStream byteStream) {
	}

	/**
	 * @see org.w3c.dom.ls.LSInput#setCertifiedText(boolean)
	 */
	
	public void setCertifiedText(boolean certifiedText) {
	}

	/**
	 * @see org.w3c.dom.ls.LSInput#setCharacterStream(java.io.Reader)
	 */
	
	public void setCharacterStream(Reader characterStream) {
	}

	/**
	 * @see org.w3c.dom.ls.LSInput#setEncoding(java.lang.String)
	 */
	
	public void setEncoding(String encoding) {
	}

	/**
	 * @see org.w3c.dom.ls.LSInput#setPublicId(java.lang.String)
	 */
	
	public void setPublicId(String publicId) {
		this.publicId = publicId;
	}

	/**
	 * @see org.w3c.dom.ls.LSInput#setStringData(java.lang.String)
	 */
	
	public void setStringData(String stringData) {
		throw new IllegalArgumentException("Error method setStringData not supported.");
	}

	/**
	 * @see org.w3c.dom.ls.LSInput#setSystemId(java.lang.String)
	 */
	
	public void setSystemId(String systemId) {
		this.systemId = systemId;
	}
	


}
