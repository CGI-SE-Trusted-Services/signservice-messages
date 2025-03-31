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
package se.signatureservice.messages.csmessages;

import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.logging.Logger;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyName;
import javax.xml.crypto.dsig.keyinfo.RetrievalMethod;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;

import se.signatureservice.messages.MessageProcessingException;
import se.signatureservice.messages.MessageSecurityProvider;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Special version of a key selector that only supports one X509Data containing
 * exactly one X509Certificate and returns it if it's valid and authorized.
 * <p>
 * It also contains a help method to return the X509Certificate in
 */
public class X509DataOnlyKeySelector extends KeySelector {
	
	protected static Logger log = Logger.getLogger(X509DataOnlyKeySelector.class.getName());

	protected MessageSecurityProvider pkiMessageSecurityProvider;
	
	/**
	 * Default constructor.
	 * @param pkiMessageSecurityProvider the provider to use.
	 */
	public X509DataOnlyKeySelector(MessageSecurityProvider pkiMessageSecurityProvider){
		this.pkiMessageSecurityProvider = pkiMessageSecurityProvider;
	}

	/**
	 * Finds a certificate from the key info part of the signed message
	 * and checks it with the security provider if it's valid and authorized.
	 *
	 * 
	 *
	 * @param keyInfo a <code>KeyInfo</code> (may be <code>null</code>)
	 * @param purpose the key's purpose
	 * @param method the algorithm method that this key is to be used for.
	 *    Only keys that are compatible with the algorithm and meet the
	 *    constraints of the specified algorithm should be returned.
	 * @param context an <code>XMLCryptoContext</code> that may contain additional
	 *    useful information for finding an appropriate key
	 * @return a key selector result
	 * @throws KeySelectorException if an exceptional condition occurs while
	 *    attempting to find a key. Note that an inability to find a key is not
	 *    considered an exception (<code>null</code> should be
	 *    returned in that case). However, an error condition (ex: network
	 *    communications failure) that prevented the <code>KeySelector</code>
	 *    from finding a potential key should be considered an exception.
	 * @throws ClassCastException if the data type of <code>method</code>
	 *    is not supported by this key selector
	 */
	public KeySelectorResult select(KeyInfo keyInfo, 
			KeySelector.Purpose purpose, AlgorithmMethod method,
			XMLCryptoContext context) throws KeySelectorException {


		SignatureMethod sm = (SignatureMethod) method;

		String organisation = findOrganisation(context);

		// Iterate through KeyInfo types
		Iterator<?> i = keyInfo.getContent().iterator();
		while (i.hasNext()) {
			XMLStructure kiType = (XMLStructure) i.next();
			// check X509Data
			if (kiType instanceof X509Data) {
				X509Data xd = (X509Data) kiType;
				KeySelectorResult ksr = x509DataSelect(xd, sm, organisation);
				if (ksr != null) {
					return ksr;
				}
			} else if (kiType instanceof KeyName) {
				log.fine("Recieved digitally signed message with unsupported KeyName in KeyInfo, skipping.");
			} else if (kiType instanceof RetrievalMethod) {
				log.fine("Recieved digitally signed message with unsupported KeyName in RetrievalMethod, skipping.");
			}
		}


		// return null since no match could be found
		return new SimpleKeySelectorResult(null);
	}

	/**
	 * Help method that extracts the organisation name or throws KeySelectorException if not found.
	 * @param context the context, must be a DOMValidateContext
	 * @return the organisation name set in the organisation field.
	 */
	private String findOrganisation(XMLCryptoContext context) throws KeySelectorException {
		String retval = null;
		if(!(context instanceof DOMValidateContext)){
			throw new KeySelectorException("Invalid XMLCryptoContext, a DOMValidateContext is required to extract organisation name.");
		}
		
		DOMValidateContext ctx = (DOMValidateContext) context;
		NodeList csMessageChilds = ctx.getNode().getParentNode().getChildNodes();
		for(int i= 0; i < csMessageChilds.getLength(); i++){
			Node next = csMessageChilds.item(i);
			if(next.getLocalName().equals("organisation")){
				retval = next.getTextContent();
				break;
			}
		}		
		
		if(retval == null){
			throw new KeySelectorException("Error couldn't find required organisation name in message");
		}		
		return retval;
	}

	/**
	 * A simple KeySelectorResult containing a public key.
	 */
	private static class SimpleKeySelectorResult implements KeySelectorResult {
		private final Key key;
		SimpleKeySelectorResult(Key key) { this.key = key; }
		public Key getKey() { return key; }
	}

	/**
	 * Searches the specified key info for a certificate that is valid
	 * and authorized to sign.
	 *
	 * @return a KeySelectorResult containing the cert's public key if there
	 *   is a match; otherwise null
	 */
	private KeySelectorResult x509DataSelect(X509Data xd, SignatureMethod sm, String organisation) 
			throws KeySelectorException {

		KeySelectorResult ksr = null;
		Iterator<?> xi = xd.getContent().iterator();
		while (xi.hasNext()) {
			ksr = null;
			Object o = xi.next();
			// check X509Certificate
			if (o instanceof X509Certificate) {
				X509Certificate xcert = (X509Certificate) o;
				try{
					if(pkiMessageSecurityProvider.isValidAndAuthorized(xcert, organisation)){
						ksr = new SimpleKeySelectorResult(xcert.getPublicKey());
					}else{
						log.fine("A certificate with DN " + xcert.getSubjectDN().toString() + " signing a message wasn't authorized or valid.");
					}
				}catch(IllegalArgumentException e){
					throw new KeySelectorException(e.getMessage(),e);
				}catch(MessageProcessingException e){
					throw new KeySelectorException(e.getMessage(),e);	
				}			
			} else if (o instanceof X509IssuerSerial) {
				log.fine("Recieved digitally signed message with unsupported X509Data with X509IssuerSerial, skipping.");
			} else if (o instanceof String) {
				log.fine("Recieved digitally signed message with unsupported X509Data with String, only X509Certificate supported, skipping.");
			} else if (o instanceof byte[]) {
				log.fine("Recieved digitally signed message with unsupported X509Data with String, only SPKIInfo supported, skipping.");
			} else {
				// skip all other entries
				continue;
			}
			if (ksr != null) {
				return ksr;
			}
		}
		return null;
	}
}


