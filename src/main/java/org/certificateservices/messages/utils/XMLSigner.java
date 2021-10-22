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

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.logging.Logger;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.utils.Base64;
import org.certificateservices.messages.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import org.certificateservices.messages.ContextMessageSecurityProvider.Context;

/**
 * Class containing help methods for digital XML signatures
 * 
 * @author Philip Vendil
 *
 */
public class XMLSigner {
	
	public static String XMLDSIG_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#";
	
	private static String ENVELOPE_TRANSFORM = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
	private static String C14N_TRANSFORM = "http://www.w3.org/2001/10/xml-exc-c14n#";

	static Logger log = Logger.getLogger(XMLSigner.class.getName());

	static SystemTime systemTime = new DefaultSystemTime();
	private DocumentBuilder documentBuilder;
	private CertificateFactory cf;
	private SignatureLocationFinder defaultSignatureLocationFinder;
	private OrganisationLookup defaultOrganisationLookup;

	private Set<String> supportedDigestsAlgorithm;
	private Set<String> supportedSignatureAlgorithm;
	private MessageSecurityProvider messageSecurityProvider;
	private Transformer transformer;
	private boolean signMessages;


	/**
	 * Constructor used for context based message security providers.
     */
	public XMLSigner(MessageSecurityProvider messageSecurityProvider,
					 DocumentBuilder documentBuilder,
					 boolean signMessages,
					 SignatureLocationFinder defaultSignatureLocationFinder,
					 OrganisationLookup defaultOrganisationLookup) throws MessageProcessingException{

		this.messageSecurityProvider = messageSecurityProvider;
		this.defaultSignatureLocationFinder = defaultSignatureLocationFinder;
		this.defaultOrganisationLookup = defaultOrganisationLookup;
		this.documentBuilder = documentBuilder;
		this.signMessages = signMessages;


		try {
			cf = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new MessageProcessingException("Error instanciating CertificateFactory for XMLSigner: " + e.getMessage(),e);
		}

		supportedDigestsAlgorithm = new HashSet<String>();
		supportedSignatureAlgorithm = new HashSet<String>();
		for(SigningAlgorithmScheme scheme : SigningAlgorithmScheme.values()){
			supportedDigestsAlgorithm.add(scheme.getHashAlgorithmURI());
			supportedSignatureAlgorithm.add(scheme.getSignatureAlgorithmURI());
		}

		TransformerFactory tf = TransformerFactory.newInstance();
		try {
			transformer = tf.newTransformer();
		} catch (TransformerConfigurationException e) {
			throw new MessageProcessingException("Error creating Transformer for XMLSigner: " + e.getMessage(),e);
		}

	}


	/**
	 * Help method to verify a signed enveloped message and performs the following checks. Using
	 * the default context.
	 *
	 * <li>That the signature if included X509Certificate verifies.
	 * <li>That the signatures algorithms is one of supported signature schemes.
	 * <li>That the signature method is enveloped.
	 * <p>
	 * This method does not perform and authorization call towards message security provider.
	 *
	 * @param message the message to verify signature of.
	 * @throws MessageContentException if message content was faulty
	 * @throws MessageProcessingException if internal error occurred verifying the signature.
	 */
	@Deprecated
	public void verifyEnvelopedSignature(byte[] message) throws MessageContentException, MessageProcessingException{
		verifyEnvelopedSignature(ContextMessageSecurityProvider.DEFAULT_CONTEXT,message, false);
	}
	
	/**
	 * Help method to verify a signed enveloped message and performs the following checks.
	 * 
	 * <li>That the signature if included X509Certificate verifies.
	 * <li>That the signatures algorithms is one of supported signature schemes.
	 * <li>That the signature method is enveloped.
	 * <p>
	 * This method does not perform and authorization call towards message security provider.
	 *
	 * @param context the related message security context
	 * @param message the message to verify signature of.
	 * @throws MessageContentException if message content was faulty
	 * @throws MessageProcessingException if internal error occurred verifying the signature.
	 */
	public void verifyEnvelopedSignature(Context context, byte[] message) throws MessageContentException, MessageProcessingException{
		  verifyEnvelopedSignature(context, message, false);
	}

	/**
	 * Help method to verify a signed enveloped message and performs the following checks.
	 * Using the default message security context.
	 *
	 * <li>That the signature if included X509Certificate verifies.
	 * <li>That the signatures algorithms is one of supported signature schemes.
	 * <li>That the signature method is enveloped.
	 *
	 * @param message the message to verify signature of.
	 * @param authorizeAgainstOrganisation true if the message security provider should perform
	 * any authorization to the related organisation, that must exist in the message of true.
	 * @throws MessageContentException if message content was faulty
	 * @throws MessageProcessingException if internal error occured verifying the signature.
	 */
	@Deprecated
	public void verifyEnvelopedSignature(byte[] message, boolean authorizeAgainstOrganisation) throws MessageContentException, MessageProcessingException{
		verifyEnvelopedSignature(ContextMessageSecurityProvider.DEFAULT_CONTEXT,message,authorizeAgainstOrganisation);
	}
	/**
	 * Help method to verify a signed enveloped message and performs the following checks.
	 * 
	 * <li>That the signature if included X509Certificate verifies.
	 * <li>That the signatures algorithms is one of supported signature schemes.
	 * <li>That the signature method is enveloped.
	 *
	 * @param context the related message security context
	 * @param message the message to verify signature of.
	 * @param authorizeAgainstOrganisation true if the message security provider should perform
	 * any authorization to the related organisation, that must exist in the message of true.
	 * @throws MessageContentException if message content was faulty
	 * @throws MessageProcessingException if internal error occured verifying the signature.
	 */
	public void verifyEnvelopedSignature(Context context, byte[] message, boolean authorizeAgainstOrganisation) throws MessageContentException, MessageProcessingException{
		Document doc;
		try{
			doc = documentBuilder.parse(new ByteArrayInputStream(message));		
		}catch(Exception e){
			throw new MessageContentException("Error validating signature of message: " + e.getMessage(),e);
		}
		verifyEnvelopedSignature(context, doc, authorizeAgainstOrganisation);
	}

	/**
	 * Help method to verify a signed enveloped CS message and performs the following checks.
	 * Using the default message security context.
	 *
	 * <li>That the signature if included X509Certificate verifies.
	 * <li>That the signatures algorithms is one of supported signature schemes.
	 * <li>That the signature method is enveloped.
	 *
	 * @param doc the message to verify signature of.
	 * @param performValidation true if the message security provider should perform
	 * validate that the signing certificate is valid and authorized for related organisation.
	 * Otherwise must validation be performed manually after the message is parsed.
	 * @throws MessageContentException if message content was faulty
	 * @throws MessageProcessingException if internal error occured verifying the signature.
	 */
	@Deprecated
	public void verifyEnvelopedSignature(Document doc, boolean performValidation) throws MessageContentException, MessageProcessingException{
		verifyEnvelopedSignature(ContextMessageSecurityProvider.DEFAULT_CONTEXT,doc,performValidation);
	}

	/**
	 * Help method to verify a signed enveloped CS message and performs the following checks.
	 *
	 * <li>That the signature if included X509Certificate verifies.
	 * <li>That the signatures algorithms is one of supported signature schemes.
	 * <li>That the signature method is enveloped.
	 *
	 * @param context the related message security context
	 * @param doc the message to verify signature of.
	 * @param performValidation true if the message security provider should perform
	 * validate that the signing certificate is valid and authorized for related organisation.
	 * Otherwise must validation be performed manually after the message is parsed.
	 * @throws MessageContentException if message content was faulty
	 * @throws MessageProcessingException if internal error occured verifying the signature.
	 */
	public void verifyEnvelopedSignature(Context context, Document doc, boolean performValidation) throws MessageContentException, MessageProcessingException{
		verifyEnvelopedSignature(context, doc, (performValidation ? defaultOrganisationLookup : null));
	}

	/**
	 * Help method to verify a signed enveloped message and performs the following checks. Using the
	 * default signature location finder.
	 *
	 * <li>That the signature if included X509Certificate verifies.
	 * <li>That the signatures algorithms is one of supported signature schemes.
	 * <li>That the signature method is enveloped.
	 *
	 * @param context the related message security context
	 * @param doc the message to verify signature of.
	 * @param organisationLookup implementation to extract organsiation name from a given XML message.
	 * If null must validation be performed manually after the message is parsed. It is possible to use the
	 * checkBasicCertificateValidation help method for this.
	 * @throws MessageContentException if message content was faulty
	 * @throws MessageProcessingException if internal error occured verifying the signature.
	 */
	public void verifyEnvelopedSignature(Context context, Document doc, OrganisationLookup organisationLookup) throws MessageContentException, MessageProcessingException{
		verifyEnvelopedSignature(context, doc,defaultSignatureLocationFinder,organisationLookup);
	}

	/**
	 * Help method to verify a signed enveloped message and performs the following checks. Using the
	 * default signature location finder.
	 * Using the default message security context.
	 *
	 * <li>That the signature if included X509Certificate verifies.
	 * <li>That the signatures algorithms is one of supported signature schemes.
	 * <li>That the signature method is enveloped.
	 * 
	 * @param doc the message to verify signature of.
	 * @param organisationLookup implementation to extract organsiation name from a given XML message.
	 * If null must validation be performed manually after the message is parsed. It is possible to use the
	 * checkBasicCertificateValidation help method for this.
	 * @throws MessageContentException if message content was faulty
	 * @throws MessageProcessingException if internal error occured verifying the signature.
	 */
	@Deprecated
	public void verifyEnvelopedSignature(Document doc, OrganisationLookup organisationLookup) throws MessageContentException, MessageProcessingException{
		verifyEnvelopedSignature(doc,defaultSignatureLocationFinder,organisationLookup);
	}
	/**
	 * Help method to verify a signed enveloped message and performs the following checks.
	 * Using the default message security context.
	 *
	 * <li>That the signature if included X509Certificate verifies.
	 * <li>That the signatures algorithms is one of supported signature schemes.
	 * <li>That the signature method is enveloped.
	 *
	 * @param message the message to verify signature of.
	 * @param signatureLocationFinder reference to implementation finding the signature element of a document. (Required)
	 * @param organisationLookup implementation to extract organsiation name from a given XML message.
	 * If null must validation be performed manually after the message is parsed. It is possible to use the
	 * checkBasicCertificateValidation help method for this.
	 * @throws MessageContentException if message content was faulty
	 * @throws MessageProcessingException if internal error occured verifying the signature.
	 */
	@Deprecated
	public void verifyEnvelopedSignature(byte[] message, SignatureLocationFinder signatureLocationFinder, OrganisationLookup organisationLookup) throws MessageContentException, MessageProcessingException {
		verifyEnvelopedSignature(ContextMessageSecurityProvider.DEFAULT_CONTEXT,message,signatureLocationFinder,organisationLookup);
	}

	/**
	 * Help method to verify a signed enveloped message and performs the following checks.
	 *
	 * <li>That the signature if included X509Certificate verifies.
	 * <li>That the signatures algorithms is one of supported signature schemes.
	 * <li>That the signature method is enveloped.
	 *
	 * @param context the related message security context
	 * @param message the message to verify signature of.
	 * @param signatureLocationFinder reference to implementation finding the signature element of a document. (Required)
	 * @param organisationLookup implementation to extract organsiation name from a given XML message.
	 * If null must validation be performed manually after the message is parsed. It is possible to use the
	 * checkBasicCertificateValidation help method for this.
	 * @throws MessageContentException if message content was faulty
	 * @throws MessageProcessingException if internal error occured verifying the signature.
	 */
	public void verifyEnvelopedSignature(Context context, byte[] message, SignatureLocationFinder signatureLocationFinder, OrganisationLookup organisationLookup) throws MessageContentException, MessageProcessingException {
		Document doc;
		try{
			doc = documentBuilder.parse(new ByteArrayInputStream(message));
		}catch(Exception e){
			throw new MessageContentException("Error validating signature of message: " + e.getMessage(),e);
		}
		verifyEnvelopedSignature(context, doc, signatureLocationFinder, organisationLookup);
	}

	/**
	 * Help method to verify a signed enveloped message and performs the following checks, using
	 * the default context.
	 * Using the default message security context.
	 * <li>That the signature if included X509Certificate verifies.
	 * <li>That the signatures algorithms is one of supported signature schemes.
	 * <li>That the signature method is enveloped.
	 *
	 * @param doc the message to verify signature of.
	 * @param signatureLocationFinder reference to implementation finding the signature element of a document. (Required)
	 * @param organisationLookup implementation to extract organsiation name from a given XML message.
	 * If null is basic validation performed such as key usage and expiration, but no revocation checks.
	 * @throws MessageContentException if message content was faulty
	 * @throws MessageProcessingException if internal error occured verifying the signature.
	 */
	@Deprecated
	public void verifyEnvelopedSignature(Document doc, SignatureLocationFinder signatureLocationFinder, OrganisationLookup organisationLookup) throws MessageContentException, MessageProcessingException {
		verifyEnvelopedSignature(ContextMessageSecurityProvider.DEFAULT_CONTEXT,doc,signatureLocationFinder,organisationLookup);
	}

		/**
         * Help method to verify a signed enveloped message and performs the following checks.
         *
         * <li>That the signature if included X509Certificate verifies.
         * <li>That the signatures algorithms is one of supported signature schemes.
         * <li>That the signature method is enveloped.
         *
		 * @param context the related message security context
         * @param doc the message to verify signature of.
         * @param signatureLocationFinder reference to implementation finding the signature element of a document. (Required)
         * @param organisationLookup implementation to extract organsiation name from a given XML message.
         * If null is basic validation performed such as key usage and expiration, but no revocation checks.
         * @throws MessageContentException if message content was faulty
         * @throws MessageProcessingException if internal error occured verifying the signature.
         */
	public void verifyEnvelopedSignature(Context context, Document doc, SignatureLocationFinder signatureLocationFinder, OrganisationLookup organisationLookup) throws MessageContentException, MessageProcessingException{

		try{

			Element[] signedElements = signatureLocationFinder.getSignatureLocations(doc);
			for(Element signedElement: signedElements) {
				Element signature = findSignatureElementInObject(signedElement);

				checkValidSignatureURI(signature);
				checkValidDigestURI(signature);
				checkValidTransform(signature);
				checkValidReferenceURI(signedElement, signature, signatureLocationFinder.getIDAttribute());


				X509Certificate signerCert = null;
				NodeList certList = signature.getElementsByTagNameNS(XMLDSIG_NAMESPACE, "X509Certificate");
				if (certList.getLength() > 0) {
					String certData = certList.item(0).getFirstChild().getNodeValue();
					if (certData != null) {
						signerCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.decode(certData)));
					}
				}


				if (signerCert == null) {
					throw new MessageContentException("Invalid signature, no related certificate found.");
				}


				DOMValidateContext validationContext = new DOMValidateContext(signerCert.getPublicKey(), signature);
				String idAttribute = signatureLocationFinder.getIDAttribute();
				if(idAttribute != null) {
					validationContext.setIdAttributeNS(signedElement, null, signatureLocationFinder.getIDAttribute());
				}
				XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
				XMLSignature sig = signatureFactory.unmarshalXMLSignature(validationContext);
				if (!sig.validate(validationContext)) {
					throw new MessageContentException("Error, signed message didn't pass validation.");
				}

				String organisation = null;
				if (organisationLookup != null) {
					organisation = organisationLookup.findOrganisation(doc);
				}

				if(messageSecurityProvider instanceof ContextMessageSecurityProvider){
					if (!((ContextMessageSecurityProvider) messageSecurityProvider).isValidAndAuthorized(context,signerCert, organisation)) {
						throw new MessageContentException("A certificate with DN " + signerCert.getSubjectDN().toString() + " signing a message wasn't authorized or valid.");
					}
				}else{
					if (!messageSecurityProvider.isValidAndAuthorized(signerCert, organisation)) {
						throw new MessageContentException("A certificate with DN " + signerCert.getSubjectDN().toString() + " signing a message wasn't authorized or valid.");
					}
				}

			}

		}catch(Exception e){
			if(e instanceof MessageContentException ){
				throw (MessageContentException) e;
			}
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageContentException("Error validating signature of message: " + e.getMessage(),e);
		}
	}
	
	/**
	 * Method to find first certificate found in signature element using the default signature finder.
	 *
	 * @param message the message to extract certificate of.
	 * @return the certificate in signature.
	 * 
	 * @throws MessageContentException if message content was faulty
	 * @throws MessageProcessingException if internal error occurred parsing the certificate.
	 */
	public X509Certificate findSignerCertificate(byte[] message)  throws MessageContentException, MessageProcessingException{
		return findSignerCertificate(message,defaultSignatureLocationFinder);
	}

	/**
	 * Method to find first certificate found in signature element with specifieddefault signature finder.
	 *
	 * @param message the message to extract certificate of.
	 * @param signatureLocationFinder the custom signature location finder.
	 * @return the certificate in signature.
	 *
	 * @throws MessageContentException if message content was faulty
	 * @throws MessageProcessingException if internal error occurred parsing the certificate.
	 */
	public X509Certificate findSignerCertificate(byte[] message, SignatureLocationFinder signatureLocationFinder)  throws MessageContentException, MessageProcessingException{
		try{
			Document doc = documentBuilder.parse(new ByteArrayInputStream(message));

			Element signedElement = signatureLocationFinder.getSignatureLocations(doc)[0];
			Element signature = findSignatureElementInObject(signedElement);

			X509Certificate signerCert = null;
			NodeList certList = signature.getElementsByTagNameNS(XMLDSIG_NAMESPACE, "X509Certificate");
			if(certList.getLength() > 0){
				String certData = certList.item(0).getFirstChild().getNodeValue();
				if(certData != null){
					signerCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.decode(certData)));
				}
			}

			if(signerCert == null){
				throw new MessageContentException("Invalid signature, no related certificate found.");
			}

			return signerCert;

		}catch(Exception e){
			if(e instanceof MessageContentException ){
				throw (MessageContentException) e;
			}
			if(e instanceof MessageProcessingException){
				throw (MessageProcessingException) e;
			}
			throw new MessageContentException("Error parsing the certificate from signature in message: " + e.getMessage(),e);
		}
	}

	/**
	 * Help method that checks that certificate has:
	 * <li>Has digital signature key usage</li>
	 * <li>current time is withing not before and not after.</li>
	 * @param cert the certificate to check.
	 * @return true if valid otherwise false.
     */
	public static boolean checkBasicCertificateValidation(X509Certificate cert){
		boolean[] keyUsage = cert.getKeyUsage();
		if (keyUsage != null && keyUsage[0] == false) {
			log.severe("Error processing Certificate Services message signing certificate expired has not keyUsage digitalSignature.");
			return false;
		}

		Date currentTime = systemTime.getSystemTime();
		if(currentTime.after(cert.getNotAfter())){
			log.severe("Error processing Certificate Services message signing certificate expired: " + cert.getNotAfter());
			return false;
		}
		if(currentTime.before(cert.getNotBefore())){
			log.severe("Error processing Certificate Services message signing certificate not yet valid: " + cert.getNotBefore());
			return false;
		}

		return true;
	}


	/**
	 * Help method to sign an XML Document using default context
	 *
	 * Method that generates the signature and marshalls the message to byte array in UTF-8 format.
	 * @param doc a XML document about to be signed.
	 * @param signatureLocationFinder to find in which element the signature should be placed.
	 *
	 * @throws MessageProcessingException if problems occurred when processing the message.
	 * @throws MessageContentException if unsupported version is detected in message.
	 */
	@Deprecated
	public void sign(Document doc,  SignatureLocationFinder signatureLocationFinder) throws MessageProcessingException, MessageContentException {
		sign(ContextMessageSecurityProvider.DEFAULT_CONTEXT,doc,signatureLocationFinder);
	}
		/**
         * Help method to sign an XML Document
         *
         * Method that generates the signature and marshalls the message to byte array in UTF-8 format.
		 *
		 * @param context the related message security context
         * @param doc a XML document about to be signed.
         * @param signatureLocationFinder to find in which element the signature should be placed.
         *
         * @throws MessageProcessingException if problems occurred when processing the message.
         * @throws MessageContentException if unsupported version is detected in message.
         */
	public void sign(Context context, Document doc,  SignatureLocationFinder signatureLocationFinder) throws MessageProcessingException, MessageContentException{

		try {

			if(signMessages){
				Element[] signatureLocations = signatureLocationFinder.getSignatureLocations(doc);
				for(Element signatureLocation : signatureLocations) {
					XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM",new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
					SigningAlgorithmScheme scheme = (messageSecurityProvider instanceof ContextMessageSecurityProvider ? ((ContextMessageSecurityProvider) messageSecurityProvider).getSigningAlgorithmScheme(context) : messageSecurityProvider.getSigningAlgorithmScheme());
					DigestMethod digestMethod = fac.newDigestMethod(scheme.getHashAlgorithmURI(), null);

					String messageID = signatureLocationFinder.getIDValue(signatureLocation);
					List<Transform> transFormList = new ArrayList<Transform>();
					transFormList.add(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
					transFormList.add(fac.newTransform(C14N_TRANSFORM, (TransformParameterSpec)null));

					Reference ref = fac.newReference((messageID == null ? "" : "#" + messageID),digestMethod, transFormList, null, null);

					ArrayList<Reference> refList = new ArrayList<Reference>();
					refList.add(ref);
					CanonicalizationMethod cm =  fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,(C14NMethodParameterSpec) null);
					SignatureMethod sm = fac.newSignatureMethod(scheme.getSignatureAlgorithmURI(),null);
					SignedInfo signedInfo =fac.newSignedInfo(cm,sm,refList);

					List<QName> beforeSiblings = signatureLocationFinder.getSiblingsBeforeSignature(signatureLocation);
					Node siblingNode = null;
					if (beforeSiblings != null) {
						for (QName name : beforeSiblings) {
							NodeList foundList = signatureLocation.getElementsByTagNameNS(name.getNamespaceURI(), name.getLocalPart());
							if (foundList.getLength() > 0) {
								siblingNode = foundList.item(0);
								break;
							}
						}
					}
					PrivateKey signingKey = (messageSecurityProvider instanceof ContextMessageSecurityProvider ? ((ContextMessageSecurityProvider) messageSecurityProvider).getSigningKey(context) : messageSecurityProvider.getSigningKey());
					DOMSignContext signContext;
					if (siblingNode != null) {
						signContext = new DOMSignContext(signingKey, signatureLocation, siblingNode);
					} else {
						signContext = new DOMSignContext(signingKey, signatureLocation);
					}
					String idAttribute = signatureLocationFinder.getIDAttribute();
					if(idAttribute != null) {
						signContext.setIdAttributeNS(signatureLocation, null, idAttribute);
					}
					signContext.putNamespacePrefix("http://www.w3.org/2000/09/xmldsig#", "ds");

					KeyInfoFactory kif = KeyInfoFactory.getInstance("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
					List<X509Certificate> certs = new ArrayList<X509Certificate>();
					X509Certificate cert = (messageSecurityProvider instanceof ContextMessageSecurityProvider ? ((ContextMessageSecurityProvider) messageSecurityProvider).getSigningCertificate(context) : messageSecurityProvider.getSigningCertificate());
					certs.add(cert);
					X509Data x509Data = kif.newX509Data(certs);
					KeyInfo ki = kif.newKeyInfo(Collections.singletonList(x509Data));

					XMLSignature signature = fac.newXMLSignature(signedInfo, ki);

					// Check if we are using a HSMMessageSecurityProvider or PKCS11MessageSecurityProvider.
					// If this is the case we explicitly specify tha Java Security Provider to use that should
					// handle the signature operation.
					Provider customProvider = null;
					if(messageSecurityProvider instanceof HSMMessageSecurityProvider){
						customProvider = Security.getProvider(((HSMMessageSecurityProvider) messageSecurityProvider).getHSMProvider());
						log.fine("Performing signature using HSM provider: " + customProvider.getName());
					} else if(messageSecurityProvider instanceof PKCS11MessageSecurityProvider){
						customProvider = Security.getProvider(((PKCS11MessageSecurityProvider)messageSecurityProvider).getPKCS11Provider());
						log.fine("Performing signature using PKCS#11 provider: " + customProvider.getName());
					}
					if(customProvider != null){
						signContext.setProperty("org.jcp.xml.dsig.internal.dom.SignatureProvider", customProvider);
					}
					signature.sign(signContext);
				}
			}

		} catch (NoSuchAlgorithmException e) {
			throw new MessageProcessingException("Error signing the XML, " + e.getMessage(),e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new MessageProcessingException("Error signing the XML, " + e.getMessage(),e);
		} catch (MarshalException e) {
			throw new MessageProcessingException("Error signing the XML, " + e.getMessage(),e);
		} catch (XMLSignatureException e) {
			throw new MessageProcessingException("Error signing the XML, " + e.getMessage(),e);
		}
	}

	/**
	 * Method to convert a Document to a UTF-8 encoded byte array
	 * @param doc the document to convert
	 * @return a marshalled byte array in UTF-8 format.
	 * @throws MessageProcessingException if problems occurred when processing the message.
	 * @throws MessageContentException if unsupported version is detected in message.
     */
	public byte[] marshallDoc(Document doc) throws MessageProcessingException, MessageContentException{
		try {
			StringWriter writer = new StringWriter();
			transformer.transform(new DOMSource(doc), new StreamResult(writer));
			String output = writer.getBuffer().toString();
			return output.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new MessageProcessingException("Error marshalling to XML, " + e.getMessage(),e);
		} catch (TransformerException e) {
			throw new MessageProcessingException("Error marshalling to XML, " + e.getMessage(),e);
		}
	}


	/**
	 * Help method to marshall and sign an XML Document
	 *
	 * Method that generates the signature and marshalls the message to byte array in UTF-8 format.
	 * @param context related message security context.
	 * @param doc a XML document about to be signed.
	 * @param signatureLocationFinder to find in which element the signature should be placed.

	 * @return a marshalled and signed message.
	 * @throws MessageProcessingException if problems occurred when processing the message.
	 * @throws MessageContentException if unsupported version is detected in message.
	 */
	public byte[] marshallAndSign(Context context, Document doc, SignatureLocationFinder signatureLocationFinder) throws MessageProcessingException, MessageContentException{

		sign(context,doc,signatureLocationFinder);
		return marshallDoc(doc);
	}

	/**
	 * Help method to marshall and sign an XML Document
	 *
	 * Method that generates the signature and marshalls the message to byte array in UTF-8 format.
	 * @param doc a XML document about to be signed.
	 * @param signatureLocationFinder to find in which element the signature should be placed.

	 * @return a marshalled and signed message.
	 * @throws MessageProcessingException if problems occurred when processing the message.
	 * @throws MessageContentException if unsupported version is detected in message.
	 */
	@Deprecated
	public byte[] marshallAndSign(Document doc, SignatureLocationFinder signatureLocationFinder) throws MessageProcessingException, MessageContentException{

		sign(ContextMessageSecurityProvider.DEFAULT_CONTEXT,doc,signatureLocationFinder);
		return marshallDoc(doc);
	}

	
	/**
	 * Help method to find ds:Signature element among direct childs to this element.
	 */
	private Element findSignatureElementInObject(Element signedElement) throws MessageContentException{
		NodeList childs = signedElement.getChildNodes();
		for(int i = 0; i < childs.getLength(); i++){
			Node next = childs.item(i);
			if(next instanceof Element) {
				if (((Element) next).getLocalName().equals("Signature") && ((Element) next).getNamespaceURI().equals(XMLDSIG_NAMESPACE)) {
					return (Element) next;
				}
			}
		}
		
		throw new MessageContentException("Required digital signature not found in message.");
	}

	
	/**
	 * Method that checks the referenced URI actually is the same as ID of the enveloped signed object otherwise MessageContentException
	 */
	private void checkValidReferenceURI(Element signedElement, Element signature, String signedElementIDAttr) throws MessageContentException{
		try{
			if(signedElementIDAttr != null) {
				String objectID = signedElement.getAttribute(signedElementIDAttr);
				Element transform = (Element) signature.getElementsByTagNameNS(XMLDSIG_NAMESPACE, "Reference").item(0);
				String referenceID = transform.getAttribute("URI");
				if (!referenceID.equals("#" + objectID)) {
					throw new MessageContentException("Error checking reference URI of digital signature it doesn't match the id of the signed element.");
				}
			}
		}catch(Exception e){
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			throw new MessageContentException("Error checking Reference URI with the signed object: " + e.getMessage(),e);
		}
	}

	/**
	 * Method that check that the transform is set to enveloped otherwise MessageContentException
	 */
	private void checkValidTransform(Element signature) throws MessageContentException {
		try{
			Element transform = (Element) signature.getElementsByTagNameNS(XMLDSIG_NAMESPACE, "Transform").item(0);
			String algorithm = transform.getAttribute("Algorithm");
			if(!algorithm.equals(ENVELOPE_TRANSFORM)){
				throw new MessageContentException("Error unsupported transform in digital sigature: " + algorithm + " only enveloped signatures are supported.");
			}
		}catch(Exception e){
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			throw new MessageContentException("Error extracting transform from digital sigature: " + e.getMessage(),e);
		}
	}

	/**
	 * Method that checks supported digestURI from available SigningAlgorithmScheme otherwise MessageContentException
	 */
	private void checkValidDigestURI(Element signature) throws MessageContentException{
		try{
			Element transform = (Element) signature.getElementsByTagNameNS(XMLDSIG_NAMESPACE, "DigestMethod").item(0);
			String algorithm = transform.getAttribute("Algorithm");
			
			if(!supportedDigestsAlgorithm.contains(algorithm)){
				throw new MessageContentException("Error unsupported digest algorithm in digital sigature: " + algorithm + ".");
			}
		}catch(Exception e){
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			throw new MessageContentException("Error extracting digest algorithm from digital sigature: " + e.getMessage(),e);
		}
	}

	/**
	 * Method that checks supported signature algorithm from available SigningAlgorithmScheme otherwise MessageContentException
	 */
	private void checkValidSignatureURI(Element signature) throws MessageContentException{
		try{
			Element transform = (Element) signature.getElementsByTagNameNS(XMLDSIG_NAMESPACE, "SignatureMethod").item(0);
			String algorithm = transform.getAttribute("Algorithm");
			
			if(!supportedSignatureAlgorithm.contains(algorithm)){
				throw new MessageContentException("Error unsupported digest algorithm in digital sigature: " + algorithm + ".");
			}
		}catch(Exception e){
			if(e instanceof MessageContentException){
				throw (MessageContentException) e;
			}
			throw new MessageContentException("Error extracting digest algorithm from digital sigature: " + e.getMessage(),e);
		}
		
	}
	
	/**
	 * Interface used to find the location and ID of a signed object.
	 * 
	 * @author Philip Vendil
	 *
	 */
	public interface SignatureLocationFinder{
		
		/**
		 * Return the element inside a document that should be signed.
		 */
		Element[] getSignatureLocations(Document doc) throws MessageContentException;

		/**
		 *
		 * @return the name of the ID attribute referenced by the envelope signature.
         */
		String getIDAttribute();

		/**
		 * @param signedElement the element that should be signed, and ID value for should be fetched.
		 * @return the signature reference ID value
		 *
		 */
		String getIDValue(Element signedElement) throws MessageContentException;

		/**
		 * Method that should return the possible siblings that should be placed before the signature element in the
		 * specified element. If a specified sibling isn't found should the next be used.
		 * @param element the element about to be signed and those siblings should be found.
		 * @return a list of siblings that should be before signature, if the first doesn't exist due to optional is the next
		 * in list use. return null to place signature last in element.
		 * @throws MessageContentException if problems was found with the supplied element
         */
		List<QName> getSiblingsBeforeSignature(Element element) throws MessageContentException;
		
	}

	/**
	 * Interface for determining organisation related to a XML message.
	 *
	 * Created by philip on 31/12/16.
	 */
	public interface OrganisationLookup {

		String UNKNOWN = "UNKNOWN";

		/**
		 * Method that should extract the organisiation name from a given xml message.
		 * @param doc the document to extract organisation from.
		 * @return might the organisation found, it might return UNKNWON if supported with used MessageSecurityProvider.
		 * @throws MessageContentException if organisation couldn't be extracted from message.
		 * @throws MessageProcessingException if internal problems occurred extractign the organisation name.
		 */
		String findOrganisation(Document doc) throws MessageContentException, MessageProcessingException;
	}


	
}
