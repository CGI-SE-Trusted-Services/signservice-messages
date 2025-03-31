package org.signatureservice.messages.utils;

import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateFactorySpi;

/**
 * Custom RSA Key Generator used to make the right BC Key Generator is used that can add
 * PKCS12 Bag Attributes. Related to a problem where Certservice-admin and vcc-factoryra
 * couldn't be deployed in the same Tomcat which led to incompatible keys were generated.
 *
 * @author Philip Vendil
 *
 */
class BCCertificateFactory extends CertificateFactory{
	
	public BCCertificateFactory() throws NoSuchProviderException{
		super(new org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory(), CertUtils.getBCProvider() ,"X.509");
	}

	protected BCCertificateFactory(CertificateFactorySpi certFacSpi,
		Provider provider, String type){
		super(certFacSpi, provider, type);
	}
	
}
