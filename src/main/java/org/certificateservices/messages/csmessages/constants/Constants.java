/**
 * 
 */
package org.certificateservices.messages.csmessages.constants;

/**
 * Class containing general constants related to the PKI message protocol
 * 
 * @author Philip Vendil
 *
 */
public class Constants {
	
	/**
	 * Special value used when forwarding CRL automatically generated requests where the CA
	 * doesn't know which organisation the CRL belongs to and it's up the the receiver to figure this out.
	 */
	public static final String ORGANISATION_UNKNOWN = "UNKNOWN";
	
	/**
	 * Constant used when related end entity of CA name couldn't be determined.
	 */
	public static final String RELATED_END_ENTITY_UNKNOWN = "UNKNOWN";

	/**
	 * Constant used for credential sub type.
	 */
	public static final String CREDENTIAL_SUBTYPE_UNKNOWN = "UNKNOWN";

}
