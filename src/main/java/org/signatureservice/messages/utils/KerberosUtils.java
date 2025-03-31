package org.signatureservice.messages.utils;

import org.signatureservice.messages.MessageProcessingException;
import org.signatureservice.messages.csmessages.jaxb.Attribute;
import org.signatureservice.messages.csmessages.jaxb.Credential;
import org.signatureservice.messages.csmessages.jaxb.ObjectFactory;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;

import javax.xml.datatype.XMLGregorianCalendar;
import java.util.Date;

/**
 * Class containing help method generating messages in a kerberos context.
 *
 * Created by philip on 05/01/17.
 */
public class KerberosUtils {

    private static ObjectFactory of = new ObjectFactory();

    private static SystemTime systemTime = new DefaultSystemTime();

    public static final String CREDENTIAL_ATTRIBUTE_USERID = "USER_UNIQUEID";
    public static final String CREDENTIAL_ATTRIBUTE_USERDISPLAYNAME = "USER_USERDISPLAYNAME";

    /**
     * Help method to create a kerberos original credential.
     *
     * @param credentialType the credential type to use preferable from AvailableCredentialTypes
     * @param credentialSubType the credential sub type to use preferable from AvailableCredentialSubTypes
     * @param issuerId the name of the kerberos realm or
     * @param gssCredential the related kerberos credential
     * @param status the current status, one of CredentialStatus
     * @param userUniqueId the unique id within the organisation.
     * @param userDisplayname the display name of the user.
     * @return a kerberos type credential that can be used as originator in CSMessages
     * @throws MessageProcessingException
     */
    public static Credential generateKerberosOriginator(String credentialType, String credentialSubType, String issuerId,
                                                        GSSCredential gssCredential,
                                                        int status, String userUniqueId, String userDisplayname) throws MessageProcessingException {

        try{
            String randomId = MessageGenerateUtils.generateRandomUUID();

            XMLGregorianCalendar now = MessageGenerateUtils.dateToXMLGregorianCalendar(systemTime.getSystemTime());

            Attribute userUniqueidAttr = of.createAttribute();
            userUniqueidAttr.setKey(CREDENTIAL_ATTRIBUTE_USERID);
            userUniqueidAttr.setValue(userUniqueId);

            Attribute userDisplayNameAttr = of.createAttribute();
            userDisplayNameAttr.setKey(CREDENTIAL_ATTRIBUTE_USERDISPLAYNAME);
            userDisplayNameAttr.setValue(userDisplayname);


            Credential.Attributes attributes = of.createCredentialAttributes();
            attributes.getAttribute().add(userUniqueidAttr);
            attributes.getAttribute().add(userDisplayNameAttr);


            Credential c = of.createCredential();
            c.setCredentialType(credentialType);
            c.setCredentialSubType(credentialSubType);
            c.setIssuerId(issuerId);
            c.setUniqueId("kb:" + userUniqueId);
            c.setSerialNumber(randomId);
            c.setDisplayName(gssCredential.getName().toString());
            c.setIssueDate(now);
            c.setExpireDate(MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(systemTime.getSystemTimeMS() + (gssCredential.getRemainingLifetime() * 1000L))));
            c.setValidFromDate(now);
            c.setCredentialData(new byte[0]);
            c.setAttributes(attributes);
            c.setStatus(status);

            return c;
        }catch(GSSException e){
            throw new MessageProcessingException("Internal error parsing kerberos GSSCredential");
        }
    }

    /**
     * Help method to create a kerberos original credential.
     *
     * @param credentialType the credential type to use preferable from AvailableCredentialTypes
     * @param credentialSubType  the credential sub type to use preferable from AvailableCredentialSubTypes
     * @param issuerId the name of the kerberos realm or
     * @param lifeTime kerberos ticket lifetime in milliseconds.
     * @param status the current status, one of CredentialStatus
     * @param userUniqueId the unique id within the organisation.
     * @param userDisplayname the display name of the user.
     * @return  a kerberos type credential that can be used as originator in CSMessages
     * @throws MessageProcessingException
     */
    public static Credential generateKerberosOriginator(String credentialType, String credentialSubType, String issuerId, long lifeTime, int status, String userUniqueId, String userDisplayname) throws MessageProcessingException {
        String randomId = MessageGenerateUtils.generateRandomUUID();

        XMLGregorianCalendar now = MessageGenerateUtils.dateToXMLGregorianCalendar(systemTime.getSystemTime());

        Attribute userUniqueidAttr = of.createAttribute();
        userUniqueidAttr.setKey(CREDENTIAL_ATTRIBUTE_USERID);
        userUniqueidAttr.setValue(userUniqueId);

        Attribute userDisplayNameAttr = of.createAttribute();
        userDisplayNameAttr.setKey(CREDENTIAL_ATTRIBUTE_USERDISPLAYNAME);
        userDisplayNameAttr.setValue(userDisplayname);

        Credential.Attributes attributes = of.createCredentialAttributes();
        attributes.getAttribute().add(userUniqueidAttr);
        attributes.getAttribute().add(userDisplayNameAttr);


        Credential c = of.createCredential();
        c.setCredentialType(credentialType);
        c.setCredentialSubType(credentialSubType);
        c.setIssuerId(issuerId);
        c.setUniqueId("kb:" + userUniqueId);
        c.setSerialNumber(randomId);
        c.setDisplayName(userDisplayname);
        c.setIssueDate(now);
        c.setExpireDate(MessageGenerateUtils.dateToXMLGregorianCalendar(new Date(systemTime.getSystemTimeMS() + lifeTime)));
        c.setValidFromDate(now);
        c.setCredentialData(new byte[0]);
        c.setAttributes(attributes);
        c.setStatus(status);

        return c;
    }
}
