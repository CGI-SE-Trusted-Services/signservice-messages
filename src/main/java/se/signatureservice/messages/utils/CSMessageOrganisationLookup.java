package se.signatureservice.messages.utils;

import se.signatureservice.messages.MessageContentException;
import se.signatureservice.messages.csmessages.DefaultCSMessageParser;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * Implementation of Organisation lookup that fins the organisation element in a CS message.
 *
 * Created by philip on 02/01/17.
 */
public class CSMessageOrganisationLookup implements XMLSigner.OrganisationLookup {
    public String findOrganisation(Document doc) throws MessageContentException {
        String organisationElementLocalName = "organisation";
        String organisationElementNS = DefaultCSMessageParser.CSMESSAGE_NAMESPACE;

        NodeList organisationElements = doc.getElementsByTagNameNS(organisationElementNS, organisationElementLocalName);
        if (organisationElements.getLength() == 0) {
            throw new MessageContentException("Error verifying signature, no element " + organisationElementLocalName + " found in message.");
        }
        if (organisationElements.getLength() > 1) {
            throw new MessageContentException("Error verifying signature, Only one organisation element " + organisationElementLocalName + " is each message is supported.");
        }
        try {
            Element orgElement = (Element) organisationElements.item(0);
            return orgElement.getFirstChild().getNodeValue();
        } catch (Exception e) {
            throw new MessageContentException("Error extracting organisation element " + organisationElementLocalName + " from message: " + e.getMessage(), e);
        }
    }
}