package org.signatureservice.messages.sweeid2.pricipalselection1_0;

import org.signatureservice.messages.sweeid2.pricipalselection1_0.jaxb.MatchValueType;
import org.signatureservice.messages.sweeid2.pricipalselection1_0.jaxb.ObjectFactory;
import org.signatureservice.messages.sweeid2.pricipalselection1_0.jaxb.PrincipalSelectionType;
import org.signatureservice.messages.sweeid2.pricipalselection1_0.jaxb.RequestedPrincipalSelectionType;

import javax.xml.bind.JAXBElement;
import java.util.List;

/**
 * Class containing helper method to generate PricipalSelection Elements used in extentions of AuthNRequest
 * and MetaData.
 *
 * @author Philip 2020-10-22
 */
public class PrincipalSelectionGenerator {

    ObjectFactory objectFactory = new ObjectFactory();

    /**
     * Help method to create a PricipalSelection Element from a list of match value types.
     * @param matchValues list of match value types.
     * @return a newly created  PricipalSelection Element that can be added to AuthNRequest extensions object.
     */
    public JAXBElement<PrincipalSelectionType> genPrincipalSelectionElement(List<MatchValueType> matchValues){
        PrincipalSelectionType pcs = objectFactory.createPrincipalSelectionType();
        pcs.getMatchValue().addAll(matchValues);
        return objectFactory.createPrincipalSelection(pcs);
    }

    /**
     * Help method to create a RequestedPrincipalSelection Element from a list of match value types.
     * @param matchValues list of match value types.
     * @return a newly created  RequestedPrincipalSelection Element that can be added to MetaData extensions object.
     */
    public JAXBElement<RequestedPrincipalSelectionType> genRequestedPrincipalSelectionElement(List<MatchValueType> matchValues){
        RequestedPrincipalSelectionType pcs = objectFactory.createRequestedPrincipalSelectionType();
        pcs.getMatchValue().addAll(matchValues);
        return objectFactory.createRequestedPrincipalSelection(pcs);
    }
}
