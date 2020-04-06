/**
 * 
 */
package org.certificateservices.messages.assertion;

import javax.xml.bind.JAXBElement;

import org.certificateservices.messages.MessageContentException;
import org.certificateservices.messages.MessageProcessingException;
import org.certificateservices.messages.saml2.assertion.jaxb.AttributeType;
import org.certificateservices.messages.saml2.assertion.jaxb.NameIDType;
import org.certificateservices.messages.saml2.protocol.jaxb.AttributeQueryType;

/**
 * Data of a parsed attribute query.
 * 
 * @author Philip Vendil
 *
 */
public class AttributeQueryData {

	protected String id;
	protected AttributeQueryTypeEnum type;
	protected String subjectId;
	protected String tokenType;

	/**
	 * Main Constructor.
	 */
	public AttributeQueryData() {
	}

	/**
	 * Main parser called by AssertionPayloadParser when parsing attribute query.
	 */
	public void parse(JAXBElement<AttributeQueryType> attributeQuery)
			throws MessageContentException, MessageProcessingException {

		try{
			id = attributeQuery.getValue().getID();

			for(Object subjectContent : attributeQuery.getValue().getSubject().getContent()){
				if(subjectContent instanceof JAXBElement<?> && ((JAXBElement<?>) subjectContent).getValue() instanceof NameIDType){
					this.subjectId = ((NameIDType) ((JAXBElement<?>) subjectContent).getValue()).getValue();
				}
			}

			for(Object attr : attributeQuery.getValue().getAttribute()){
				if(attr instanceof AttributeType){
					for(AttributeQueryTypeEnum t : AttributeQueryTypeEnum.values()){
						if(((AttributeType) attr).getName().equals(t.getAttributeValue())){
							type = t;
							break;
						}
					}
					if(((AttributeType) attr).getName().equals(AssertionPayloadParser.ATTRIBUTE_NAME_TOKENTYPE) && ((AttributeType) attr).getAttributeValue().size() > 0){
						tokenType = ((AttributeType) attr).getAttributeValue().get(0).toString();
						break;
					}
				}	
			}


		}catch(Exception e){
			throw new MessageContentException("Error parsing Attribute Query: " + e.getMessage(), e);
		}


		if(type == null){
			throw new MessageContentException("Error parsing Attribute Query: couldn't determine type of attribute query");	
		}

		if(subjectId == null || subjectId.trim().equals("")){
			throw new MessageContentException("Error parsing Attribute Query: couldn't parse related subject Id");
		}
	}

	/**
	 * 
	 * @return the id of the attribute query.
	 */
	public String getID(){
		return id;
	}

	/**
	 * 
	 * @return the type of attribute query.
	 */
	public AttributeQueryTypeEnum getType() {
		return type;
	}

	/**
	 * 
	 * @return the subject id to look-up.
	 */
	public String getSubjectId() {
		return subjectId;
	}
	
	/**
	 * 
	 * @return the related token type in attribute query. only set for UserData Attribute queries, otherwise null.
	 */
	public String getTokenType() {
		return tokenType;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((id == null) ? 0 : id.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		AttributeQueryData other = (AttributeQueryData) obj;
		if (id == null) {
			if (other.id != null)
				return false;
		} else if (!id.equals(other.id))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "AttributeQueryData [id=" + id + ", type=" + type
				+ ", subjectId=" + subjectId + "]";
	}


}
