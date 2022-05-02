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
package org.certificateservices.messages.csmessages;

/**
 * Value objects containing the cs message and payload version of a message.
 * 
 * @author philip
 *
 */
public class CSMessageVersion {
	
	private String messageVersion;
	private String payLoadVersion;
	
	public CSMessageVersion() {
		super();
	}
	
	/**
	 * 
	 * @param messageVersion the header version of the message.
	 * @param payLoadVersion the pay load version of the message.
	 */
	public CSMessageVersion(String messageVersion, String payLoadVersion) {
		super();
		this.messageVersion = messageVersion;
		this.payLoadVersion = payLoadVersion;
	}
	
	/**
	 * 
	 * @return returns the header version of the message.
	 */
	public String getMessageVersion() {
		return messageVersion;
	}
	
	/**
	 * 
	 * @param messageVersion the header version of the message.
	 */
	public void setMessageVersion(String messageVersion) {
		this.messageVersion = messageVersion;
	}
	
	/**
	 * 
	 * @return returns the pay load version of the message.
	 */
	public String getPayLoadVersion() {
		return payLoadVersion;
	}
	
	/**
	 * 
	 * @return returns the pay load version of the message.
	 */
	public void setPayLoadVersion(String payLoadVersion) {
		this.payLoadVersion = payLoadVersion;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((messageVersion == null) ? 0 : messageVersion.hashCode());
		result = prime * result
				+ ((payLoadVersion == null) ? 0 : payLoadVersion.hashCode());
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
		CSMessageVersion other = (CSMessageVersion) obj;
		if (messageVersion == null) {
			if (other.messageVersion != null)
				return false;
		} else if (!messageVersion.equals(other.messageVersion))
			return false;
		if (payLoadVersion == null) {
			if (other.payLoadVersion != null)
				return false;
		} else if (!payLoadVersion.equals(other.payLoadVersion))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "CSMessageVersion [messageVersion=" + messageVersion
				+ ", payLoadVersion=" + payLoadVersion + "]";
	}
	
	

}
