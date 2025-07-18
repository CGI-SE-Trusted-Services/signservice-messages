/************************************************************************
 *                                                                       *
 *  Signature Service - Messages                                         *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.messages.utils;

import java.security.SecureRandom;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import se.signatureservice.messages.MessageProcessingException;

/**
 * Class containing help utils when populating data in messages.
 *
 * @author Philip Vendil
 *
 */
public class MessageGenerateUtils {

	private static SecureRandom secureRandom = new SecureRandom();
	private static String[] specialCharSet = {"8","9","a","b"};

	/**
	 * Help method to generate a unique UUID according the the message header specification
	 * <p>
	 * Pattern: [0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[8-9a-bA-B][0-9a-fA-F]{3}-[0-9a-fA-F]{12}
	 * @return a newly generated UUID
	 */
	public static String generateRandomUUID(){
		byte[] randomData = new byte[15];
		secureRandom.nextBytes(randomData);
		String hexData = new String(bytesToHex(randomData));
		String specialChar = specialCharSet[secureRandom.nextInt(4)];

		return hexData.substring(0, 8) + "-" + hexData.substring(8,12) + "-4" + hexData.substring(12,15) + "-" + specialChar + hexData.substring(15,18) + "-" + hexData.substring(18);
	}

	/**
	 * Method to convert a date to a XML gregorian calendar
	 * @param date the date to convert
	 * @return a XMLGregorianCalendar object or null if date is null.
	 * @throws MessageProcessingException if internal problems occurred converting the date.
	 */
	public static XMLGregorianCalendar dateToXMLGregorianCalendar(Date date) throws MessageProcessingException{
		return dateToXMLGregorianCalendar(date, null);
	}

	/**
	 * Method to convert a date to a XML gregorian calendar using a specific timezone
	 * @param date the date to convert
	 * @param timeZone Timezone to use or null if default timezone should be used.
	 * @return a XMLGregorianCalendar object or null if date is null.
	 * @throws MessageProcessingException if internal problems occurred converting the date.
	 */
	public static XMLGregorianCalendar dateToXMLGregorianCalendar(Date date, TimeZone timeZone) throws MessageProcessingException{
		if(date == null){
			return null;
		}

		GregorianCalendar c = timeZone != null ? new GregorianCalendar(timeZone) : new GregorianCalendar();
		c.setTime(date);
		try {
			return DatatypeFactory.newInstance().newXMLGregorianCalendar(c);
		} catch (DatatypeConfigurationException e) {
			throw new MessageProcessingException("Error generating XMLGregorianDate from Date : " + e.getMessage(),e);
		}
	}

	/**
	 * Method to convert a date to a XML gregorian calendar without time zone.
	 * @param date the date to convert
	 * @return a XMLGregorianCalendar object or null if date is null.
	 * @throws MessageProcessingException if internal problems occurred converting the date.
	 */
	public static XMLGregorianCalendar dateToXMLGregorianCalendarNoTimeZone(Date date) throws MessageProcessingException{
		if(date == null){
			return null;
		}
		XMLGregorianCalendar xmlGregorianCalendar = dateToXMLGregorianCalendar(date, TimeZone.getTimeZone("UTC"));
		return xmlGregorianCalendar;
	}

	/**
	 * Method to convert a  XML gregorian calendar to a date
	 * @param calendarDate the date to convert
	 * @return a Date object or null if calendarDate is null.
	 * @throws MessageProcessingException if internal problems occurred converting the date.
	 */
	public static Date xMLGregorianCalendarToDate(XMLGregorianCalendar calendarDate) throws MessageProcessingException{
		if(calendarDate == null){
			return null;
		}

		return calendarDate.toGregorianCalendar().getTime();
	}

	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	public static String bytesToHex(byte[] bytes) {
		if(bytes == null){
			return null;
		}
		char[] hexChars = new char[bytes.length * 2];
		for ( int j = 0; j < bytes.length; j++ ) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}



}
