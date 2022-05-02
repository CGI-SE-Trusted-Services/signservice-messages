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

public class TestMessages {
	
	static byte[] invalidXML = """invalidxml"""
	
	static byte[] simpleCSMessage = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="2.0" timeStamp="2015-05-28T09:52:58.204+02:00" version="2.0" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd"><cs:name>testname</cs:name><cs:sourceId>SOMESOURCEID</cs:sourceId><cs:destinationId>somedest</cs:destinationId><cs:organisation>someorg</cs:organisation><cs:payload><sysconfig:GetActiveConfigurationRequest><sysconfig:application>asdf</sysconfig:application><sysconfig:organisationShortName>SomeOrg</sysconfig:organisationShortName></sysconfig:GetActiveConfigurationRequest></cs:payload><ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#12345678-1234-4444-8000-123456789012"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>WH7EQj0roOOavhQhpredMPODCgjDp1R8ih4VrHy4QGo=</DigestValue></Reference></SignedInfo><SignatureValue>EYOLAj/yA4jFn3otvtOt/I/fv9iTrJ20H03/ENQh3QGXnKl/XeZFcLyYODUwDhqHR8xzuy/adfFF
DIikCJC1NNaBjxki10awc5D/eEiu6O9e1qhUQnP/R+fmBc+SqTMC8USEpB6R3yMRQML5KTMyHGRe
lMVXiPa9+nHBoZccbgCkqs5qc2yRrWAacGc5qv7Y8rPG5u47IVJM1V4cXlQCwVM2vlGuoZlEDQWn
DOpiOIp+aURpAmJt0vaiyPR8p+ZKfVbV26cFzSMVEjGngxEP0vvRSIi4Zypwmu1IdYs4ZYTTYslk
x3vBOm2AkhumAc1cq5KtbdOkdTSzo3Wyd6SQZQ==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
dXN0b21lcjEgQVQgU2VydmVyQ0ExGjAYBgNVBAoMEURlbW8gQ3VzdG9tZXIxIEFUMB4XDTEyMTAx
MDE0NDQwNFoXDTE0MTAxMDE0NDQwNFowKzENMAsGA1UEAwwEdGVzdDEaMBgGA1UECgwRRGVtbyBD
dXN0b21lcjEgQVQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCbDqmR4e8sgxw2Afi/
y3i/mT7WwtpW18/QfyUGpYPPxQ4bvPPn61y3jJg/dAbGHvnyQSHfIvrIJUN83q6evvk0bNZNVSEN
UEP29isE4D+KjD3PFtAzQq18P8m/8mSXMva5VTooEUSDX+VJ/6el6tnyZdc85AlIJkkkvyiDKcjh
f10yllaiVCHLunGMDXAec4DapPi5GdmSMMXyPOhRx5e+oy6b5q9XmT3C29VNVFf+tkAt3ew3BoQb
d+VrlBI4oRYq+mfbgkXU6dSKr9DRqhsbu5rU4Jdst2KClXsxaxvC0rVeKQ8iXCDKFH5glzhSYoeW
l7CI15CdQM6/so7EisSvAgMBAAGjgeMwgeAwHQYDVR0OBBYEFLpidyp0Pc46cUpJf1neFnq/rLJB
MAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUgEn+Hp9+Yxe4lOhaIPmf++Wu7SYwGAYDVR0gBBEw
DzANBgsrBgEEAYH1fgMDCTBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vYXQtY3JsLndtLm5ldC9k
ZW1vY3VzdG9tZXIxX3NlcnZlcmNhLmNybDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwDwYDVR0RBAgwBoIEdGVzdDANBgkqhkiG9w0BAQUFAAOCAQEAZxGls/mNT4GyAf9u9lg7
8sSA27sc3xFvHNogrT4yUCbYAOhLXO4HJ9XuKaFyz4bKz6JGdLaQDknDI1GUvpJLpiPTXk4cq1pp
HVt5/2QVeDCGtite4CH/YrAe4gufBqWo9q7XQeQbjil0mOUsSp1ErrcSadyT+KZoD4GXJBIVFcOI
WKL7aCHzSLpw/+DY1sEiAbStmhz0K+UrFK+FVdZn1RIWGeVClhJklLb2vNjQgPYGdd5nKyLrlA4z
ekPDDWdmmxwv4A3MG8KSnl8VBU5CmAZLR1YRaioK6xL1QaH0a16FTkn3y6GVeYUGsTeyLvLlfhgA
ZLCP64EJEfE1mGxCJg==</X509Certificate></X509Data></KeyInfo></ds:Signature></cs:CSMessage>"""
	
	static byte[] simpleCSMessagePayloadVersion2_1 = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="2.1" timeStamp="2015-05-27T10:26:20.373+02:00" version="2.0" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd"><cs:name>testname</cs:name><cs:sourceId>SOMESOURCEID</cs:sourceId><cs:destinationId>somedest</cs:destinationId><cs:organisation>someorg</cs:organisation><cs:payload><sysconfig:GetActiveConfigurationRequest><sysconfig:application>asdf</sysconfig:application><sysconfig:organisationShortName>SomeOrg</sysconfig:organisationShortName></sysconfig:GetActiveConfigurationRequest></cs:payload><ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#12345678-1234-4444-8000-123456789012"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>n4Cyks7jfjT2Am4eKn/UrIcZCOgrb0u24pwAVBMFB1M=</DigestValue></Reference></SignedInfo><SignatureValue>WGL1gGZ2MDMedYvjqeCIfqcep/gtjc7vi0s8jZ7kppr00Fm1jXrmT47W729EUV9heK3Mtsf+7vjk
gA9rPR+/KcmUJHHv2rB5aW28Tv9/1T2rUgpROhKAp9ocMSvtwOL9CFaeCTbV4gUjX7IvwMrkQhH/
e7y5EAH1XSNRDqiuUJ61FpwblbTpLB8hwtfc+ZaCQ3LqAG+zHM8Y1jih7doECxwo588HWIVgNNdb
TgrCV08Dd/LEAb2UWeNPWCLue0rU7CHbeif6P3wLPJ/IqlB+p+5OqeC+oiCa1IAMJ+8lxXnAPi3W
bhRLxBHhOgDXJuQg3k17tl9U8FFv4AW8Xa1wRQ==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
dXN0b21lcjEgQVQgU2VydmVyQ0ExGjAYBgNVBAoMEURlbW8gQ3VzdG9tZXIxIEFUMB4XDTEyMTAx
MDE0NDQwNFoXDTE0MTAxMDE0NDQwNFowKzENMAsGA1UEAwwEdGVzdDEaMBgGA1UECgwRRGVtbyBD
dXN0b21lcjEgQVQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCbDqmR4e8sgxw2Afi/
y3i/mT7WwtpW18/QfyUGpYPPxQ4bvPPn61y3jJg/dAbGHvnyQSHfIvrIJUN83q6evvk0bNZNVSEN
UEP29isE4D+KjD3PFtAzQq18P8m/8mSXMva5VTooEUSDX+VJ/6el6tnyZdc85AlIJkkkvyiDKcjh
f10yllaiVCHLunGMDXAec4DapPi5GdmSMMXyPOhRx5e+oy6b5q9XmT3C29VNVFf+tkAt3ew3BoQb
d+VrlBI4oRYq+mfbgkXU6dSKr9DRqhsbu5rU4Jdst2KClXsxaxvC0rVeKQ8iXCDKFH5glzhSYoeW
l7CI15CdQM6/so7EisSvAgMBAAGjgeMwgeAwHQYDVR0OBBYEFLpidyp0Pc46cUpJf1neFnq/rLJB
MAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUgEn+Hp9+Yxe4lOhaIPmf++Wu7SYwGAYDVR0gBBEw
DzANBgsrBgEEAYH1fgMDCTBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vYXQtY3JsLndtLm5ldC9k
ZW1vY3VzdG9tZXIxX3NlcnZlcmNhLmNybDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwDwYDVR0RBAgwBoIEdGVzdDANBgkqhkiG9w0BAQUFAAOCAQEAZxGls/mNT4GyAf9u9lg7
8sSA27sc3xFvHNogrT4yUCbYAOhLXO4HJ9XuKaFyz4bKz6JGdLaQDknDI1GUvpJLpiPTXk4cq1pp
HVt5/2QVeDCGtite4CH/YrAe4gufBqWo9q7XQeQbjil0mOUsSp1ErrcSadyT+KZoD4GXJBIVFcOI
WKL7aCHzSLpw/+DY1sEiAbStmhz0K+UrFK+FVdZn1RIWGeVClhJklLb2vNjQgPYGdd5nKyLrlA4z
ekPDDWdmmxwv4A3MG8KSnl8VBU5CmAZLR1YRaioK6xL1QaH0a16FTkn3y6GVeYUGsTeyLvLlfhgA
ZLCP64EJEfE1mGxCJg==</X509Certificate></X509Data></KeyInfo></ds:Signature></cs:CSMessage>""".getBytes("UTF-8")

static byte[] cSMessageWithInvalidSignature = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="2.2" timeStamp="2015-05-27T10:26:20.373+02:00" version="2.0" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd"><cs:name>testname</cs:name><cs:sourceId>SOMESOURCEID</cs:sourceId><cs:destinationId>somedest</cs:destinationId><cs:organisation>someorg</cs:organisation><cs:payload><sysconfig:GetActiveConfigurationRequest><sysconfig:application>asdf</sysconfig:application><sysconfig:organisationShortName>SomeOrg</sysconfig:organisationShortName></sysconfig:GetActiveConfigurationRequest></cs:payload><ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#12345678-1234-4444-8000-123456789012"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>n4Cyks7jfjT2Am4eKn/UrIcZCOgrb0u24pwAVBMFB1M=</DigestValue></Reference></SignedInfo><SignatureValue>WGL1gGZ2MDMedYvjqeCIfqcep/gtjc7vi0s8jZ7kppr00Fm1jXrmT47W729EUV9heK3Mtsf+7vjk
gA9rPR+/KcmUJHHv2rB5aW28Tv9/1T2rUgpROhKAp9ocMSvtwOL9CFaeCTbV4gUjX7IvwMrkQhH/
e7y5EAH1XSNRDqiuUJ61FpwblbTpLB8hwtfc+ZaCQ3LqAG+zHM8Y1jih7doECxwo588HWIVgNNdb
TgrCV08Dd/LEAb2UWeNPWCLue0rU7CHbeif6P3wLPJ/IqlB+p+5OqeC+oiCa1IAMJ+8lxXnAPi3W
bhRLxBHhOgDXJuQg3k17tl9U8FFv4AW8Xa1wRQ==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
dXN0b21lcjEgQVQgU2VydmVyQ0ExGjAYBgNVBAoMEURlbW8gQ3VzdG9tZXIxIEFUMB4XDTEyMTAx
MDE0NDQwNFoXDTE0MTAxMDE0NDQwNFowKzENMAsGA1UEAwwEdGVzdDEaMBgGA1UECgwRRGVtbyBD
dXN0b21lcjEgQVQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCbDqmR4e8sgxw2Afi/
y3i/mT7WwtpW18/QfyUGpYPPxQ4bvPPn61y3jJg/dAbGHvnyQSHfIvrIJUN83q6evvk0bNZNVSEN
UEP29isE4D+KjD3PFtAzQq18P8m/8mSXMva5VTooEUSDX+VJ/6el6tnyZdc85AlIJkkkvyiDKcjh
f10yllaiVCHLunGMDXAec4DapPi5GdmSMMXyPOhRx5e+oy6b5q9XmT3C29VNVFf+tkAt3ew3BoQb
d+VrlBI4oRYq+mfbgkXU6dSKr9DRqhsbu5rU4Jdst2KClXsxaxvC0rVeKQ8iXCDKFH5glzhSYoeW
l7CI15CdQM6/so7EisSvAgMBAAGjgeMwgeAwHQYDVR0OBBYEFLpidyp0Pc46cUpJf1neFnq/rLJB
MAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUgEn+Hp9+Yxe4lOhaIPmf++Wu7SYwGAYDVR0gBBEw
DzANBgsrBgEEAYH1fgMDCTBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vYXQtY3JsLndtLm5ldC9k
ZW1vY3VzdG9tZXIxX3NlcnZlcmNhLmNybDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwDwYDVR0RBAgwBoIEdGVzdDANBgkqhkiG9w0BAQUFAAOCAQEAZxGls/mNT4GyAf9u9lg7
8sSA27sc3xFvHNogrT4yUCbYAOhLXO4HJ9XuKaFyz4bKz6JGdLaQDknDI1GUvpJLpiPTXk4cq1pp
HVt5/2QVeDCGtite4CH/YrAe4gufBqWo9q7XQeQbjil0mOUsSp1ErrcSadyT+KZoD4GXJBIVFcOI
WKL7aCHzSLpw/+DY1sEiAbStmhz0K+UrFK+FVdZn1RIWGeVClhJklLb2vNjQgPYGdd5nKyLrlA4z
ekPDDWdmmxwv4A3MG8KSnl8VBU5CmAZLR1YRaioK6xL1QaH0a16FTkn3y6GVeYUGsTeyLvLlfhgA
ZLCP64EJEfE1mGxCJg==</X509Certificate></X509Data></KeyInfo></ds:Signature></cs:CSMessage>""".getBytes("UTF-8")

static byte[] simpleCSMessageWithoutSignature = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="2.1" timeStamp="2015-05-27T10:26:20.373+02:00" version="2.0" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd"><cs:name>testname</cs:name><cs:sourceId>SOMESOURCEID</cs:sourceId><cs:destinationId>somedest</cs:destinationId><cs:organisation>someorg</cs:organisation><cs:payload><sysconfig:GetActiveConfigurationRequest><sysconfig:application>asdf</sysconfig:application><sysconfig:organisationShortName>SomeOrg</sysconfig:organisationShortName></sysconfig:GetActiveConfigurationRequest></cs:payload></cs:CSMessage>""".getBytes("UTF-8")

static byte[] simpleCSMessageWithEmptyVersion = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="2.1" timeStamp="2015-05-27T10:26:20.373+02:00" version="" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd"><cs:name>testname</cs:name><cs:sourceId>SOMESOURCEID</cs:sourceId><cs:destinationId>somedest</cs:destinationId><cs:organisation>someorg</cs:organisation><cs:payload><sysconfig:GetActiveConfigurationRequest><sysconfig:application>asdf</sysconfig:application><sysconfig:organisationShortName>SomeOrg</sysconfig:organisationShortName></sysconfig:GetActiveConfigurationRequest></cs:payload><ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#12345678-1234-4444-8000-123456789012"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>n4Cyks7jfjT2Am4eKn/UrIcZCOgrb0u24pwAVBMFB1M=</DigestValue></Reference></SignedInfo><SignatureValue>WGL1gGZ2MDMedYvjqeCIfqcep/gtjc7vi0s8jZ7kppr00Fm1jXrmT47W729EUV9heK3Mtsf+7vjk
gA9rPR+/KcmUJHHv2rB5aW28Tv9/1T2rUgpROhKAp9ocMSvtwOL9CFaeCTbV4gUjX7IvwMrkQhH/
e7y5EAH1XSNRDqiuUJ61FpwblbTpLB8hwtfc+ZaCQ3LqAG+zHM8Y1jih7doECxwo588HWIVgNNdb
TgrCV08Dd/LEAb2UWeNPWCLue0rU7CHbeif6P3wLPJ/IqlB+p+5OqeC+oiCa1IAMJ+8lxXnAPi3W
bhRLxBHhOgDXJuQg3k17tl9U8FFv4AW8Xa1wRQ==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
dXN0b21lcjEgQVQgU2VydmVyQ0ExGjAYBgNVBAoMEURlbW8gQ3VzdG9tZXIxIEFUMB4XDTEyMTAx
MDE0NDQwNFoXDTE0MTAxMDE0NDQwNFowKzENMAsGA1UEAwwEdGVzdDEaMBgGA1UECgwRRGVtbyBD
dXN0b21lcjEgQVQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCbDqmR4e8sgxw2Afi/
y3i/mT7WwtpW18/QfyUGpYPPxQ4bvPPn61y3jJg/dAbGHvnyQSHfIvrIJUN83q6evvk0bNZNVSEN
UEP29isE4D+KjD3PFtAzQq18P8m/8mSXMva5VTooEUSDX+VJ/6el6tnyZdc85AlIJkkkvyiDKcjh
f10yllaiVCHLunGMDXAec4DapPi5GdmSMMXyPOhRx5e+oy6b5q9XmT3C29VNVFf+tkAt3ew3BoQb
d+VrlBI4oRYq+mfbgkXU6dSKr9DRqhsbu5rU4Jdst2KClXsxaxvC0rVeKQ8iXCDKFH5glzhSYoeW
l7CI15CdQM6/so7EisSvAgMBAAGjgeMwgeAwHQYDVR0OBBYEFLpidyp0Pc46cUpJf1neFnq/rLJB
MAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUgEn+Hp9+Yxe4lOhaIPmf++Wu7SYwGAYDVR0gBBEw
DzANBgsrBgEEAYH1fgMDCTBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vYXQtY3JsLndtLm5ldC9k
ZW1vY3VzdG9tZXIxX3NlcnZlcmNhLmNybDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwDwYDVR0RBAgwBoIEdGVzdDANBgkqhkiG9w0BAQUFAAOCAQEAZxGls/mNT4GyAf9u9lg7
8sSA27sc3xFvHNogrT4yUCbYAOhLXO4HJ9XuKaFyz4bKz6JGdLaQDknDI1GUvpJLpiPTXk4cq1pp
HVt5/2QVeDCGtite4CH/YrAe4gufBqWo9q7XQeQbjil0mOUsSp1ErrcSadyT+KZoD4GXJBIVFcOI
WKL7aCHzSLpw/+DY1sEiAbStmhz0K+UrFK+FVdZn1RIWGeVClhJklLb2vNjQgPYGdd5nKyLrlA4z
ekPDDWdmmxwv4A3MG8KSnl8VBU5CmAZLR1YRaioK6xL1QaH0a16FTkn3y6GVeYUGsTeyLvLlfhgA
ZLCP64EJEfE1mGxCJg==</X509Certificate></X509Data></KeyInfo></ds:Signature></cs:CSMessage>""".getBytes("UTF-8")

static byte[] simpleCSMessageWithEmptyPayloadVersion = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="" timeStamp="2015-05-27T10:26:20.373+02:00" version="2.0" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd"><cs:name>testname</cs:name><cs:sourceId>SOMESOURCEID</cs:sourceId><cs:destinationId>somedest</cs:destinationId><cs:organisation>someorg</cs:organisation><cs:payload><sysconfig:GetActiveConfigurationRequest><sysconfig:application>asdf</sysconfig:application><sysconfig:organisationShortName>SomeOrg</sysconfig:organisationShortName></sysconfig:GetActiveConfigurationRequest></cs:payload><ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#12345678-1234-4444-8000-123456789012"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>n4Cyks7jfjT2Am4eKn/UrIcZCOgrb0u24pwAVBMFB1M=</DigestValue></Reference></SignedInfo><SignatureValue>WGL1gGZ2MDMedYvjqeCIfqcep/gtjc7vi0s8jZ7kppr00Fm1jXrmT47W729EUV9heK3Mtsf+7vjk
gA9rPR+/KcmUJHHv2rB5aW28Tv9/1T2rUgpROhKAp9ocMSvtwOL9CFaeCTbV4gUjX7IvwMrkQhH/
e7y5EAH1XSNRDqiuUJ61FpwblbTpLB8hwtfc+ZaCQ3LqAG+zHM8Y1jih7doECxwo588HWIVgNNdb
TgrCV08Dd/LEAb2UWeNPWCLue0rU7CHbeif6P3wLPJ/IqlB+p+5OqeC+oiCa1IAMJ+8lxXnAPi3W
bhRLxBHhOgDXJuQg3k17tl9U8FFv4AW8Xa1wRQ==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
dXN0b21lcjEgQVQgU2VydmVyQ0ExGjAYBgNVBAoMEURlbW8gQ3VzdG9tZXIxIEFUMB4XDTEyMTAx
MDE0NDQwNFoXDTE0MTAxMDE0NDQwNFowKzENMAsGA1UEAwwEdGVzdDEaMBgGA1UECgwRRGVtbyBD
dXN0b21lcjEgQVQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCbDqmR4e8sgxw2Afi/
y3i/mT7WwtpW18/QfyUGpYPPxQ4bvPPn61y3jJg/dAbGHvnyQSHfIvrIJUN83q6evvk0bNZNVSEN
UEP29isE4D+KjD3PFtAzQq18P8m/8mSXMva5VTooEUSDX+VJ/6el6tnyZdc85AlIJkkkvyiDKcjh
f10yllaiVCHLunGMDXAec4DapPi5GdmSMMXyPOhRx5e+oy6b5q9XmT3C29VNVFf+tkAt3ew3BoQb
d+VrlBI4oRYq+mfbgkXU6dSKr9DRqhsbu5rU4Jdst2KClXsxaxvC0rVeKQ8iXCDKFH5glzhSYoeW
l7CI15CdQM6/so7EisSvAgMBAAGjgeMwgeAwHQYDVR0OBBYEFLpidyp0Pc46cUpJf1neFnq/rLJB
MAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUgEn+Hp9+Yxe4lOhaIPmf++Wu7SYwGAYDVR0gBBEw
DzANBgsrBgEEAYH1fgMDCTBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vYXQtY3JsLndtLm5ldC9k
ZW1vY3VzdG9tZXIxX3NlcnZlcmNhLmNybDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwDwYDVR0RBAgwBoIEdGVzdDANBgkqhkiG9w0BAQUFAAOCAQEAZxGls/mNT4GyAf9u9lg7
8sSA27sc3xFvHNogrT4yUCbYAOhLXO4HJ9XuKaFyz4bKz6JGdLaQDknDI1GUvpJLpiPTXk4cq1pp
HVt5/2QVeDCGtite4CH/YrAe4gufBqWo9q7XQeQbjil0mOUsSp1ErrcSadyT+KZoD4GXJBIVFcOI
WKL7aCHzSLpw/+DY1sEiAbStmhz0K+UrFK+FVdZn1RIWGeVClhJklLb2vNjQgPYGdd5nKyLrlA4z
ekPDDWdmmxwv4A3MG8KSnl8VBU5CmAZLR1YRaioK6xL1QaH0a16FTkn3y6GVeYUGsTeyLvLlfhgA
ZLCP64EJEfE1mGxCJg==</X509Certificate></X509Data></KeyInfo></ds:Signature></cs:CSMessage>""".getBytes("UTF-8")

static byte[] simpleCSMessageWithoutVersion = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="2.1" timeStamp="2015-05-27T10:26:20.373+02:00"  xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd"><cs:name>testname</cs:name><cs:sourceId>SOMESOURCEID</cs:sourceId><cs:destinationId>somedest</cs:destinationId><cs:organisation>someorg</cs:organisation><cs:payload><sysconfig:GetActiveConfigurationRequest><sysconfig:application>asdf</sysconfig:application><sysconfig:organisationShortName>SomeOrg</sysconfig:organisationShortName></sysconfig:GetActiveConfigurationRequest></cs:payload><ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#12345678-1234-4444-8000-123456789012"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>n4Cyks7jfjT2Am4eKn/UrIcZCOgrb0u24pwAVBMFB1M=</DigestValue></Reference></SignedInfo><SignatureValue>WGL1gGZ2MDMedYvjqeCIfqcep/gtjc7vi0s8jZ7kppr00Fm1jXrmT47W729EUV9heK3Mtsf+7vjk
gA9rPR+/KcmUJHHv2rB5aW28Tv9/1T2rUgpROhKAp9ocMSvtwOL9CFaeCTbV4gUjX7IvwMrkQhH/
e7y5EAH1XSNRDqiuUJ61FpwblbTpLB8hwtfc+ZaCQ3LqAG+zHM8Y1jih7doECxwo588HWIVgNNdb
TgrCV08Dd/LEAb2UWeNPWCLue0rU7CHbeif6P3wLPJ/IqlB+p+5OqeC+oiCa1IAMJ+8lxXnAPi3W
bhRLxBHhOgDXJuQg3k17tl9U8FFv4AW8Xa1wRQ==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
dXN0b21lcjEgQVQgU2VydmVyQ0ExGjAYBgNVBAoMEURlbW8gQ3VzdG9tZXIxIEFUMB4XDTEyMTAx
MDE0NDQwNFoXDTE0MTAxMDE0NDQwNFowKzENMAsGA1UEAwwEdGVzdDEaMBgGA1UECgwRRGVtbyBD
dXN0b21lcjEgQVQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCbDqmR4e8sgxw2Afi/
y3i/mT7WwtpW18/QfyUGpYPPxQ4bvPPn61y3jJg/dAbGHvnyQSHfIvrIJUN83q6evvk0bNZNVSEN
UEP29isE4D+KjD3PFtAzQq18P8m/8mSXMva5VTooEUSDX+VJ/6el6tnyZdc85AlIJkkkvyiDKcjh
f10yllaiVCHLunGMDXAec4DapPi5GdmSMMXyPOhRx5e+oy6b5q9XmT3C29VNVFf+tkAt3ew3BoQb
d+VrlBI4oRYq+mfbgkXU6dSKr9DRqhsbu5rU4Jdst2KClXsxaxvC0rVeKQ8iXCDKFH5glzhSYoeW
l7CI15CdQM6/so7EisSvAgMBAAGjgeMwgeAwHQYDVR0OBBYEFLpidyp0Pc46cUpJf1neFnq/rLJB
MAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUgEn+Hp9+Yxe4lOhaIPmf++Wu7SYwGAYDVR0gBBEw
DzANBgsrBgEEAYH1fgMDCTBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vYXQtY3JsLndtLm5ldC9k
ZW1vY3VzdG9tZXIxX3NlcnZlcmNhLmNybDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwDwYDVR0RBAgwBoIEdGVzdDANBgkqhkiG9w0BAQUFAAOCAQEAZxGls/mNT4GyAf9u9lg7
8sSA27sc3xFvHNogrT4yUCbYAOhLXO4HJ9XuKaFyz4bKz6JGdLaQDknDI1GUvpJLpiPTXk4cq1pp
HVt5/2QVeDCGtite4CH/YrAe4gufBqWo9q7XQeQbjil0mOUsSp1ErrcSadyT+KZoD4GXJBIVFcOI
WKL7aCHzSLpw/+DY1sEiAbStmhz0K+UrFK+FVdZn1RIWGeVClhJklLb2vNjQgPYGdd5nKyLrlA4z
ekPDDWdmmxwv4A3MG8KSnl8VBU5CmAZLR1YRaioK6xL1QaH0a16FTkn3y6GVeYUGsTeyLvLlfhgA
ZLCP64EJEfE1mGxCJg==</X509Certificate></X509Data></KeyInfo></ds:Signature></cs:CSMessage>""".getBytes("UTF-8")

static byte[] simpleCSMessageWithoutPayloadVersion = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012"  timeStamp="2015-05-27T10:26:20.373+02:00" version="2.0" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd"><cs:name>testname</cs:name><cs:sourceId>SOMESOURCEID</cs:sourceId><cs:destinationId>somedest</cs:destinationId><cs:organisation>someorg</cs:organisation><cs:payload><sysconfig:GetActiveConfigurationRequest><sysconfig:application>asdf</sysconfig:application><sysconfig:organisationShortName>SomeOrg</sysconfig:organisationShortName></sysconfig:GetActiveConfigurationRequest></cs:payload><ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#12345678-1234-4444-8000-123456789012"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>n4Cyks7jfjT2Am4eKn/UrIcZCOgrb0u24pwAVBMFB1M=</DigestValue></Reference></SignedInfo><SignatureValue>WGL1gGZ2MDMedYvjqeCIfqcep/gtjc7vi0s8jZ7kppr00Fm1jXrmT47W729EUV9heK3Mtsf+7vjk
gA9rPR+/KcmUJHHv2rB5aW28Tv9/1T2rUgpROhKAp9ocMSvtwOL9CFaeCTbV4gUjX7IvwMrkQhH/
e7y5EAH1XSNRDqiuUJ61FpwblbTpLB8hwtfc+ZaCQ3LqAG+zHM8Y1jih7doECxwo588HWIVgNNdb
TgrCV08Dd/LEAb2UWeNPWCLue0rU7CHbeif6P3wLPJ/IqlB+p+5OqeC+oiCa1IAMJ+8lxXnAPi3W
bhRLxBHhOgDXJuQg3k17tl9U8FFv4AW8Xa1wRQ==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
dXN0b21lcjEgQVQgU2VydmVyQ0ExGjAYBgNVBAoMEURlbW8gQ3VzdG9tZXIxIEFUMB4XDTEyMTAx
MDE0NDQwNFoXDTE0MTAxMDE0NDQwNFowKzENMAsGA1UEAwwEdGVzdDEaMBgGA1UECgwRRGVtbyBD
dXN0b21lcjEgQVQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCbDqmR4e8sgxw2Afi/
y3i/mT7WwtpW18/QfyUGpYPPxQ4bvPPn61y3jJg/dAbGHvnyQSHfIvrIJUN83q6evvk0bNZNVSEN
UEP29isE4D+KjD3PFtAzQq18P8m/8mSXMva5VTooEUSDX+VJ/6el6tnyZdc85AlIJkkkvyiDKcjh
f10yllaiVCHLunGMDXAec4DapPi5GdmSMMXyPOhRx5e+oy6b5q9XmT3C29VNVFf+tkAt3ew3BoQb
d+VrlBI4oRYq+mfbgkXU6dSKr9DRqhsbu5rU4Jdst2KClXsxaxvC0rVeKQ8iXCDKFH5glzhSYoeW
l7CI15CdQM6/so7EisSvAgMBAAGjgeMwgeAwHQYDVR0OBBYEFLpidyp0Pc46cUpJf1neFnq/rLJB
MAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUgEn+Hp9+Yxe4lOhaIPmf++Wu7SYwGAYDVR0gBBEw
DzANBgsrBgEEAYH1fgMDCTBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vYXQtY3JsLndtLm5ldC9k
ZW1vY3VzdG9tZXIxX3NlcnZlcmNhLmNybDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwDwYDVR0RBAgwBoIEdGVzdDANBgkqhkiG9w0BAQUFAAOCAQEAZxGls/mNT4GyAf9u9lg7
8sSA27sc3xFvHNogrT4yUCbYAOhLXO4HJ9XuKaFyz4bKz6JGdLaQDknDI1GUvpJLpiPTXk4cq1pp
HVt5/2QVeDCGtite4CH/YrAe4gufBqWo9q7XQeQbjil0mOUsSp1ErrcSadyT+KZoD4GXJBIVFcOI
WKL7aCHzSLpw/+DY1sEiAbStmhz0K+UrFK+FVdZn1RIWGeVClhJklLb2vNjQgPYGdd5nKyLrlA4z
ekPDDWdmmxwv4A3MG8KSnl8VBU5CmAZLR1YRaioK6xL1QaH0a16FTkn3y6GVeYUGsTeyLvLlfhgA
ZLCP64EJEfE1mGxCJg==</X509Certificate></X509Data></KeyInfo></ds:Signature></cs:CSMessage>""".getBytes("UTF-8")

static byte[] simpleCSMessageWithInvalidPayload ="""<?xml version="1.0" encoding="UTF-8" standalone="no"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="2.0" timeStamp="2015-05-28T10:05:37.642+02:00" version="2.0" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd"><cs:name>testname</cs:name><cs:sourceId>SOMESOURCEID</cs:sourceId><cs:destinationId>somedest</cs:destinationId><cs:organisation>someorg</cs:organisation><cs:payload><sysconfig:GetActiveConfigurationRequest><sysconfig:application>asdf</sysconfig:application></sysconfig:GetActiveConfigurationRequest></cs:payload><ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#12345678-1234-4444-8000-123456789012"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>dCyc1LE4El/q7sbCCUctZG1aDHclWmRkkUhsmPQudOg=</DigestValue></Reference></SignedInfo><SignatureValue>W4bJt70YZcz7K0z44xje3UXlyw1L6toVjoaFe1r3pnSlJ03lkhLS0PrXh+ydUlgWsRJdff4B1n00
WWd4HAq2g4+/9+hbUDYD91yHwtop61Zzd/YOeLpCt2pQkCwAY9bRuhYowz3QWR7qA0/JfjsnysPx
zwf2br8bqAl1Oy1SeDoTLNUJ8+lZnE1xwc2gj0OSteMGPUTxOU5/yd174bt/H+6Um+Xp0JdCN+A1
9uy1kr5ZEvBFBwXWwuQcZs/xSuszqqW5vGAsUzETkPWqWR3GlbSXycUC3Zm1V3pGCiJbRVj5XEe4
7HUoAX25MaMLsWIXorXjhIafsoX1ERTIiZ/AmA==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
dXN0b21lcjEgQVQgU2VydmVyQ0ExGjAYBgNVBAoMEURlbW8gQ3VzdG9tZXIxIEFUMB4XDTEyMTAx
MDE0NDQwNFoXDTE0MTAxMDE0NDQwNFowKzENMAsGA1UEAwwEdGVzdDEaMBgGA1UECgwRRGVtbyBD
dXN0b21lcjEgQVQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCbDqmR4e8sgxw2Afi/
y3i/mT7WwtpW18/QfyUGpYPPxQ4bvPPn61y3jJg/dAbGHvnyQSHfIvrIJUN83q6evvk0bNZNVSEN
UEP29isE4D+KjD3PFtAzQq18P8m/8mSXMva5VTooEUSDX+VJ/6el6tnyZdc85AlIJkkkvyiDKcjh
f10yllaiVCHLunGMDXAec4DapPi5GdmSMMXyPOhRx5e+oy6b5q9XmT3C29VNVFf+tkAt3ew3BoQb
d+VrlBI4oRYq+mfbgkXU6dSKr9DRqhsbu5rU4Jdst2KClXsxaxvC0rVeKQ8iXCDKFH5glzhSYoeW
l7CI15CdQM6/so7EisSvAgMBAAGjgeMwgeAwHQYDVR0OBBYEFLpidyp0Pc46cUpJf1neFnq/rLJB
MAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUgEn+Hp9+Yxe4lOhaIPmf++Wu7SYwGAYDVR0gBBEw
DzANBgsrBgEEAYH1fgMDCTBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vYXQtY3JsLndtLm5ldC9k
ZW1vY3VzdG9tZXIxX3NlcnZlcmNhLmNybDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwDwYDVR0RBAgwBoIEdGVzdDANBgkqhkiG9w0BAQUFAAOCAQEAZxGls/mNT4GyAf9u9lg7
8sSA27sc3xFvHNogrT4yUCbYAOhLXO4HJ9XuKaFyz4bKz6JGdLaQDknDI1GUvpJLpiPTXk4cq1pp
HVt5/2QVeDCGtite4CH/YrAe4gufBqWo9q7XQeQbjil0mOUsSp1ErrcSadyT+KZoD4GXJBIVFcOI
WKL7aCHzSLpw/+DY1sEiAbStmhz0K+UrFK+FVdZn1RIWGeVClhJklLb2vNjQgPYGdd5nKyLrlA4z
ekPDDWdmmxwv4A3MG8KSnl8VBU5CmAZLR1YRaioK6xL1QaH0a16FTkn3y6GVeYUGsTeyLvLlfhgA
ZLCP64EJEfE1mGxCJg==</X509Certificate></X509Data></KeyInfo></ds:Signature></cs:CSMessage>""".getBytes("UTF-8")

static byte[] simpleCSMessageWithBadCertificate = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="2.0" timeStamp="2015-05-28T09:52:58.204+02:00" version="2.0" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd"><cs:name>testname</cs:name><cs:sourceId>SOMESOURCEID</cs:sourceId><cs:destinationId>somedest</cs:destinationId><cs:organisation>someorg</cs:organisation><cs:payload><sysconfig:GetActiveConfigurationRequest><sysconfig:application>asdf</sysconfig:application><sysconfig:organisationShortName>SomeOrg</sysconfig:organisationShortName></sysconfig:GetActiveConfigurationRequest></cs:payload><ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#12345678-1234-4444-8000-123456789012"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>WH7EQj0roOOavhQhpredMPODCgjDp1R8ih4VrHy4QGo=</DigestValue></Reference></SignedInfo><SignatureValue>EYOLAj/yA4jFn3otvtOt/I/fv9iTrJ20H03/ENQh3QGXnKl/XeZFcLyYODUwDhqHR8xzuy/adfFF
DIikCJC1NNaBjxki10awc5D/eEiu6O9e1qhUQnP/R+fmBc+SqTMC8USEpB6R3yMRQML5KTMyHGRe
lMVXiPa9+nHBoZccbgCkqs5qc2yRrWAacGc5qv7Y8rPG5u47IVJM1V4cXlQCwVM2vlGuoZlEDQWn
DOpiOIp+aURpAmJt0vaiyPR8p+ZKfVbV26cFzSMVEjGngxEP0vvRSIi4Zypwmu1IdYs4ZYTTYslk
x3vBOm2AkhumAc1cq5KtbdOkdTSzo3Wyd6SQZQ==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
dXN0b21lcjEgQVQgU2VydmVyQ0ExGjAYBgNVBAdsoMEURlbW8gQ3VzdG9tZXIxIEFUMB4XDTEyMTAx
MDE0NDQwNFoXDTE0MTAxMDE0NDQwNFowKzENMAsGA1UEAwwEdGVzdDEaMBgGA1UECgwRRGVtbyBD
dXN0b21lcjEgQVQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCbDqmR4e8sgxw2Afi/
y3i/mT7WwtpW18/QfyUGpYPPxQ4bvPPn61y3jJg/dAbGHvnyQSHfIvrIJUN83q6evvk0bNZNVSEN
UEP29isE4D+KjD3PFtAzQq18P8m/8mSXMva5VTooEUSDX+VJ/6el6tnyZdc85AlIJkkkvyiDKcjh
f10yllaiVCHLunGMDXAec4DapPi5GdmSMMXyPOhRx5e+oy6b5q9XmT3C29VNVFf+tkAt3ew3BoQb
d+VrlBI4oRYq+mfbgkXU6dSKr9DRqhsbu5rU4Jdst2KClXsxaxvC0rVeKQ8iXCDKFH5glzhSYoeW
l7CI15CdQM6/so7EisSvAgMBAAGjgeMwgeAwHQYDVR0OBBYEFLpidyp0Pc46cUpJf1neFnq/rLJB
MAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUgEn+Hp9+Yxe4lOhaIPmf++Wu7SYwGAYDVR0gBBEw
DzANBgsrBgEEAYH1fgMDCTBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vYXQtY3JsLndtLm5ldC9k
ZW1vY3VzdG9tZXIxX3NlcnZlcmNhLmNybDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwDwYDVR0RBAgwBoIEdGVzdDANBgkqhkiG9w0BAQUFAAOCAQEAZxGls/mNT4GyAf9u9lg7
8sSA27sc3xFvHNogrT4yUCbYAOhLXO4HJ9XuKaFyz4bKz6JGdLaQDknDI1GUvpJLpiPTXk4cq1pp
HVt5/2QVeDCGtite4CH/YrAe4gufBqWo9q7XQeQbjil0mOUsSp1ErrcSadyT+KZoD4GXJBIVFcOI
WKL7aCHzSLpw/+DY1sEiAbStmhz0K+UrFK+FVdZn1RIWGeVClhJklLb2vNjQgPYGdd5nKyLrlA4z
ekPDDWdmmxwv4A3MG8KSnl8VBU5CmAZLR1YRaioK6xL1QaH0a16FTkn3y6GVeYUGsTeyLvLlfhgA
ZLCP64EJEfE1mGxCJg==</X509Certificate></X509Data></KeyInfo></ds:Signature></cs:CSMessage>""".getBytes("UTF-8")

static byte[] getApprovalRequestWithInvalidRequestPayload = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><cs:CSMessage xmlns:cs="http://certificateservices.org/xsd/csmessages2_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:sysconfig="http://certificateservices.org/xsd/sysconfig2_0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="12345678-1234-4444-8000-123456789012" payLoadVersion="2.0" timeStamp="2015-05-29T15:23:59.054+02:00" version="2.0" xsi:schemaLocation="http://certificateservices.org/xsd/csmessages2_0 csmessages_schema2_0.xsd"><cs:name>GetApprovalRequest</cs:name><cs:sourceId>SOMEREQUESTER</cs:sourceId><cs:destinationId>SOMESOURCEID</cs:destinationId><cs:organisation>someorg</cs:organisation><cs:originator><cs:credential><cs:credentialRequestId>123</cs:credentialRequestId><cs:uniqueId>SomeOriginatorUniqueId</cs:uniqueId><cs:displayName>SomeOrignatorDisplayName</cs:displayName><cs:serialNumber>SomeSerialNumber</cs:serialNumber><cs:issuerId>SomeIssuerId</cs:issuerId><cs:status>100</cs:status><cs:credentialType>SomeCredentialType</cs:credentialType><cs:credentialSubType>SomeCredentialSubType</cs:credentialSubType><cs:attributes><cs:attribute><cs:key>someattrkey</cs:key><cs:value>someattrvalue</cs:value></cs:attribute></cs:attributes><cs:usages><cs:usage>someusage</cs:usage></cs:usages><cs:credentialData>MTIzNDVBQkNFRg==</cs:credentialData><cs:issueDate>1970-01-01T01:00:01.234+01:00</cs:issueDate><cs:expireDate>1970-01-01T01:00:02.234+01:00</cs:expireDate><cs:validFromDate>1970-01-01T01:00:03.234+01:00</cs:validFromDate></cs:credential></cs:originator><cs:payload><cs:GetApprovalRequest><cs:requestPayload><sysconfig:GetActiveConfigurationRequest><sysconfig:application>SomeApp</sysconfig:application></sysconfig:GetActiveConfigurationRequest></cs:requestPayload></cs:GetApprovalRequest></cs:payload><ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#12345678-1234-4444-8000-123456789012"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>8Ymvtypy/HJ9/p0Iuq8Z2B5qX3TUXeaOFJyuglpODv8=</DigestValue></Reference></SignedInfo><SignatureValue>OnA2i0E400V4p7MqeNTl4ZZy/hifljIEP2RMBe4GGk7CWnqWIWJnlOiMDYcGDwA7Q+m6mAARbvJa
0pHUp0JoNt5bGmvIb4GjJFmV7vz2jl+yFBvhoxxh3/5dUOgpehcatcDS4dFcpy+lToWkkWDkkn6B
1CLKm8NqR7+2inlrM2dtmyFiUqLBo76PwV/pgkOUDjBIxfIxmj0tlwAknT0ml1mbtm13cMkLM3uo
a8PrBamEZ6UwR/hHXMz4XWC1ctYMin7o2lR4i36bdmneu7I7qpQuF2BNBbLAg2hPx3lfwQN7HWxd
3rR4l/yMx37rZ6Bd/oaPj/q1a79aQWLbORMqPQ==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
dXN0b21lcjEgQVQgU2VydmVyQ0ExGjAYBgNVBAoMEURlbW8gQ3VzdG9tZXIxIEFUMB4XDTEyMTAx
MDE0NDQwNFoXDTE0MTAxMDE0NDQwNFowKzENMAsGA1UEAwwEdGVzdDEaMBgGA1UECgwRRGVtbyBD
dXN0b21lcjEgQVQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCbDqmR4e8sgxw2Afi/
y3i/mT7WwtpW18/QfyUGpYPPxQ4bvPPn61y3jJg/dAbGHvnyQSHfIvrIJUN83q6evvk0bNZNVSEN
UEP29isE4D+KjD3PFtAzQq18P8m/8mSXMva5VTooEUSDX+VJ/6el6tnyZdc85AlIJkkkvyiDKcjh
f10yllaiVCHLunGMDXAec4DapPi5GdmSMMXyPOhRx5e+oy6b5q9XmT3C29VNVFf+tkAt3ew3BoQb
d+VrlBI4oRYq+mfbgkXU6dSKr9DRqhsbu5rU4Jdst2KClXsxaxvC0rVeKQ8iXCDKFH5glzhSYoeW
l7CI15CdQM6/so7EisSvAgMBAAGjgeMwgeAwHQYDVR0OBBYEFLpidyp0Pc46cUpJf1neFnq/rLJB
MAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUgEn+Hp9+Yxe4lOhaIPmf++Wu7SYwGAYDVR0gBBEw
DzANBgsrBgEEAYH1fgMDCTBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vYXQtY3JsLndtLm5ldC9k
ZW1vY3VzdG9tZXIxX3NlcnZlcmNhLmNybDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwDwYDVR0RBAgwBoIEdGVzdDANBgkqhkiG9w0BAQUFAAOCAQEAZxGls/mNT4GyAf9u9lg7
8sSA27sc3xFvHNogrT4yUCbYAOhLXO4HJ9XuKaFyz4bKz6JGdLaQDknDI1GUvpJLpiPTXk4cq1pp
HVt5/2QVeDCGtite4CH/YrAe4gufBqWo9q7XQeQbjil0mOUsSp1ErrcSadyT+KZoD4GXJBIVFcOI
WKL7aCHzSLpw/+DY1sEiAbStmhz0K+UrFK+FVdZn1RIWGeVClhJklLb2vNjQgPYGdd5nKyLrlA4z
ekPDDWdmmxwv4A3MG8KSnl8VBU5CmAZLR1YRaioK6xL1QaH0a16FTkn3y6GVeYUGsTeyLvLlfhgA
ZLCP64EJEfE1mGxCJg==</X509Certificate></X509Data></KeyInfo></ds:Signature></cs:CSMessage>""".getBytes("UTF-8")

}
