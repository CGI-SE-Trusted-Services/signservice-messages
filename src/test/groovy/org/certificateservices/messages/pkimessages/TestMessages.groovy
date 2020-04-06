package org.certificateservices.messages.pkimessages;

import org.junit.Ignore;

@Ignore
public class TestMessages {
	
	public static String faultyRequestAgainstXSD = """<?xml version="1.0" encoding="UTF-8"?>
<tns:PKIMessage version="1.0" ID="12345678-1234-4123-8899-123456789012"
	xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
	xmlns:tns="http://certificateservices.org/xsd/pkimessages1_0"
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://certificateservices.org/xsd/pkimessages1_0 pkimessages_schema.xsd ">

	<sourceId>PIE1</sourceId>
	<destinationId>CA1</destinationId>
	<payload>
      	<issueTokenCredentialsRequest>
			<tokenRequest>
				<credentialRequests>
					<credentialRequest>
					    <credentialRequestId>1</credentialRequestId>
						<credentialType>X509Certificate</credentialType>
						<credentialSubType>VehicleCert</credentialSubType>
						<x509RequestType>PKCS10</x509RequestType>
						<credentialRequestData>MA==</credentialRequestData>
					</credentialRequest>
				</credentialRequests>
				<organisation>VCCDEV</organisation>
				<user>ABCDE1234</user>
				<tokenContainer>PKCS12</tokenContainer>
				<tokenType>VEHICLECERT</tokenType>
				<tokenClass>ORDINARY</tokenClass>
			</tokenRequest>
		</issueTokenCredentialsRequest>
	</payload>
	<ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
		<SignedInfo>
			<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
			<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
			<Reference URI="#e50a362b-223c-4f0a-ae80-b1a1fb168753">
				<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
				<DigestValue>MA==</DigestValue>
			</Reference>
		</SignedInfo>
		<SignatureValue>
			MA==
		</SignatureValue>
		<KeyInfo>
			<X509Data>
				<X509Certificate>MA==</X509Certificate>
			</X509Data>
		</KeyInfo>
	</ds:Signature>
</tns:PKIMessage>"""
		
	   public  static String testMessage = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><PKIMessage xmlns="http://certificateservices.org/xsd/pkimessages1_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="59fa9386-c549-4f90-9e0e-b369c15d67f6" version="1.0" xsi:schemaLocation="http://certificateservices.org/xsd/pkimessages1_0 pkimessages_schema.xsd"><name>IssueTokenCredentialsRequest</name><sourceId>SOMESOURCEID</sourceId><destinationId>SomeDestinationId</destinationId><organisation>SomeOrg</organisation><payload><issueTokenCredentialsRequest><tokenRequest><credentialRequests><credentialRequest><credentialRequestId>123</credentialRequestId><credentialType>SomeCredentialType</credentialType><credentialSubType>SomeCredentialSubType</credentialSubType><x509RequestType>SomeX509RequestType</x509RequestType><credentialRequestData>MTIzNDVBQkM=</credentialRequestData></credentialRequest></credentialRequests><user>someuser</user><tokenContainer>SomeTokenContainer</tokenContainer><tokenType>SomeTokenType</tokenType><tokenClass>SomeTokenClass</tokenClass></tokenRequest></issueTokenCredentialsRequest></payload><ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#59fa9386-c549-4f90-9e0e-b369c15d67f6"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>baU/12YkrEwSrmfHIfJHqCngu+04DJczIHkGcrv056E=</DigestValue></Reference></SignedInfo><SignatureValue>OkmAUdnYINYB7kU9mluXbQpxm+Aj49K2Ajuy4yysZIFnCnw0p+eIL4L8z6UNE+1FLVoAD564F5N4
0pdZJsT3Li4UoBGvC8i+YNb2VEBCpOC2ZPHiljwDTsTDPKiwmSfUm7VwwRkgOzMJ93WIVb5esRy3
nptv5kKsT6zL1us67607f0Dom7LHp5et1TYT3+p/dQFXQj1+bu36wh+3NAf1ILI83Z3TKfRLtSxh
RwrgejXqCXtqoX2tGr4m+BHk1j+L2EQ/eWFaoNorith1M5Nn/ea/FKRiJsIJ/Ka18F+31Vxso3sQ
cqEfBm5K+ZeO22tdYTi2maXKGXUkP6QSyy5Bsg==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
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
ZLCP64EJEfE1mGxCJg==</X509Certificate></X509Data></KeyInfo></ds:Signature></PKIMessage>"""
	   
	public  static String testMessageWithInvalidSignature = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><PKIMessage xmlns="http://certificateservices.org/xsd/pkimessages1_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="7ff1778b-5525-4311-aee7-99e4e895c113" version="1.0" xsi:schemaLocation="http://certificateservices.org/xsd/pkimessages1_0 pkimessages_schema.xsd"><name>IssueTokenCredentialsResponse</name><sourceId>SOMESOURCEID</sourceId><destinationId>SOMEREQUESTER</destinationId><payload><issueTokenCredentialsResponse><inResponseTo>5f5b4513-d818-4f34-a9e5-085ae622b0c5</inResponseTo><status>SUCCESS</status><tokenRequest><credentialRequests><credentialRequest><credentialRequestId>123</credentialRequestId><credentialType>SomeCredentialType</credentialType><credentialSubType>SomeCredentialSubType</credentialSubType><x509RequestType>SomeX509RequestType</x509RequestType><credentialRequestData>MTIzNDVBQkM=</credentialRequestData></credentialRequest></credentialRequests><organisation>someorg</organisation><user>someuser</user><tokenContainer>SomeTokenContainer2</tokenContainer><tokenType>SomeTokenType</tokenType><tokenClass>SomeTokenClass</tokenClass></tokenRequest><credentials><credential><credentialRequestId>123</credentialRequestId><uniqueId>SomeUniqueId</uniqueId><displayName>SomeDisplayName</displayName><serialNumber>SomeSerialNumber</serialNumber><issuerId>SomeIssuerId</issuerId><status>SomeStatus</status><credentialType>SomeCredentialType</credentialType><credentialSubType>SomeCredentialSubType</credentialSubType><attributes><attribute><key>someattrkey</key><value>someattrvalue</value></attribute></attributes><usages><usage>someusage</usage></usages><credentialData>MTIzNDVBQkNFRg==</credentialData><issueDate>1970-01-01T01:00:01.234+01:00</issueDate><expireDate>1970-01-01T01:00:02.234+01:00</expireDate><validFromDate>1970-01-01T01:00:03.234+01:00</validFromDate></credential></credentials></issueTokenCredentialsResponse></payload><ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#7ff1778b-5525-4311-aee7-99e4e895c113"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>eQTzERBMp+yl3eHlAwVPr8X7qOfT0l24VYrKhSLqmKs=</DigestValue></Reference></SignedInfo><SignatureValue>GlCuqTMt7jQrAwuSCGY1L+1g2kTRHgb146joYd9C2WWYhKXc3ZCfMn9ZM+53lrRZL1p8rfaKjX1i
vmM6RbtVmGlRe1DlwQ2W6Pc9/EVO/lgsSvnnihs+W6b/UQNdSUpE/B51kRGUikfx1jHifTJZ7glM
OnSSzEjK4GsJZQ21RAE7gK+wk/LUKdULALdfwDbsObpSWoUtkik+T138HfnZ5luzrZ7V5IOD6vIP
D9qI6CCmsRgOLzxgBzDtMbOjdmk3Vo6WsEe2g0d2iFKQRJtaHPGt9xOy+ES5VdValgWYdM0dg703
HbH/EhxO2Vtz3bHXHkjiX8coRD05gIFSdHnvWg==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
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
ZLCP64EJEfE1mGxCJg==</X509Certificate></X509Data></KeyInfo></ds:Signature></PKIMessage>"""
		
public  static String testMessageWithNoCert= """<?xml version="1.0" encoding="UTF-8" standalone="no"?><PKIMessage xmlns="http://certificateservices.org/xsd/pkimessages1_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="7ff1778b-5525-4311-aee7-99e4e895c113" version="1.0" xsi:schemaLocation="http://certificateservices.org/xsd/pkimessages1_0 pkimessages_schema.xsd"><name>IssueTokenCredentialsResponse</name><sourceId>SOMESOURCEID</sourceId><destinationId>SOMEREQUESTER</destinationId><payload><issueTokenCredentialsResponse><inResponseTo>5f5b4513-d818-4f34-a9e5-085ae622b0c5</inResponseTo><status>SUCCESS</status><tokenRequest><credentialRequests><credentialRequest><credentialRequestId>123</credentialRequestId><credentialType>SomeCredentialType</credentialType><credentialSubType>SomeCredentialSubType</credentialSubType><x509RequestType>SomeX509RequestType</x509RequestType><credentialRequestData>MTIzNDVBQkM=</credentialRequestData></credentialRequest></credentialRequests><organisation>someorg</organisation><user>someuser</user><tokenContainer>SomeTokenContainer2</tokenContainer><tokenType>SomeTokenType</tokenType><tokenClass>SomeTokenClass</tokenClass></tokenRequest><credentials><credential><credentialRequestId>123</credentialRequestId><uniqueId>SomeUniqueId</uniqueId><displayName>SomeDisplayName</displayName><serialNumber>SomeSerialNumber</serialNumber><issuerId>SomeIssuerId</issuerId><status>SomeStatus</status><credentialType>SomeCredentialType</credentialType><credentialSubType>SomeCredentialSubType</credentialSubType><attributes><attribute><key>someattrkey</key><value>someattrvalue</value></attribute></attributes><usages><usage>someusage</usage></usages><credentialData>MTIzNDVBQkNFRg==</credentialData><issueDate>1970-01-01T01:00:01.234+01:00</issueDate><expireDate>1970-01-01T01:00:02.234+01:00</expireDate><validFromDate>1970-01-01T01:00:03.234+01:00</validFromDate></credential></credentials></issueTokenCredentialsResponse></payload><ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#7ff1778b-5525-4311-aee7-99e4e895c113"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>eQTzERBMp+yl3eHlAwVPr8X7qOfT0l24VYrKhSLqmKs=</DigestValue></Reference></SignedInfo><SignatureValue>GlCuqTMt7jQrAwuSCGY1L+1g2kTRHgb146joYd9C2WWYhKXc3ZCfMn9ZM+53lrRZL1p8rfaKjX1i
vmM6RbtVmGlRe1DlwQ2W6Pc9/EVO/lgsSvnnihs+W6b/UQNdSUpE/B51kRGUikfx1jHifTJZ7glM
OnSSzEjK4GsJZQ21RAE7gK+wk/LUKdULALdfwDbsObpSWoUtkik+T138HfnZ5luzrZ7V5IOD6vIP
D9qI6CCmsRgOLzxgBzDtMbOjdmk3Vo6WsEe2g0d2iFKQRJtaHPGt9xOy+ES5VdValgWYdM0dg703
HbH/EhxO2Vtz3bHXHkjiX8coRD05gIFSdHnvWg==</SignatureValue><KeyInfo><X509Data></X509Data></KeyInfo></ds:Signature></PKIMessage>"""

	public static final String testMessageWithInvalidVersion = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><PKIMessage xmlns="http://certificateservices.org/xsd/pkimessages1_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="d774ba90-d6ca-4a89-b941-39df4882e418" version="999.99" xsi:schemaLocation="http://certificateservices.org/xsd/pkimessages1_0 pkimessages_schema.xsd"><name>IssueTokenCredentialsResponse</name><sourceId>SOMESOURCEID</sourceId><destinationId>SOMEREQUESTER</destinationId><payload><issueTokenCredentialsResponse><inResponseTo>cd51dd18-d83f-409e-8a96-fb2c53f403f0</inResponseTo><status>SUCCESS</status><tokenRequest><credentialRequests><credentialRequest><credentialRequestId>123</credentialRequestId><credentialType>SomeCredentialType</credentialType><credentialSubType>SomeCredentialSubType</credentialSubType><x509RequestType>SomeX509RequestType</x509RequestType><credentialRequestData>MTIzNDVBQkM=</credentialRequestData></credentialRequest></credentialRequests><organisation>someorg</organisation><user>someuser</user><tokenContainer>SomeTokenContainer</tokenContainer><tokenType>SomeTokenType</tokenType><tokenClass>SomeTokenClass</tokenClass></tokenRequest><credentials><credential><credentialRequestId>123</credentialRequestId><uniqueId>SomeUniqueId</uniqueId><displayName>SomeDisplayName</displayName><serialNumber>SomeSerialNumber</serialNumber><issuerId>SomeIssuerId</issuerId><status>SomeStatus</status><credentialType>SomeCredentialType</credentialType><credentialSubType>SomeCredentialSubType</credentialSubType><attributes><attribute><key>someattrkey</key><value>someattrvalue</value></attribute></attributes><usages><usage>someusage</usage></usages><credentialData>MTIzNDVBQkNFRg==</credentialData><issueDate>1970-01-01T01:00:01.234+01:00</issueDate><expireDate>1970-01-01T01:00:02.234+01:00</expireDate><validFromDate>1970-01-01T01:00:03.234+01:00</validFromDate></credential></credentials></issueTokenCredentialsResponse></payload><ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#d774ba90-d6ca-4a89-b941-39df4882e418"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>4RFQnBGB96Zao4k5eeTd8FxOgJ0dso1aWoyLouxi9ac=</DigestValue></Reference></SignedInfo><SignatureValue>PKovv4BQqz0MKf8k6byxYhDdBRrWict6j3+O6vpzZcFVetm4Q7epzp2dg6gHfkeqr3sTRRJ91dBI
VUCsRYcW9H/4lEiOVUfbvOoTL5jFqnJ9UKWKVYmp5Br++e4Asxlquw2KEZ+pF6zietAJzyRDeOQO
Pp64BJ66akDl1xWTffnSlm8K+GUZ+nbw6g/wJlR5QNBFaGWJyX7Z01yLSvxg5zpUaGkl1oF5SKVM
8S1QWAgZUh5ia+t2skfnvf1K+lBFqiIxAJ/yC6pNuD3dgGFwIFYy2JP2NIycJkl2U43gW4YCrb/W
DIAIFi6bK6hb/eY+vYxavcm3OULQ8eOo0QViCA==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
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
ZLCP64EJEfE1mGxCJg==</X509Certificate></X509Data></KeyInfo></ds:Signature></PKIMessage>"""
	
public  static String testMessageWithResponse = """<?xml version="1.0" encoding="UTF-8" standalone="no"?><PKIMessage xmlns="http://certificateservices.org/xsd/pkimessages1_0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="59fa9386-c549-4f90-9e0e-b369c15d67f6" version="1.0" xsi:schemaLocation="http://certificateservices.org/xsd/pkimessages1_0 pkimessages_schema.xsd"><name>IssueTokenCredentialsRequest</name><sourceId>SOMEREQUESTER</sourceId><destinationId>SomeDestinationId</destinationId><organisation>SomeOrg</organisation><payload><issueTokenCredentialsRequest><tokenRequest><credentialRequests><credentialRequest><credentialRequestId>123</credentialRequestId><credentialType>SomeCredentialType</credentialType><credentialSubType>SomeCredentialSubType</credentialSubType><x509RequestType>SomeX509RequestType</x509RequestType><credentialRequestData>MTIzNDVBQkM=</credentialRequestData></credentialRequest></credentialRequests><user>someuser</user><tokenContainer>SomeTokenContainer</tokenContainer><tokenType>SomeTokenType</tokenType><tokenClass>SomeTokenClass</tokenClass></tokenRequest></issueTokenCredentialsRequest></payload><ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#59fa9386-c549-4f90-9e0e-b369c15d67f6"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>baU/12YkrEwSrmfHIfJHqCngu+04DJczIHkGcrv056E=</DigestValue></Reference></SignedInfo><SignatureValue>OkmAUdnYINYB7kU9mluXbQpxm+Aj49K2Ajuy4yysZIFnCnw0p+eIL4L8z6UNE+1FLVoAD564F5N4
0pdZJsT3Li4UoBGvC8i+YNb2VEBCpOC2ZPHiljwDTsTDPKiwmSfUm7VwwRkgOzMJ93WIVb5esRy3
nptv5kKsT6zL1us67607f0Dom7LHp5et1TYT3+p/dQFXQj1+bu36wh+3NAf1ILI83Z3TKfRLtSxh
RwrgejXqCXtqoX2tGr4m+BHk1j+L2EQ/eWFaoNorith1M5Nn/ea/FKRiJsIJ/Ka18F+31Vxso3sQ
cqEfBm5K+ZeO22tdYTi2maXKGXUkP6QSyy5Bsg==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
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
ZLCP64EJEfE1mGxCJg==</X509Certificate></X509Data></KeyInfo></ds:Signature></PKIMessage>"""

public  static String testMessageWithVersion1_1= """<?xml version="1.0" encoding="UTF-8" standalone="no"?><PKIMessage xmlns="http://certificateservices.org/xsd/pkimessages1_1" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="59fa9386-c549-4f90-9e0e-b369c15d67f6" version="1.1" xsi:schemaLocation="http://certificateservices.org/xsd/pkimessages1_0 pkimessages_schema.xsd"><name>IssueTokenCredentialsRequest</name><sourceId>SOMEREQUESTER</sourceId><destinationId>SomeDestinationId</destinationId><organisation>SomeOrg</organisation><payload><issueTokenCredentialsRequest><tokenRequest><credentialRequests><credentialRequest><credentialRequestId>123</credentialRequestId><credentialType>SomeCredentialType</credentialType><credentialSubType>SomeCredentialSubType</credentialSubType><x509RequestType>SomeX509RequestType</x509RequestType><credentialRequestData>MTIzNDVBQkM=</credentialRequestData></credentialRequest></credentialRequests><user>someuser</user><tokenContainer>SomeTokenContainer</tokenContainer><tokenType>SomeTokenType</tokenType><tokenClass>SomeTokenClass</tokenClass></tokenRequest></issueTokenCredentialsRequest></payload><ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#59fa9386-c549-4f90-9e0e-b369c15d67f6"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>baU/12YkrEwSrmfHIfJHqCngu+04DJczIHkGcrv056E=</DigestValue></Reference></SignedInfo><SignatureValue>OkmAUdnYINYB7kU9mluXbQpxm+Aj49K2Ajuy4yysZIFnCnw0p+eIL4L8z6UNE+1FLVoAD564F5N4
0pdZJsT3Li4UoBGvC8i+YNb2VEBCpOC2ZPHiljwDTsTDPKiwmSfUm7VwwRkgOzMJ93WIVb5esRy3
nptv5kKsT6zL1us67607f0Dom7LHp5et1TYT3+p/dQFXQj1+bu36wh+3NAf1ILI83Z3TKfRLtSxh
RwrgejXqCXtqoX2tGr4m+BHk1j+L2EQ/eWFaoNorith1M5Nn/ea/FKRiJsIJ/Ka18F+31Vxso3sQ
cqEfBm5K+ZeO22tdYTi2maXKGXUkP6QSyy5Bsg==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIID0jCCArqgAwIBAgIIJFd3fZe2b/8wDQYJKoZIhvcNAQEFBQAwQTEjMCEGA1UEAwwaRGVtbyBD
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
ZLCP64EJEfE1mGxCJg==</X509Certificate></X509Data></KeyInfo></ds:Signature></PKIMessage>"""

public  static String testMessageWithNoVersion= """<?xml version="1.0" encoding="UTF-8" standalone="no"?><PKIMessage xmlns="http://certificateservices.org/xsd/pkimessages1_1" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="59fa9386-c549-4f90-9e0e-b369c15d67f6"  xsi:schemaLocation="http://certificateservices.org/xsd/pkimessages1_0 pkimessages_schema.xsd"></PKIMessage>"""
public  static String testMessageWithEmptyVersion= """<?xml version="1.0" encoding="UTF-8" standalone="no"?><PKIMessage xmlns="http://certificateservices.org/xsd/pkimessages1_1" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="59fa9386-c549-4f90-9e0e-b369c15d67f6" version="" xsi:schemaLocation="http://certificateservices.org/xsd/pkimessages1_0 pkimessages_schema.xsd"></PKIMessage>"""

}
