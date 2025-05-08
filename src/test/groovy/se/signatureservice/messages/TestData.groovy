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
package se.signatureservice.messages

class TestData {
    static byte[] base64Cert =(
            "MIIDLTCCAhWgAwIBAgIIYmVP6xQ/t3QwDQYJKoZIhvcNAQEFBQAwJDETMBEGA1UE" +
            "AwwKVGVzdCBlSURDQTENMAsGA1UECgwEVGVzdDAeFw0xMTEwMjExNDM2MzlaFw0z" +
            "MTEwMjExNDM2MzlaMCQxEzARBgNVBAMMClRlc3QgZUlEQ0ExDTALBgNVBAoMBFRl" +
            "c3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDecUf5if2UdWbV/HIj" +
            "h6U3XIymmh28wo8VVxPIbV1A8Yxz7QaMkP8vqaDwHnB1B6mHEjn4VyVogxWxI70I" +
            "wPudUL+Oxkc9ZL7H7zkbi6l2d/n85PjyZvdarCwcBzpEqIRsc+Wa3bGFKBpdZjwL" +
            "XjuuI4YWx+uUrQ96X+WusvFcb8C4Ru3w/K8Saf7yLJNvqmTJrgAOeKY49Jnp9V5x" +
            "9dGe+xpHR3t2xhJ5HXhm+SeUsrH5fHXky7/OVKvLPOXSve+1KHpyp+eOxxgYozTh" +
            "5k+viL0pP9G3AbEPp1mXtxCNzRjUgNlG0BDSIbowD5JciLkz8uYbamLzoUiz1KzZ" +
            "uCfXAgMBAAGjYzBhMB0GA1UdDgQWBBT6HyWgz7ykq9BxTCaULtOIjen3bDAPBgNV" +
            "HRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFPofJaDPvKSr0HFMJpQu04iN6fdsMA4G" +
            "A1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQUFAAOCAQEAbG7Y+rm82Gz1yIWVFKBf" +
            "XxDee7UwX2pyKdDfvRf9lFLxXv4LKBnuM5Zlb2RPdAAe7tTMtnYDwOWs4Uniy57h" +
            "YrCKU3v80u4uZoH8FNCG22APWQ+xa5UQtuq0yRf2xp2e4wjGZLQZlYUbePAZEjle" +
            "0E2YIa/kOrlvy5Z62sj24yczBL9uHfWpQUefA1+R9JpbOj0WEk+rAV0xJ2knmC/R" +
            "NzHWz92kL6UKUFzyBXBiBbY7TSVjO+bV/uPaTEVP7QhJk4Cahg1a7h8iMdF78ths" +
            "+xMeZX1KyiL4Dpo2rocZAvdL/C8qkt/uEgOjwOTdmoRVxkFWcm+DRNa26cclBQ4t" +
            "Vw==").getBytes()

    static byte[] base64CertWithKeyUsage = (
            "MIIDtTCCAp2gAwIBAgIIQIAaGoHvZG0wDQYJKoZIhvcNAQEFBQAwZTE1MDMGA1UE" +
            "AwwsTG9naWNhIFNFIElNIENlcnRpZmljYXRlIFNlcnZpY2UgU1QgU2VydmVyQ0Ex" +
            "LDAqBgNVBAoMI0xvZ2ljYSBTRSBJTSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlIFNUMB4X" +
            "DTE3MDcxMjExMDcwMloXDTE5MDcxMTExMDcwMlowWTEpMCcGA1UEAwwgdGVzdC5i" +
            "YWNrZW5kLnNpZ25hdHVyZXNlcnZpY2Uuc2UxLDAqBgNVBAoMI0xvZ2ljYSBTRSBJ" +
            "TSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlIFNUMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A" +
            "MIIBCgKCAQEAhLoCPpDifhnsbiR27W1tJ4SFrjHvhfe8GVlQC6F7pps5x7LsRj4X" +
            "ZvcpIQ+o7qaFD7mMxMb4qPEH/n8sUsbPt12ByRgarXFOI9S6XyB0il6TGuODXvIX" +
            "GeUhZHcRUdgB/nbGgZrboPIMXU5IXJAcm6/K4CJwr0s1Ix/vGy/QgjJ1Dl9obxSJ" +
            "1Lh5tnUJxd5/2XQod+6up5XAtieLwfURJSj3gF6dKNp/cMhwVkPtDM2PA+zdayil" +
            "+PUsvKiZQxBny/K7obmALCuTqDmQkE2WvLGdezooBQjpCeWUSweq+8IVDgrkLkrI" +
            "GFM2ERmGYnnFG/E0Iv4l+ye9SGMGGfnMRwIDAQABo3UwczAMBgNVHRMBAf8EAjAA" +
            "MB8GA1UdIwQYMBaAFOBD1HKL2rBlAoaehRcftgg2gElPMBMGA1UdJQQMMAoGCCsG" +
            "AQUFBwMBMB0GA1UdDgQWBBQ1p+7jFbgGWSTPUFU7TmukAROfDDAOBgNVHQ8BAf8E" +
            "BAMCBaAwDQYJKoZIhvcNAQEFBQADggEBAFVOWWhnXDGglSp5jxuhxEftfYp8ZK/q" +
            "npmY6Dkgix2qZL2KFpzxd3CF1HHAIFyw+X9bVZHemIeEjtHttinkzsOPBkAYA2FY" +
            "gWSBy4Wc8ucxoguxnNrVGRBv20CX6jIfOCeAZGi0oTrj4OvBwbLvNgh35BwAHl99" +
            "rPIJOnH7SogrGNGYYHaCxEjEDYB2uOZ/0z17MHdZ1aPpgR/6z+kZUQ0mjskkGAXt" +
            "B+eV9XZWiEf4DcQWCNkpeYW9H3dI9nsxCbxUuH5dJMsWtpzADQYScIMh0dlFTxeQ" +
            "tXiZAHBV81NZPvVE8wUr2cX+V46RBvi9fqFV7ysx12Pzc6qjVU2C1Ok=").getBytes()
}
