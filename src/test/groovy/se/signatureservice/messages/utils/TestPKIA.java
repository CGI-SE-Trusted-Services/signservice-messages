/*************************************************************************
 *                                                                       *
 *  Certificate Service - Test Utils                                     *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.messages.utils;

/**
 * Test PKI A
 */
public class TestPKIA {
    public static String TEST_ROOT_CA_CERT_PEM =
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIIFszCCA5ugAwIBAgIJAN5tM7zfSgVnMA0GCSqGSIb3DQEBCwUAMF8xGzAZBgNV\n" +
                    "BAMMElRlc3QgUm9vdCBDQSBEVU1NWTERMA8GA1UECwwIU2VjdXJpdHkxHTAbBgNV\n" +
                    "BAoMFENlcnRpZmljYXRlIFNlcnZpY2VzMQ4wDAYDVQQHDAVLaXN0YTAgFw0xOTAx\n" +
                    "MTExMzU3MjBaGA8yMTAxMDMwMjEzNTcyMFowXzEbMBkGA1UEAwwSVGVzdCBSb290\n" +
                    "IENBIERVTU1ZMREwDwYDVQQLDAhTZWN1cml0eTEdMBsGA1UECgwUQ2VydGlmaWNh\n" +
                    "dGUgU2VydmljZXMxDjAMBgNVBAcMBUtpc3RhMIICIjANBgkqhkiG9w0BAQEFAAOC\n" +
                    "Ag8AMIICCgKCAgEA2kRCQv0YgabI7K7/lyPhBBfurWzrYh6VvOlXNzmGR1+0ETUP\n" +
                    "4DhKqmwdX/cltvR6vxZQCDaxuw1gPFZFLBB5VfOXvUQ2nOnKAOTdOi3I8k4ACcwZ\n" +
                    "RHz+xKmj4h8POYMfJgZ49E0VrCoytzsFefkJ3zOQZCTzM1X8ACLUXkK2mSMF3gdz\n" +
                    "pjiPY2WukFpY0cn6qOGoxyFiwv7kc+gzFexFSQDVVwavZGRrhEYVPsn5N+MbDiQA\n" +
                    "NawTEX9Inr6e482vg3uM0JgLoOIL+UQPfY8+Iw5081aTuHdjxT5mY0PBHuyAWVWn\n" +
                    "YH+4wvTLtEEJHfHCGDB6Dqx3kqNGw2tm77An/rNXtTx75W8JfPLWXw170MiHa4eO\n" +
                    "fo/bUezvvUTuiM4VwgBEXFOnaD8xjESVXOrlUNEu+F0eOMjN84wHiYT1JJ1Gfvpo\n" +
                    "yyTUR14gFLbEvQ4YpHBoeTRWkCLqeX328uFBvyt7KlRdH0Vdhgfy36FKhzCzqQ8q\n" +
                    "IA1TPBjX7UsyQX1wTbPIaMOv/KUbXlQ1MEe2II4b5ZUpg/SpQhZ0GOf/ACvzlYWJ\n" +
                    "vCf6kSlNIK52JxerekP0uq8+ULvhm4sd3yQpnPozRNTHnccs6V6RaDJv2vlyywbR\n" +
                    "JUdBzLsBrjrxLxrNiwIUaLYhUnoAK7HSW5H1oFRNZQZmGZgJMkA6E/3KRfMCAwEA\n" +
                    "AaNwMG4wHQYDVR0OBBYEFGfUHJcAz+L3KkTLUOKvWcw8jJMCMAwGA1UdEwQFMAMB\n" +
                    "Af8wCwYDVR0PBAQDAgEGMDIGA1UdHwQrMCkwJ6AloCOGIWh0dHA6Ly90cnVzdC5k\n" +
                    "dW1teS5vcmcvcm9vdGNhLmNybDANBgkqhkiG9w0BAQsFAAOCAgEAteKvnt421OMy\n" +
                    "WqhDWfySIZwtD5KR5ER+M9ecJoOVZRf66hHNXM25fZ6Hpcvu/JP4O/sWcmH/uvy3\n" +
                    "FxENY2ydONxXzcbFy8kSidywm5tGQ2MGF04eDj+ILu62nGLdMNqCcOpnu1GJS9A8\n" +
                    "fKF7twmiIV3+XbR0S8tkF+KKWKlUNhK3o8E4KvIqizXylPm4IXPUbt+ixG4gSlNn\n" +
                    "5bBSyJ2gZXVaURDxGh6O3J2f5nFJ8On1+iNG33t8Ouf5d9rfqsBVG3UyuXtxXLPL\n" +
                    "uF2mLfccKob1PCxgQaap9ErGBsIvfgKqfPjcV2YbaQSMxkKVKjXZWwny0KWMtr5o\n" +
                    "y5lMuwM958UHW5aXLrDsF4kWWmc9E9U/V1c2LzX6++hfg4OdlQumIDGdK9ztthgo\n" +
                    "bkMVsGKq2RF2hf8Or4LxoqzSVO8UXwHeG5tUZzDIREG051jArdCfBaaU/BUkUOPd\n" +
                    "yYxdnbDot4GadKcqWV4YZ3/rlAZetNYhnYOCAzU2oqkSoy0XDsot3VHnNbS295zh\n" +
                    "7KlCSDRhEmKWPFG5z4X+GMJXYMoUTlXaL9qFamxsKo9FpunhcH/R7D0FgehoXttb\n" +
                    "tBTGlbeaxrmqTeNe0jkBShGGirgLA36AZdYz/jRX3qVY9tUFTeQUEhDQdAQuf0am\n" +
                    "gOmmqV8enq6Z1T5xHkoJrtwCudwtoyk=\n" +
                    "-----END CERTIFICATE-----";

    public static byte[] TEST_ROOT_CA_CERT_BASE64 = getBase64FromPEM(TEST_ROOT_CA_CERT_PEM);

    public static String TEST_ROOT_CA_KEY_PEM =
            "-----BEGIN RSA PRIVATE KEY-----\n" +
                    "MIIJJwIBAAKCAgEA2kRCQv0YgabI7K7/lyPhBBfurWzrYh6VvOlXNzmGR1+0ETUP\n" +
                    "4DhKqmwdX/cltvR6vxZQCDaxuw1gPFZFLBB5VfOXvUQ2nOnKAOTdOi3I8k4ACcwZ\n" +
                    "RHz+xKmj4h8POYMfJgZ49E0VrCoytzsFefkJ3zOQZCTzM1X8ACLUXkK2mSMF3gdz\n" +
                    "pjiPY2WukFpY0cn6qOGoxyFiwv7kc+gzFexFSQDVVwavZGRrhEYVPsn5N+MbDiQA\n" +
                    "NawTEX9Inr6e482vg3uM0JgLoOIL+UQPfY8+Iw5081aTuHdjxT5mY0PBHuyAWVWn\n" +
                    "YH+4wvTLtEEJHfHCGDB6Dqx3kqNGw2tm77An/rNXtTx75W8JfPLWXw170MiHa4eO\n" +
                    "fo/bUezvvUTuiM4VwgBEXFOnaD8xjESVXOrlUNEu+F0eOMjN84wHiYT1JJ1Gfvpo\n" +
                    "yyTUR14gFLbEvQ4YpHBoeTRWkCLqeX328uFBvyt7KlRdH0Vdhgfy36FKhzCzqQ8q\n" +
                    "IA1TPBjX7UsyQX1wTbPIaMOv/KUbXlQ1MEe2II4b5ZUpg/SpQhZ0GOf/ACvzlYWJ\n" +
                    "vCf6kSlNIK52JxerekP0uq8+ULvhm4sd3yQpnPozRNTHnccs6V6RaDJv2vlyywbR\n" +
                    "JUdBzLsBrjrxLxrNiwIUaLYhUnoAK7HSW5H1oFRNZQZmGZgJMkA6E/3KRfMCAwEA\n" +
                    "AQKCAgB+SkCMwiUL35UiXZ9FtFzeIXrYnc0UWN4LEHiGW6J2acmmqy0kb23EbgoR\n" +
                    "HM+VrJ/ZMO/d0MfFk1e7ka80b9PFB80klfODl0JqggH/R76ddMRQ5uc32ZsP75gD\n" +
                    "njUQ8e1z8wrJUFDZ7RCrNFtW1+H+Y7eIOlj9uyK0cXKvl6pPsRQUA/vGkbNlr8/x\n" +
                    "dlUuDdAbJ3agwZCDgzhsWE42wR7VvsWyNQwG6pPLVUG1suegjqd45xu38niWBy/d\n" +
                    "qi4FYV3MlhBEIbWYwTJsaBUOcXNilVrV8aJHec0gs5pKlUmIuw8IoabXDw+4viuf\n" +
                    "gIHl8Zx8oo/9LY2CKzcmm15UEXkRtFjjpr0MnHDX6kTK+hjj8Xi24CTT74aqO1qg\n" +
                    "9wcWFi25OK2ncZmAjngZBgFpFFyDhYNWj9hzIwvBKezUfLCQwEMPLs6WxXxEVy1a\n" +
                    "KeLTYu+GzYlsJVYOy5+wWsh737kV9UgH9Y157kiUg8pzlAhxLq+2m2YnC1U9wuEr\n" +
                    "Zc+I9vIct7o/YVvwPDCBWy4PInBX7C0N8BaJXismqpaYbs57obJapkFm2HrBPn5a\n" +
                    "NgyO97eotqLiR2eDrxDjqnO3GWuzBTyaJ9jYhZ5S6G5J/N3UX3qeYzLd6EFvILY6\n" +
                    "IOCyO41MQB2XLbZBXKB6JRbPdreey8RexxC007x4Pt/QCB8QAQKCAQEA+/MB2iZV\n" +
                    "y7gB7OpGffy1WDCalsS1LIoELLDov8IMdfnL8f2ka4jR60ed6T2CI0mbft1BdJ1G\n" +
                    "yaiYRDCRbFiZ/OasHu06rWJ6dAaVbgmjFhqPg7/xr3Ydhekent1dSrqYNYzHxI4T\n" +
                    "+epEHJqzKbHoUoH9Q8NFyZtaepRCyua8DQM+TXJAWBvPN7AMr0OTXRAqUTiD+OJk\n" +
                    "bBvqnF6q0HKMUE5IkpLbeK0Fzbnv0sNTIn5EvZoerR/F/3SZRN021d1nHxAaFmG4\n" +
                    "C8h2w03Dd1UGA2LnQMvi0ndDiAOLW4SsQcBMcs6GN7ZqGQ6s2J4KztUi1Tqc1lEo\n" +
                    "bLOboLDgSejCQQKCAQEA3caeNx9sCU2rqeoCGbtk0gJKZlbv66vdLwm18LRITGrs\n" +
                    "8GrLkiG0hMl5th1sdJ0PLYwR8ehnw/XM++ra3ghAaczRAiryMcDNbmiqHjFKUkZj\n" +
                    "JgOFsO7JO0Kf0tWYxenzA/ypb+g3LZ7gnuAeAM3yGdA0QLrfjB1bFRcREe+bbkyF\n" +
                    "uEY7PqznDbYVSsDvi9AgY08BfqanfrErsPmKkmzXVx9iYuWBq9XnbwVOUSzaaO0L\n" +
                    "TT4kCkMxXJV/LGL/EA+jDgQP7O7cPKRxsl8r5IfQArT0NPIGbofW9PRzFNGzsmKG\n" +
                    "aIlYloXPaEas03kXbAR6BFhGDuySTOs4CCZfuFDTMwKCAQB74pyZiNoNBtijhvrM\n" +
                    "flMpHxUUZ3rygJbW5tI7YA5CgGahAeg0HB2kRB3Ijz8LXOlBs0e5MJCbHfRpKzyG\n" +
                    "evaU3VPrDRkaIl815/rYFZMEjmDdFqefcEPKEbvFv/Fcim3HfwbHhlkaPO/q5MKO\n" +
                    "EPW8hEBlboJFRMdzmK1TGauD9oFPEYvEB0CYEE/caizuyMEWGOUDn0ZjxkJRS1dQ\n" +
                    "kdKeti+HKwER0HoXE4NyLisVveLNHBhTZlk0aD/pFaEd/fTz2DYLpVcbLCIBnJ4t\n" +
                    "cjg3uA0f1mEcvhoNqjh+8rjEx+qPVS+3+1EmKwogpW2JEFJFaMGvvE5VTOeMVwyi\n" +
                    "KvpBAoIBAGq8yy0QjHi1zycKH1SvIkkJHTHAKdytbNjUvaJJwno1BDB51dxRKIa4\n" +
                    "SUHjS22coc90GLbq+fYQeUXNtOUj54yELRvz+3kCqFy5Nxcs9e4/PjzveQq9AlDp\n" +
                    "Me7RKqQmgvWqRwo7I0NrsgQFLauJczoFQQDeb/UJs+qknWyae55MahdUhfMWWGX6\n" +
                    "+qhtz1zlIJFrVvbT0s1hC/wzPgRXKhUeX8XlW9GOM8L1NMpQ4hWZ8NSOUd42lK1Q\n" +
                    "rlJ4mvXp8LowLlIEbC8rniURNRjaXLzQxrAsw/eynTxr4m9kti3myXXKlL5tTHON\n" +
                    "gGSPZTxxsyAgNCe+qHMoymDxxyP4ko0CggEAcY0vdXFimmYYPXLvKD+RcAmRZ5Ip\n" +
                    "qZRVR9Hlt5D9EjOW3pb+ikmspzzM6YatMaZUXCOfdh6XU7rIrzabb1ERMIrmulhu\n" +
                    "7YVRRxEBMS9RYkqyblcml2vFq0Ef4Q7d+35c3k9VqljobGo0kfM15257x6tLPhDY\n" +
                    "oH4K+kpSBkUAeB+Rs/h/SLW74ZOXCdmjn1LLeEWjSTQSvC8xBEEfuBdT7Q80vpF4\n" +
                    "Ok0zqeXADrwFYJs8+GzG4MUlD0fOGWjhRBhU2PbWRalyVHFINfPeD+rJoKwhfm17\n" +
                    "eju0ipE3sOBeAM+Y0P2SvhY4naIxLwnsWVoGk0rj48Q/sPOEUPSHcMlIgA==\n" +
                    "-----END RSA PRIVATE KEY-----";

    public static byte[] TEST_ROOT_CA_KEY_BASE64 = getBase64FromPEM(TEST_ROOT_CA_KEY_PEM);

    public static String TEST_POLICY_CA_CERT_PEM =
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIIFrTCCA5WgAwIBAgIBATANBgkqhkiG9w0BAQsFADBfMRswGQYDVQQDDBJUZXN0\n" +
                    "IFJvb3QgQ0EgRFVNTVkxETAPBgNVBAsMCFNlY3VyaXR5MR0wGwYDVQQKDBRDZXJ0\n" +
                    "aWZpY2F0ZSBTZXJ2aWNlczEOMAwGA1UEBwwFS2lzdGEwIBcNMTkwMTExMTM1NzIw\n" +
                    "WhgPMjA3MzEwMTQxMzU3MjBaMGExHTAbBgNVBAMMFFRlc3QgUG9saWN5IENBIERV\n" +
                    "TU1ZMQ4wDAYDVQQHDAVLaXN0YTEdMBsGA1UECgwUQ2VydGlmaWNhdGUgU2Vydmlj\n" +
                    "ZXMxETAPBgNVBAsMCFNlY3VyaXR5MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC\n" +
                    "CgKCAgEAu0IN5fycCEIln/MxE+5nhzukdtysSMy/CtQtCh/0++BQGC6Yx3bpU8F2\n" +
                    "wMvIUS1TJIRyxGPmk3ehVoSeHYJ0eXLLDFnoOEYw3tLLGJVTOGMKoQvWjz1TVXP3\n" +
                    "042IIeBWA7AERuuGQV9i5l6MFHlp3EqBn9G7hMrTmo1ra4Gui2Y4WmKKV4XCQVvK\n" +
                    "oIUxIklsllpMmQ6jKAeln7zmoNZDKp6/QLTrzUoR2/iVwK6972YFTyXOj0QdzeQZ\n" +
                    "adLjCIOSVOYZi+yPN2Kre+BSckovyO0a3BxDgVkwlTMUJuMsQ/709zaub6vLqFt8\n" +
                    "NyhHGqZG+IqB1LJFPZJcd9EsO0s6Cd4rXDar2QXbm/QNYDBTQGUk88K3t3JT8UwU\n" +
                    "j+gVHKyMnJ4sZHRkI6pztslSaFkjravaIoOAn6kkiA0rdmARKzAjnMeL5njVkmvP\n" +
                    "L7DzqsNLS9sab/JEw1rOaDEu1enOZYKfs2rfeaIrMiD2iBRqmaeeEVOcJrREvcfc\n" +
                    "pSVhBoVVntb0THc3diKaU3f8yUj3JtUa0/ePZFWezXOrye0Icb3S5kV7N89bQF0P\n" +
                    "CFsK23j9q3ufKb7jqbl3DyIwYBRwxF34wA09UKXdkz3lAtd0ro048F26T9sEjTs7\n" +
                    "JPnmmvBmC+9MeAaYi6Vpmke1A7FVGeJPRorfCu7gLxaY9jiTiC0CAwEAAaNwMG4w\n" +
                    "HQYDVR0OBBYEFO4eInGKmY9PItvL0bQDAZzVTKVqMAwGA1UdEwQFMAMBAf8wCwYD\n" +
                    "VR0PBAQDAgEGMDIGA1UdHwQrMCkwJ6AloCOGIWh0dHA6Ly90cnVzdC5kdW1teS5v\n" +
                    "cmcvcm9vdGNhLmNybDANBgkqhkiG9w0BAQsFAAOCAgEAG/4IrKkWmyg0m3AYN/FH\n" +
                    "wkp5nIPxCOx433TH29WJlUKv/tQh7jvrjTrQgqURItklyPDN8n44IHsU2/Msejb9\n" +
                    "JaaCMadnK9c9xNWYF7hGIKeNIuU/+2PHIxuba5Vwk1yvzHf3dOBggGghI9/VKQXy\n" +
                    "ibpffmA38xvVpM2LQJ6MORuF0SpkYYmB9mOpPK2PIXy2vcF6MzYty24cjG6xz5W5\n" +
                    "U5Nn1LeeREPz/scPG5XK6irXnxz/v+AZxPLklNZVN7382Bx//05sek/hssmVF5xy\n" +
                    "TzYVDqb/UuYGuFv4BLNoYf1iIEnNoOi0frkSu2hQAd8106d8nsvv66tkZfWWd5gg\n" +
                    "Pyl8B6Uu+z8LXQnVoL4ym1qFzS0r+5o3lN703KJ3E/dIV8LNkYNF8PM2iXoN1UnZ\n" +
                    "yy3MV6t7p4CX+zUZw03Og8y+9XFjx8zLrstcuggakY5GQnybvW+/XPmA+5zASJmA\n" +
                    "xeKrxD+7yyufD8F5qGhLsnbcwlKAJo5asw2Ow4NGlFYKbKbbvUpneJNAbqeKXxdO\n" +
                    "nqL0HHM2gwTYZp2gk0O5OVVdBt0be/P573fb7+wII6Pf/UKTCRLH7idG+oHsTlQF\n" +
                    "ipb3ZPzx+4GUvOBYRGdSSG3+luvmWn+zPKAsapdwXmOeuoB8DZ0CSjFbeEOjUwH8\n" +
                    "wNnRwLj9jLVbAm2CDCI9E+4=\n" +
                    "-----END CERTIFICATE-----";

    public static byte[] TEST_POLICY_CA_CERT_BASE64 = getBase64FromPEM(TEST_POLICY_CA_CERT_PEM);

    public static String TEST_POLICY_CA_KEY_PEM =
            "-----BEGIN RSA PRIVATE KEY-----\n" +
                    "MIIJKQIBAAKCAgEAu0IN5fycCEIln/MxE+5nhzukdtysSMy/CtQtCh/0++BQGC6Y\n" +
                    "x3bpU8F2wMvIUS1TJIRyxGPmk3ehVoSeHYJ0eXLLDFnoOEYw3tLLGJVTOGMKoQvW\n" +
                    "jz1TVXP3042IIeBWA7AERuuGQV9i5l6MFHlp3EqBn9G7hMrTmo1ra4Gui2Y4WmKK\n" +
                    "V4XCQVvKoIUxIklsllpMmQ6jKAeln7zmoNZDKp6/QLTrzUoR2/iVwK6972YFTyXO\n" +
                    "j0QdzeQZadLjCIOSVOYZi+yPN2Kre+BSckovyO0a3BxDgVkwlTMUJuMsQ/709zau\n" +
                    "b6vLqFt8NyhHGqZG+IqB1LJFPZJcd9EsO0s6Cd4rXDar2QXbm/QNYDBTQGUk88K3\n" +
                    "t3JT8UwUj+gVHKyMnJ4sZHRkI6pztslSaFkjravaIoOAn6kkiA0rdmARKzAjnMeL\n" +
                    "5njVkmvPL7DzqsNLS9sab/JEw1rOaDEu1enOZYKfs2rfeaIrMiD2iBRqmaeeEVOc\n" +
                    "JrREvcfcpSVhBoVVntb0THc3diKaU3f8yUj3JtUa0/ePZFWezXOrye0Icb3S5kV7\n" +
                    "N89bQF0PCFsK23j9q3ufKb7jqbl3DyIwYBRwxF34wA09UKXdkz3lAtd0ro048F26\n" +
                    "T9sEjTs7JPnmmvBmC+9MeAaYi6Vpmke1A7FVGeJPRorfCu7gLxaY9jiTiC0CAwEA\n" +
                    "AQKCAgAlteGypTKO/zMwiPsjNmmm9D3kqgAQERuQBLalSVY+uyemFwwxbyMB+P3/\n" +
                    "SYqnvmb1/a5XGn8+x2K4V7C35KOsKY/2hsybOJdy6CR6aOf/fQKQ+B9XbVQw60/H\n" +
                    "TMNTfygTSgkydw/sblcuaW/wV5sX//EmzEflMCt4/m3Zkp4h+I30tc+CXK+IFgIy\n" +
                    "XWBNtVem17yBPk9hKlkSWCphzYRtOtbtIwIxr271S5Rs30PkyDjdfZGhjGgsJHlx\n" +
                    "tESAXG7FpikS4qrczoQWSFCSL5p77jPwi8iUbe+4vDactjcd4mRWvK5YUtKKrxHO\n" +
                    "0c+v8DhuqQYIXXZQNf9lKbysnDOtnIt59L3D8dfFUmHgC1XRR/iREMO7tOLZzzwE\n" +
                    "a6gm3dahJAlPwZBAiz0K0B1w0s53gmVmMkCZZfpHptYMeP6kgx8NjDPyQd0G4dfR\n" +
                    "wKA1MTCV/l0cwQfgJoE+PA4QnKGraFv91PaOIYF+U5bulzSC/iPNRUSVaxXcPsLp\n" +
                    "S9HsQyNkk9l3/Inf4mkwrls5SCfCYi1zSM6wE1VbfPxNezjOsIntOqeFKwSmrHBm\n" +
                    "Ub21E+cqvpN8aE0Q0aamLrXG4RkjsWiwQEdOFE+I4Vppuxz62B9TqygLyag3OpDn\n" +
                    "Fs4mr1il4yuL4wh8fXXJTvFYqJVqt5C0BV/+WlBtl9Xag+fkgQKCAQEA7pLKquuD\n" +
                    "F6NQ5qCs3YGN6fkuzs00517CNcKSt4SV06LfXqaSPBDbuq1YQ0tcR7rJAsw9r9dJ\n" +
                    "bBOzupJb9OZosp29NywQLuOqyGdTEvkhJrd0g8zX3oJrZFmkopw0VJJIVWWX6HzI\n" +
                    "IYPeWWE7OlVaCs/P6Loiktt6GNlNp5Hb4CO/qruYeNFflvjNqKFqBBgYADqxa9U7\n" +
                    "kgRCGsggQkGnySWpIPL5XdKNflVn0AQuyxQq/qsEjMVGZAPtEsqKtoiu/V7ohiib\n" +
                    "lrQh1RnwXuawLeW3xs7PL3eayYNk0iKHcqVcnh20eEWM+mKfgDvHnr7r9LB0pSht\n" +
                    "oX7vlXO8ucRckQKCAQEAyO+wibNdgL/a0bKjKW3Kk39jeiCAb5jrPDmiG7ihHGKa\n" +
                    "Aq9zbg30WJCZn265gpW7j6Bx9xqBSdXK38Y71q6DTMSDIgQUtjGDG1enYijScG88\n" +
                    "V2/TxysGaS5WwQmjMuMezjGljsrBfAFyyyqnFWCVBhOXZwuNCkPrQredf/8xEIFJ\n" +
                    "wP6hzKEL3yIQY9x8GtZlf35iltyNWxqz9SeU4gNi7qbXpZ+P+j8m15rjQ/6DD6rq\n" +
                    "Pq9sJ1ghVOq8yDZHwKzUgOijfImf7JC6SRzKITdUR3auvvXreZ95KOY7cpM0tVto\n" +
                    "wTrixhBHXl2NZ8uj7MLiJRtRLZkPFBD8Tv7tqIEv3QKCAQBXiMiPueXZkHSoih+j\n" +
                    "DlvxkxoXird0hRIhA4ktiJooksP+SIOzQkQ81ElkN4xeTSxfuGyRzh4EZ540QGs5\n" +
                    "Cik0EChSy/oMGkCZUz/p4DrHp9w6V7iEzbl1kmaTu1iAB0Q/AQ2hodcUZPv6M3C1\n" +
                    "0Ic/HEyeiV0SITFFWMXjS+Mu9C7pB/fDrJ60GAnta3wokGaN/vsGI7C9vI48oV0k\n" +
                    "sk5LwWOy0TOptw1vYwq6Ci7ZGEdGNZ1vwRo4rDAaCvKmUrRSBrauMswTmXgoZmIJ\n" +
                    "j/7oeDbb3RmrwuiqM2mUqFKmQAIhiaij0HEPlYwMUuLFXivZFb1Ws+S1sotZfKOs\n" +
                    "TV3hAoIBAQCsdMvX45IExqVQBTn0fL65CUSftPWG0oBTGEQB9tyQODBmzZ8Mff2R\n" +
                    "Zcn0BFxDr69i/hnSM3VzoYKVvNXu06jtYlwJ/eao2KXl+b03ikHTLiVkBh6Fem/u\n" +
                    "Jk9fLp5bNoNiBUpK28pkW/niVaFBv7snk/kF/+v1O4XXpTAQgz3hJJXghqrnrfE6\n" +
                    "eUoH61y4y/ohCqAjSvgnkSuS5X3q3W0z1w6On/w6k6kKs20LFo32DIMvefAhdIpn\n" +
                    "D3EnhS7gN3XLjd+DK7uOlkjMJ2F0UMCM9VfVncuUf0LFz5SGKcG7RdEKxzeLNr2K\n" +
                    "SFDtHOJ8emcN4fwyXoOKfWmPg00GqpohAoIBAQDWT6UWmSTO4YEyuvsh9Q/tuEpM\n" +
                    "LzL3LQWZzgVliDynzuNbANOzavs94JEJrfB9dLmrNUS3OdwndcirGjarvaDOEBRU\n" +
                    "sriTB81YfWaS3kv/1Ah6L+gHRi33e4z0KYAa/W1+SIrkj6+RPT/9l/A6ASwsJLF2\n" +
                    "qlUEkQ/5Si3PKfrDOrLmxlVO1KqOYRaZC9gdXv2P6HVmnJCvFX4H7uP6zNbIV2SD\n" +
                    "kxD0rYf51rI7h6rB7KaMZ9t6xfPPIMpPOzF0HqhO+AFIiE5gdMtULPDGbNhHqjuJ\n" +
                    "FMT0pkayg5wKYorMdku5Itr8q9h2TmA5oPA42i4Dv8HlMPA0v4+DGjm27yzs\n" +
                    "-----END RSA PRIVATE KEY-----";

    public static byte[] TEST_POLICY_CA_KEY_BASE64 = getBase64FromPEM(TEST_POLICY_CA_KEY_PEM);

    public static String TEST_SERVER_CA_CERT_PEM =
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIIFsTCCA5mgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBhMR0wGwYDVQQDDBRUZXN0\n" +
                    "IFBvbGljeSBDQSBEVU1NWTEOMAwGA1UEBwwFS2lzdGExHTAbBgNVBAoMFENlcnRp\n" +
                    "ZmljYXRlIFNlcnZpY2VzMREwDwYDVQQLDAhTZWN1cml0eTAgFw0xOTAxMTExMzU3\n" +
                    "MjFaGA8yMDczMTAxNDEzNTcyMVowYTEdMBsGA1UEAwwUVGVzdCBTZXJ2ZXIgQ0Eg\n" +
                    "RFVNTVkxDjAMBgNVBAcMBUtpc3RhMR0wGwYDVQQKDBRDZXJ0aWZpY2F0ZSBTZXJ2\n" +
                    "aWNlczERMA8GA1UECwwIU2VjdXJpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw\n" +
                    "ggIKAoICAQDoS05B4/FSUCZDPsXJBnZEj8NiGFaQoI/+Cge5I58xZEYikUXoJOL/\n" +
                    "y56L8Z4XJheZT90kE2iB5jIwxbq75KZygwLbS9A+qitLqjVHW/h99U3mVTdSfU/h\n" +
                    "X1MihyaE6JZb7LhIfD1MPDF6HsCDJ3A28yqCArsD4J8weWwFFdbRn//bl1L0GMtg\n" +
                    "SVTTb2x3qZ2GZzleRfEe37InBTRuF5VJnVby9vzYu3gw1YYk5g2V23DmFpZzNEQc\n" +
                    "pDDVu+WFU0Bh9lY+txK00A2/OlxgAD3j2qrwRwXogDW6SPRbyL/pj5z8Jq38T4ul\n" +
                    "o0+DQE7fmLx28qklysPJ03Pv7YQHzxu+Cm9BwHr0lQbd1OSD3hG1viXgz6ZaiZJC\n" +
                    "IYFlEU5lfQE42tbqcEw4ulqu8Mn2BLI+GUE0fsvpumpsmjBTGXs7yxn72mC2XG4z\n" +
                    "bMAsVtxocfCX5/RopzPq4ePUlKtmy7N8sFmq0S4JtrP8eFcSsC4BDPyR99p9oFzK\n" +
                    "l31g7S6CMfadTtcqSh5IoXi+ZbiaQpgw1CtVxCUC5BMZOTEr1aHS3j2GVSLiJwJN\n" +
                    "1cGcsxrW/uzCYaCYxGUNlFVOUuCp0Tox69gP7jtbLdO+Gcw8IdbaJ3qu+dIE38dl\n" +
                    "izaL5Ax3XPYtKp5QRnQnsOIPYINx4PiOmXtfOqeccidhLc6lqeFn2QIDAQABo3Iw\n" +
                    "cDAdBgNVHQ4EFgQU+s4BMnKRUSBQCZG2k0IKUAxQncswDAYDVR0TBAUwAwEB/zAL\n" +
                    "BgNVHQ8EBAMCAQYwNAYDVR0fBC0wKzApoCegJYYjaHR0cDovL3RydXN0LmR1bW15\n" +
                    "Lm9yZy9wb2xpY3ljYS5jcmwwDQYJKoZIhvcNAQELBQADggIBAH87jJUqetGr5b55\n" +
                    "hYVDKsfGMbhmhvE+ItGzAk4JvzcmNIh9yhEFnRD5WmZBpsHcipu0Jr+moP7a5jYX\n" +
                    "Hie9ZoKLB5tJLu4beDnKwTl24286IhzmvF3yZjbbFYzErp4/j6tq3Yw2CgC9ioGE\n" +
                    "QvFA3wZlmHY77Mei4xZPpVVVf7ABM3nwdGXfAIaFCI1KE9tE+pGf4fBl+45g12+E\n" +
                    "kXOeJVl8P57yWC/dzNGUy2v1ivS9wKgZeyNwXNe5I7J1HDqLelVyhM6dxyq02SMz\n" +
                    "0KmSK0p0eh+vOwRQSDGB+NrF27LJ+yn3z3vXJqdrYBYfsnN7Simuy8bskFdK8h61\n" +
                    "H+EnpIbzyULeRoATqipNL0MIPVAQ6pYOlNiDWMvDBxrz6fnBVOLMrF9PdB89FaBh\n" +
                    "Lnn5ieCdrMxUhubGWA3hRbDLhkBsMRXrjmHt9GmlJ3uzkCZ7QaFMdbe8TNrqh/YC\n" +
                    "NB/eHRzWh7R2Mm2pivCbtw1jEqZ9NKfjPI0d6ca9s4Dk/H4h/hZIbq3Vqaa0+G7w\n" +
                    "HVFgUBmwQnuqzX9zyYakbd/ioT0niGAFDKODU0oKVQVYFFUXT25cXNrSe+JDA2RT\n" +
                    "fwUbaQazjWeAH5dxMiW1jlsTTm/eb3ULkqGUZU0QlPIObr8omGLnGZO7htEJaLUD\n" +
                    "U8rWEXSyDaXrKoeVFnkinafWYVK7\n" +
                    "-----END CERTIFICATE-----";

    public static byte[] TEST_SERVER_CA_CERT_BASE64 = getBase64FromPEM(TEST_SERVER_CA_CERT_PEM);

    public static String TEST_SERVER_CA_KEY_PEM =
            "-----BEGIN RSA PRIVATE KEY-----\n" +
                    "MIIJKQIBAAKCAgEA6EtOQePxUlAmQz7FyQZ2RI/DYhhWkKCP/goHuSOfMWRGIpFF\n" +
                    "6CTi/8uei/GeFyYXmU/dJBNogeYyMMW6u+SmcoMC20vQPqorS6o1R1v4ffVN5lU3\n" +
                    "Un1P4V9TIocmhOiWW+y4SHw9TDwxeh7AgydwNvMqggK7A+CfMHlsBRXW0Z//25dS\n" +
                    "9BjLYElU029sd6mdhmc5XkXxHt+yJwU0bheVSZ1W8vb82Lt4MNWGJOYNldtw5haW\n" +
                    "czREHKQw1bvlhVNAYfZWPrcStNANvzpcYAA949qq8EcF6IA1ukj0W8i/6Y+c/Cat\n" +
                    "/E+LpaNPg0BO35i8dvKpJcrDydNz7+2EB88bvgpvQcB69JUG3dTkg94Rtb4l4M+m\n" +
                    "WomSQiGBZRFOZX0BONrW6nBMOLparvDJ9gSyPhlBNH7L6bpqbJowUxl7O8sZ+9pg\n" +
                    "tlxuM2zALFbcaHHwl+f0aKcz6uHj1JSrZsuzfLBZqtEuCbaz/HhXErAuAQz8kffa\n" +
                    "faBcypd9YO0ugjH2nU7XKkoeSKF4vmW4mkKYMNQrVcQlAuQTGTkxK9Wh0t49hlUi\n" +
                    "4icCTdXBnLMa1v7swmGgmMRlDZRVTlLgqdE6MevYD+47Wy3TvhnMPCHW2id6rvnS\n" +
                    "BN/HZYs2i+QMd1z2LSqeUEZ0J7DiD2CDceD4jpl7XzqnnHInYS3OpanhZ9kCAwEA\n" +
                    "AQKCAgEArSML1iKeSJrCmhZcdsPhPKLmnuPDCZMTH+a78OszCS5S9ArRTwDHTJ6o\n" +
                    "smfJTDmxFy0mh3AL0d4QhLerwcXfpbQuWeM8+Kf/EytvAJv1L3S5tjbHwCz0b+eL\n" +
                    "4E1ZkXCGOUfL5wLq8TpgKkRnepnXkq1VfoeoenBeVlP6BiRL8/xMSJCWXKdqVn7x\n" +
                    "wZHoB5ydc4LWiISa/kb+0wSXGoNrWu3x06/xr1yzbbqIfFIXyB1CHcyyIHXRWoOq\n" +
                    "fnPI08HEV/+yMpZjU+9Kf8Bw/4DOoFjoVaSqK6v737fmoc6T8/J9sJbn0Qo87J03\n" +
                    "c31oDFIcDpA5MJjbqz92x1qBsQxWALjV+JKH8LSVkYt2iNBSyLP/m0RZ4qHLETl1\n" +
                    "QDOtKnO8vfc276vV4ve1iwSPbnOEF7l0sQFCQRIAkcmcCqsOf6uAr4uYOX5D3W6w\n" +
                    "wmjFCb6MeEOcKfYAml5TIQ2ln79zgqjSEEEM+c/3V93XmtRnlrljtrRqSvl/4pdF\n" +
                    "A6wSVb7e7nUK2fkjnA/NAjesvJRXoyg5q8RFMLNPsS4dcKvaor0Q8EZk1QpaVHQP\n" +
                    "Pkxci6Qy+r5WuxfGJ6Xq7B5DcAQQltMVMpeB/v9oKNCkX1Tj8mG5+utNzp5F56ct\n" +
                    "2AezAH0x/GWl4LHZpxQ5SKsZPxgSinRUlOVdMYlND64ek6QHcTECggEBAPgKvlyZ\n" +
                    "13EDm5q6kekgmSHXGwK2+ByGILdWeJAnt/7fvzjZOWVBpsNL6ZMBam/J1uIQEOey\n" +
                    "O6Y3ikJ3kSwK729WSVIKKiX4DKAccppdlws+jy/4Yzl/QLk+vzY+yuIh9g6pfAGP\n" +
                    "+7eockU5vWFVx3C5/u+HX4+TgNJewpEeHiOoFx5H7kovCcZf8+3opZgK7/VWMteT\n" +
                    "dBU5U5B7BoIlbpgziFM7VS5tevzi1daJ6P9+Zvjq5rgMQVLnEN6lQZPuWSbxT0xc\n" +
                    "cvsOcckTKnDeV2F2hDSKJTJZdIboCTF1iz/y+aQTEDmgNPPrqlW0Yys8IUGxv3sP\n" +
                    "i2Od0vIc5Y7Zb40CggEBAO+/OEU2YZwUSnHXns+32ZzV3WEdPJ7A0xkOxumH/+ve\n" +
                    "NIA627HEAiMewHMrQF1+UQnl94/kjT5dAuB/mBWBDgIMtR1mT83Y0pzU26cAE2Fj\n" +
                    "/P0+zsKkK3Yk3S7NY8r8mek01BdaXqiXVHw00GEAgsSAlWlDx9lwOCjwYPvIxTGs\n" +
                    "eFKQ1943ktFCZzaQXfsTjDQEr83GB4igXHiKIQWW6EV0KN7icZzf+9V1w5ExZ5Tp\n" +
                    "p1jqpD8VEBfDSdep83h3s+rMQaSJBcKGyLaZUfVgzsHSWsfVoPcI1dZaLkpyx8he\n" +
                    "xt/EnrpBpm6UD6VPRMniQLprl2e/EHjzIfjPKHlZsH0CggEAUo6Y349g0r/FqdFR\n" +
                    "QUvVTBshZVzq5euKthr00940coOcTNqYLOiWDciVfJVrDLwcZm+8gLGlAuTXgtnz\n" +
                    "GrqlCOSqUMELWEngQeZWCqT94gM3e1rsA7YkH8QPtold07hEAotMt+Rpfq51Ii9e\n" +
                    "pif70rxFawoet1X7+YkKr2xb0bhfwXdli5FuanWDZfsaKqnxRjIjh/cPGwVSl/Mq\n" +
                    "rmSxE72LMVC9QE+2MLd7PwX15Bv5P/5HPpjtoR9BUSml0wvw5nJI13yp1H/xRWC4\n" +
                    "roqCgPEGfcpBKSn3C/PtI2YhK+6+QmsJ6nQ1S75zmkUJANnpo8j6l4YL+eMM1ALk\n" +
                    "MRCT/QKCAQAlRfhsokjIqEruqhQxvSajAIj7iT0cfWQUeDyqoA9Ez3YgHYZ8e7nN\n" +
                    "VgGbpjTKlFHrFQrJH0JqWLGSz6OIbFkOLoWV/YsYuMX9xgYkT5mzwYTapoIktrtf\n" +
                    "EdolZZ9HNsCDBkiXHOCsm2JyMQ/YlOi/vjH8fKI8hvrkOoMJgixOTb8jLwuwq7ky\n" +
                    "uX0seYNy/pYEnFnsxwXy0uOtheQeZ1jTO30DMfdx6UzQ4g82qpStDSqMY2aHvDGV\n" +
                    "UDJRykVlDE83iOwHtZnkpWndIbchTBy4+4hLm0X8Qi5ktf6Oaovu9fU7Yuk+kehb\n" +
                    "Nr+79rf+HyPrF8EhSw43j61Pbn2faDdNAoIBAQDPxvEFKBzhIJp+vGlKEBjd5piy\n" +
                    "YSZT+qkXq7DOOAF7Li5Qj953aq8nyc/XP6haM+snJQheijWlhdnl3hQBbELw8ilu\n" +
                    "Q+AhEteOfcwW4A3sIgvVkeq8IyrUeyNBMpSuxPs+d0oHuCppBg/WAXCKwSX4DGYu\n" +
                    "hfA31Ff0RdtxD6Ig8HC1I0j3WQscNFD1yxLMAN9LSLx+cp6PWQm4iAUDymvXF7Hz\n" +
                    "vqt1EtKlPFzgvH/+anQniLOlkuSNRRnC60FV8HLZU7GVKEuw2U65s862K/JjFR6h\n" +
                    "DHg+OyJayP5L0AV0uE4MskJx077vJqNjpUHS/9jIymHxjnFYZUY8Yvyu6btT\n" +
                    "-----END RSA PRIVATE KEY-----";

    public static byte[] TEST_SERVER_CA_KEY_BASE64 = getBase64FromPEM(TEST_SERVER_CA_KEY_PEM);

    public static String TEST_SERVER_CERT_PEM =
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIIE6TCCAtGgAwIBAgIBBDANBgkqhkiG9w0BAQsFADBhMR0wGwYDVQQDDBRUZXN0\n" +
                    "IFNlcnZlciBDQSBEVU1NWTEOMAwGA1UEBwwFS2lzdGExHTAbBgNVBAoMFENlcnRp\n" +
                    "ZmljYXRlIFNlcnZpY2VzMREwDwYDVQQLDAhTZWN1cml0eTAeFw0xOTAxMTcwOTI1\n" +
                    "MTdaFw00NjA2MDQwOTI1MTdaMF0xGTAXBgNVBAMMEHNlcnZlci5kdW1teS5vcmcx\n" +
                    "DjAMBgNVBAcMBUtpc3RhMR0wGwYDVQQKDBRDZXJ0aWZpY2F0ZSBTZXJ2aWNlczER\n" +
                    "MA8GA1UECwwIU2VjdXJpdHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\n" +
                    "AQCvWHg5EUV367GvoP/8ekBMbijRmyEbjZN9PxTDzVVeOCRU9OL/eqm2aLvvvplf\n" +
                    "yBP1dJPqIIiFAnN/3mmmpiK9ohuW0+RU4b7GYzK2qxhgUcjJm/ELx16rZhD5S8ol\n" +
                    "JgXrQecYTgGGaKdksOpiPETskJ6ZDYj3XCcBOtpP6Kxg1+GJUZVNIdw2+55OPFXi\n" +
                    "emsZ9GepBzSrFo+4tkJMtOptUrwDUsaJnDC5JxJ3XS+vdA6fCSFJND6Uutq+lebA\n" +
                    "i8hfH+QsHG4VpaqwBwnbMYNrNY6PtjsMwU7TyWzcpECO2GXJITsKp1Mf01xruWVL\n" +
                    "wHCLzlTap/rVw3PMY4etRZONAgMBAAGjga8wgawwHQYDVR0OBBYEFCWclGG+YDBj\n" +
                    "C2YyIr2GQNFe7n1bMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAJ\n" +
                    "BgNVHRMEAjAAMAsGA1UdDwQEAwIC/DA0BgNVHR8ELTArMCmgJ6AlhiNodHRwOi8v\n" +
                    "dHJ1c3QuZHVtbXkub3JnL3NlcnZlcmNhLmNybDAbBgNVHSABAf8EETAPMA0GCysG\n" +
                    "AQQBgqgcAgIDMA0GCSqGSIb3DQEBCwUAA4ICAQDkBbw/9l8FiDUCQo8YsjDS7PjG\n" +
                    "VLiu8tUQBc2murH0iNP9ps3nKzcFu/N7nIP2+2XRrLpFyTP/vSkmx4ZKAEQs9Gl+\n" +
                    "oF4msiaUrhbHPLKFARJ8prXtvNZe7JUwxH63EDuFOZqx7OvhZUu5oaVCoyOLVhdm\n" +
                    "t0frLukuIEMwiTsh8IQ1xGZVV7AUFkckXkHKSSYINPeJSLKimLXYw+u2Xfjl+cYu\n" +
                    "ch+0cCM5+67HVTx9sfzfa3NMw+qyX6UzXSJd//7tooneuyAiSBJMzTuxeKv328n7\n" +
                    "k2XmdmHJp0ltIrvp+RIc9te6SLl2/rxXFoCGo4JxBZaHEU62p2gkU/Onp76FrZR7\n" +
                    "E582SdZPsqvUjSbspyOw/1OeoLPiJsevttbaPQF5sGyXtRiTl1epI8NAApoMX966\n" +
                    "uYhk8O+uH2O4xLvX4+/WGHmbLU+B/5nNFNyd66UlXvnBvkkY06YXAWd+99X2EA0y\n" +
                    "LGYiTYJf8SBRxK/gXv6wOR7Zy7VViuLhKHdaRsunvMlMUSnbI9MJQ2D+69DNrWEL\n" +
                    "TNxJOVxYqEacs+Y8e/MbwRmYyUFWGdEqYaoSbpRJPqxpZLtqM0WOq5SzVNaB2T9O\n" +
                    "lleB6DlaeEREo3HaUdenZWeaJWmM6w3PWnOblRuw/TM53elYzITiIJsCYQXlI+TR\n" +
                    "Diqe2mGedupuoV9/9g==\n" +
                    "-----END CERTIFICATE-----";

    public static byte[] TEST_SERVER_CERT_BASE64 = getBase64FromPEM(TEST_SERVER_CERT_PEM);

    public static String TEST_SERVER_KEY_PEM =
            "-----BEGIN RSA PRIVATE KEY-----\n" +
                    "MIIEogIBAAKCAQEAr1h4ORFFd+uxr6D//HpATG4o0ZshG42TfT8Uw81VXjgkVPTi\n" +
                    "/3qptmi7776ZX8gT9XST6iCIhQJzf95ppqYivaIbltPkVOG+xmMytqsYYFHIyZvx\n" +
                    "C8deq2YQ+UvKJSYF60HnGE4BhminZLDqYjxE7JCemQ2I91wnATraT+isYNfhiVGV\n" +
                    "TSHcNvueTjxV4nprGfRnqQc0qxaPuLZCTLTqbVK8A1LGiZwwuScSd10vr3QOnwkh\n" +
                    "STQ+lLravpXmwIvIXx/kLBxuFaWqsAcJ2zGDazWOj7Y7DMFO08ls3KRAjthlySE7\n" +
                    "CqdTH9Nca7llS8Bwi85U2qf61cNzzGOHrUWTjQIDAQABAoIBADgYT23CTr0Mk+2h\n" +
                    "zgMRgRxyaXCU9kSASFzbH2N8fwEDaOwc47njngOTAfyytxJjSa9Oujs+aS5UGGsh\n" +
                    "1h7QK3ELOVRJOVTGW2fQOFsj5Up7H4cP8k9YWrrujiOS0XqM7XvTu4CVA/vh4xtd\n" +
                    "Vb5TlaEwquw/3j90Ja5JC6pgvzTDk/txycIInWDk+xWP0UBGtSOmOSq2i8Fl2eyd\n" +
                    "dPik/R7KS6DpiWLWsF2jgMvbw1BhN+ANv2RWVTU/XN64DAxl5yST6N4yxjiQi4pT\n" +
                    "8UztEDKJmDmQOvmPNquz4XkerRacHPG7lL4P1zOBn1MmeqVM///SKFFbhL11rLr0\n" +
                    "rBRJaWkCgYEA1neQF60i1zwo/GXAPmN/UOST4wtkvz5GyVGhkaSgtWY81wkSOwCa\n" +
                    "v8RZEwSMS/MJ8QIcGIevwiZiZvb6n2Hxgwnwg2wZ/UiXj74JSjNMoEfcdzaxOVzE\n" +
                    "y4eMbKpe/Ga7SXnmPmGxmNJz1nMGLUcRHcVOtth5KDULXddlfR70XXsCgYEA0U1q\n" +
                    "+om4Wo4fb2Ziwf+tZ0y01P8f7OpJ9YEMH589PIcIF30huQal7EaXKyUBZhdAksRY\n" +
                    "XniHLYiXL+PGz6elGD8lGoow7p+ZZgDSHSB6YDNF0GqfBSIgHXpDoPf6HzFauprg\n" +
                    "8VuQcMe1sW42wATJb/jmhgJU2CKIiWjNNkgEUJcCgYBkV+aUHU6q05v9k4Hh7t2X\n" +
                    "tIq49RC7JeEqukXVBeinVuFqXvUno/3DcZOXgU4/DsR8/da1Z27FcP4jXLUgM0wz\n" +
                    "WkgsxTxXtEotV+Wy0NOuPlEZef5rb0soSxBZm1D72PkRxLYEQ+M7NGQ8Vu7x6klI\n" +
                    "25Mbm6b8N+1Mh8YVR5Ff1wKBgBZyvDeUz83+kkaLb6oo9vsuUfLKTi1Fz5riNV+q\n" +
                    "35F/VhHW3OgQW3lk9M+uz2CYu9dB8cxoFu9+R+DeCDO7YkygcSVQjwD44yX6jo6L\n" +
                    "LjTlKua4mMefKlyfAWPhVNVFoNqEw/1++ZXvBYC7NmoP2V8GDgtvcpQf2A8My323\n" +
                    "6aaPAoGAJ9xpuxtoSEI/21qGuL0mj6020ehM+rt4OCRbEN0t2eYYzdmRmEV6VmRM\n" +
                    "W9hmpOHx6O/dlY+OKSm5bPhCus+fDYXywVQNI6N8O3kdlAjo5l7b2YQvReH9WiG0\n" +
                    "RKWPBeMeiknpzCPx0xE6ZXwucLe6IwMZtu2EYlX13zP9TP/wshY=\n" +
                    "-----END RSA PRIVATE KEY-----";

    public static byte[] TEST_SERVER_KEY_BASE64 = getBase64FromPEM(TEST_SERVER_KEY_PEM);

    public static String TEST_SERVICE_CLIENT_CERT_PEM =
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIIE4jCCAsqgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBhMR0wGwYDVQQDDBRUZXN0\n" +
                    "IFNlcnZlciBDQSBEVU1NWTEOMAwGA1UEBwwFS2lzdGExHTAbBgNVBAoMFENlcnRp\n" +
                    "ZmljYXRlIFNlcnZpY2VzMREwDwYDVQQLDAhTZWN1cml0eTAeFw0xOTAxMTExMzU3\n" +
                    "MjFaFw00NjA1MjkxMzU3MjFaMFYxEjAQBgNVBAMMCVJBIENsaWVudDEOMAwGA1UE\n" +
                    "BwwFS2lzdGExHTAbBgNVBAoMFENlcnRpZmljYXRlIFNlcnZpY2VzMREwDwYDVQQL\n" +
                    "DAhTZWN1cml0eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMIyszTA\n" +
                    "akeF+2rDcfcsRmCNy+HMMw08/9pAks3C/WhD8XBVdBdiFpYGjY2hbDlkkGvROTvy\n" +
                    "Ed0NHy6aVDGfQ2nA16Yk53eRi4q5U7qYfKUKckgghBixwYbapsKxZyl6ovrtB82+\n" +
                    "mFjArs08shiB/KiTBx0Al9HGhFbxbmgcREg/bKG6y7na5McuA8Y7g78kWXRnmTuu\n" +
                    "lVZeMsCWxaJadt+iAHAqKKPmo80UfvwhVb2cU52K9ZlVK3+XWbH/Slt6BrfP28Sz\n" +
                    "CPcADQ98aIcILjyU8/nrZZUe/RKE+DZyRUVqna4AOO4xFLh7X2Swl9JE6ivm/isa\n" +
                    "Zozl7F7kpT2AUbUCAwEAAaOBrzCBrDAdBgNVHQ4EFgQUmG3Hy4CMTh+ePtvaas5J\n" +
                    "zmD3DDEwIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAkGA1UdEwQC\n" +
                    "MAAwCwYDVR0PBAQDAgL8MDQGA1UdHwQtMCswKaAnoCWGI2h0dHA6Ly90cnVzdC5k\n" +
                    "dW1teS5vcmcvc2VydmVyY2EuY3JsMBsGA1UdIAEB/wQRMA8wDQYLKwYBBAGCqBwC\n" +
                    "AgMwDQYJKoZIhvcNAQELBQADggIBAA0WrDHBRMMS4wFJiy4ZtZaJor7G9Ochq8dN\n" +
                    "zoHZIDgBWH8J/MISNQtpXV1fZTib0Hi0rd5DxcQojn/X2QpAyocEd+GnsN+I0obN\n" +
                    "CsO5iYlfjZkT5zLRE73Dsu8arncdiYVSNsl9SQFdpMJKuinHvoFErTE/pchjbET1\n" +
                    "9LAeiv41kDRuhaYABw7pKo1h0bT9clBjQmMoZGI2ht16ZHq2MstMsvYXDqtUwEon\n" +
                    "vuF6PQ0XkyjxrfV5I4VoLMbzeNN78YXmUkm3rfBd8C/loT5gpS3arVLLSa7dOe6d\n" +
                    "fRV80d7QqkZUDep+MSmhq4RWBW0TpBFeZX9MmMZqyhXOAGff48Z83W8f7dkrYsJ9\n" +
                    "YISdETF5I8lzGPsBN//HN0oWZQD+pmzwhEk+zfNi+M2qb6o9TlmPBilAlR/O/MvT\n" +
                    "B7g+IOa0iZNRbPFfXrPrihfVuBOcywU42oBCFf5ABOtcTcQx1TYJ2PuV2DObI6D9\n" +
                    "1xTpOVJFNPIvb4xCb2SovECH+zfrLaC7whnqeH711KYhNXVBEypMR7YWU9S1YdCg\n" +
                    "cyiTsDlD2WV43d1JPYeTHJGa+BTR5R63vnYnDzcDf1dWw6OuQ7Bo6DVW0IGubCFT\n" +
                    "tXgQLHkFj9WvsQywALqCAF52y9V9B3dKVyYkYeEmp0NEyTSlLDqcNP3w9QG/SfvN\n" +
                    "/ajoAz8J\n" +
                    "-----END CERTIFICATE-----";

    public static byte[] TEST_SERVICE_CLIENT_CERT_BASE64 = getBase64FromPEM(TEST_SERVICE_CLIENT_CERT_PEM);

    public static String TEST_SERVICE_CLIENT_KEY_PEM =
            "-----BEGIN RSA PRIVATE KEY-----\n" +
                    "MIIEowIBAAKCAQEAwjKzNMBqR4X7asNx9yxGYI3L4cwzDTz/2kCSzcL9aEPxcFV0\n" +
                    "F2IWlgaNjaFsOWSQa9E5O/IR3Q0fLppUMZ9DacDXpiTnd5GLirlTuph8pQpySCCE\n" +
                    "GLHBhtqmwrFnKXqi+u0Hzb6YWMCuzTyyGIH8qJMHHQCX0caEVvFuaBxESD9sobrL\n" +
                    "udrkxy4DxjuDvyRZdGeZO66VVl4ywJbFolp236IAcCooo+ajzRR+/CFVvZxTnYr1\n" +
                    "mVUrf5dZsf9KW3oGt8/bxLMI9wAND3xohwguPJTz+etllR79EoT4NnJFRWqdrgA4\n" +
                    "7jEUuHtfZLCX0kTqK+b+KxpmjOXsXuSlPYBRtQIDAQABAoIBADGWvromtDzlUqkV\n" +
                    "lWF3ldUMAFb9TMABppe1y4btVsYsK1fzCjz6WCghLj5PTRJuwo41k/bhvnwC4MaG\n" +
                    "tB8juxQjIS4U2GJo8QgQgPfx/koqm7odS33+zhtAdDrdECnAXiPTKR35oG9xbHGO\n" +
                    "ITAu6TSmrrdSMnJnzd1hsz60kR8dWHxf+cxpQi/c75+Do5so8P6PvXM8+uC5oVcv\n" +
                    "5w/hkJCa/sWaFTP633ydfYDPwI+IH/sN3HnjI3/8CD4QZBAiagK/m3oxMp66UdDy\n" +
                    "y1Kqskrl/W3/DZ7wnW6qgqvbxGk+skhWYJsgnL75mGcL4m1RsKX5zwVQj/G6o6vA\n" +
                    "RmJAR8ECgYEA+AODoJnXsy805mwOix1U53IRxRjGbBLY3HsSlRzFk68OS5cn/es9\n" +
                    "AigLuDxyVpdOm2KCqMGHPAUCMZ2/c/N/8UmUT0NxRquIHjRjDBAuGB6z5Sy2mryB\n" +
                    "3Q2ghL/b9o9a6kGRXJ8KC001kfnuIsiuqHekQM+M9Ff3Gt6hpiOGrOUCgYEAyHOP\n" +
                    "Q0nxAut2un6McJDaQhcg2p9rkCR5kofD4jP57znia6Qc2SuqmnKNuSUV2ZM9hvxk\n" +
                    "eTV9qio7sdB5BE4l1OtisO5JGsKW3wD3Pn1mGmAkg4kMqH0SPEDrd6I9Jpn9Op7T\n" +
                    "1ru2xaC3VUMqdMY3Rr33rQyAp1RryoESwxj0lJECgYBIYBYoZty4cJ06ZOw1kqC1\n" +
                    "Ted7ogg9f56DcPLySswpldtRGdJU2jIaj/8ji5g+RrdsxumkP52sWTXTrtoxBy0e\n" +
                    "B7/dBaxn2CTH07fXzFz3MvaCeXLsYvhuvsxKEQcqw5jfZbT613qB480vRUVGJ1Q4\n" +
                    "23k2ZJsYrxbwY2m+5v0lNQKBgQCuj3QDNTEdSdBrOCk1He/z/hAuUwZo0FrOsEx1\n" +
                    "gK33FoGHG7PDq7M2LOwef503jHHYS5NzupFkzsKNZu78QNHRSer4CYrAMxUPvteR\n" +
                    "I8L21SL3KTJMyB5JOn/T/wUhyJgtpIL2TSItmHgPWB5w8uzQPj6iBHFFRs9X2m9s\n" +
                    "Vx8nAQKBgFHbRzdbGtylyGUSVL5d7DT1DgKL0dWDY/Ia5UeiPtORWSIMnT3SWh6G\n" +
                    "tmeDZ4oWiHoWD++OnET5KOJxn4PlqCkWXLWv+ddUtN/+HSIWrUn6wbYXNjGSsLae\n" +
                    "twtqG3AjRTHhs0T9iMLrQoVeMO5PWznnPdx9WBcfaPOyBegspRUj\n" +
                    "-----END RSA PRIVATE KEY-----";

    public static byte[] TEST_SERVICE_CLIENT_KEY_BASE64 = getBase64FromPEM(TEST_SERVICE_CLIENT_KEY_PEM);

    public static String TEST_IDP_SIGNER_CERT_PEM =
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIIEvTCCAqWgAwIBAgIBATANBgkqhkiG9w0BAQsFADBaMRowGAYDVQQDDBFUZXN0\n" +
                    "IElkUCBDQSBEVU1NWTEOMAwGA1UEBwwFS2lzdGExHTAbBgNVBAoMFENlcnRpZmlj\n" +
                    "YXRlIFNlcnZpY2VzMQ0wCwYDVQQLDARET0lQMB4XDTE5MDExMTEzNTcyMVoXDTQ2\n" +
                    "MDUyOTEzNTcyMVowWDEYMBYGA1UEAwwPVGVzdCBJZFAgU2lnbmVyMQ4wDAYDVQQH\n" +
                    "DAVLaXN0YTEdMBsGA1UECgwUQ2VydGlmaWNhdGUgU2VydmljZXMxDTALBgNVBAsM\n" +
                    "BERPSVAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCOqXboU2D9rkP\n" +
                    "3A1bC/jzGiUgZcTn6u7lmx8yCmXq5Ak0E67q5cIbQqfuD/ocd3Br0Y9/rqKyVMmG\n" +
                    "IHWaTjW+T6qs8brNxpxP+0CKl/dbpQ1NXtCyiTuoIg/MPoC/qgceM4TOB8z/UrEx\n" +
                    "/xCBBCQVNqfyn8mDcdS40TYo8nTd30B5UTRzF8cgrBaqPyTp3PU9f7P1/0Smd43w\n" +
                    "S775Ewwe7ZIxvuMefVaS7Yw3klmLrMHxJt9XqdZxCyM5do2aaGUjRTmyZgPLI4QQ\n" +
                    "RMyfrDU+K49aYFaLv7Sl0u/bTxagIhva2VLG1nJ/4hM0/+g13ak+7ey9Vann3n+g\n" +
                    "gmoBiIDlAgMBAAGjgY8wgYwwHQYDVR0OBBYEFO2ECqcPCpbcMfm9fw2uDvpvvR0f\n" +
                    "MCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAJBgNVHRMEAjAAMAsG\n" +
                    "A1UdDwQEAwIC/DAxBgNVHR8EKjAoMCagJKAihiBodHRwOi8vdHJ1c3QuZHVtbXku\n" +
                    "b3JnL2lkcGNhLmNybDANBgkqhkiG9w0BAQsFAAOCAgEA0FHcSZ0DoyefGXfEKa1E\n" +
                    "wfKZgHyPSuEI03oQTemsrCQA63D3QKAcglQfy+B8Wlik63B1qbyY0W6mOdES+1t7\n" +
                    "Q+sQGdjUvyXfstInymCMeBN25mstlNoHJKoeFjvxLJaojH636QY2O60Lkfg2g5tF\n" +
                    "91euvyDK8rT3JVim6B/8jHxT1rtYPmV+gxda3246SDb8IctcOq9baY1OaryO9A6u\n" +
                    "WqHVjjz4o3vM+XCR32AaijqFAf8cES1ymXjeru+1XYCaqs4SmLUMQWR1mNiDV0vv\n" +
                    "CZtC09kLaoIgP4r+nNyiDuHlccODkD/KIgRCC3T6ywMh/Zte7u8yyK61IJsBuS46\n" +
                    "uuPwGdWi5z6nZQOUqEtkCstQhNYMdCcHImEkloEBlOMqoKgG/afGRF/OEMY0y3ls\n" +
                    "7ULBTMTZ63zaSiKuOf1/bn3dI9Ykt8IpC7CwtRjIf8s5Y9zBgYhRBIuy2NgsddGI\n" +
                    "GKtHTfYzAmC2ADTqymqZadwHF4Gv91wUeDef3eLWWb8TJHow23VKiD8KWNodDFW0\n" +
                    "SwWh/7ukZRE46cemXgHdnPyOsVBUN5AX1wiyAkyk1epyGyu5JdPBSYq0DMrHhc3N\n" +
                    "YbgREprcdr0Tp9RWPx/wCe537bk/bLLFO0m6h+gZcyOsNjZHKIe/8naj9/jXt1EV\n" +
                    "z1Q5X7RMM02V1oVzjuE7Ksw=\n" +
                    "-----END CERTIFICATE-----";

    public static byte[] TEST_IDP_SIGNER_CERT_BASE64 = getBase64FromPEM(TEST_IDP_SIGNER_CERT_PEM);

    public static String TEST_IDP_SIGNER_KEY_PEM =
            "-----BEGIN RSA PRIVATE KEY-----\n" +
                    "MIIEpQIBAAKCAQEAwjql26FNg/a5D9wNWwv48xolIGXE5+ru5ZsfMgpl6uQJNBOu\n" +
                    "6uXCG0Kn7g/6HHdwa9GPf66islTJhiB1mk41vk+qrPG6zcacT/tAipf3W6UNTV7Q\n" +
                    "sok7qCIPzD6Av6oHHjOEzgfM/1KxMf8QgQQkFTan8p/Jg3HUuNE2KPJ03d9AeVE0\n" +
                    "cxfHIKwWqj8k6dz1PX+z9f9EpneN8Eu++RMMHu2SMb7jHn1Wku2MN5JZi6zB8Sbf\n" +
                    "V6nWcQsjOXaNmmhlI0U5smYDyyOEEETMn6w1PiuPWmBWi7+0pdLv208WoCIb2tlS\n" +
                    "xtZyf+ITNP/oNd2pPu3svVWp595/oIJqAYiA5QIDAQABAoIBAQCnJ/Yp6M5fbeyi\n" +
                    "+4z6+HjOL4gYM72copHrRO86D7zaxFovWWlGe2nsMBd6SIHGEfzMrdPD3TXkKBgv\n" +
                    "uKu9muWh3cpTgM513iIUq3VGUbbuRkQGfD08CeMvtfDGpFwFl3z8vvXiotAIRNB+\n" +
                    "6Lb5cejj4N/1bRLubv7V+CeWYeO2NbUG7OdWPnT2xLHh1PGdkruPf+AF6HWqOiXq\n" +
                    "ks1RmBO4IrSBCOQioKjjWdjRHGwN0gPYLKKKcN9iRQgG8qiAqZ4C0gPqci7201Ds\n" +
                    "tAG0qOj3Fs3IJqGxbNBJx1DB8faaTcObA0/nlOVfGEmKUdTs39yrgGACf78ZdWn9\n" +
                    "5zvPgoVZAoGBAPYVpQRUSxtjjmG7EdHDdTT/iQlTjkSYQeOMgqRkUFs849fUPc8B\n" +
                    "WDQ1lLPhPduCp1LpiirAeSMKrCd+AIn8BPVxat90T+/zWU8RJk4eVnq8FNLp9awV\n" +
                    "Ed9dzetJx0bkUSNqvplbk130akaoqIJ2+7V3Ncgo2Z74Lg+GZNkWQDg/AoGBAMoO\n" +
                    "HZzPtzADZ/o9dZXzTiyHXkpifvaxe1q4fs2sT4/LNvo1uCzDEEH7cNiBXu96YhUI\n" +
                    "WrUVwQvEGvsiG8HToOhKNnqJ8rRU+qM8aE/ltpSEnQuxLyKUUL4hafo9zb5W7ynM\n" +
                    "gtmvplTXlgG2p8ZWkTn2ck932HSYXAblCFyldt3bAoGBAMVOAWsBMt8Y6ZYOaXEo\n" +
                    "KBeAMx2ZMt5ovZt2k2C/VXZx0bTA5XXN/CyQMVQwampPzVy7Bx7UB8xCyFk5u7Dm\n" +
                    "sgshDrFvDpCzKo4sj+vegzQRDRk2oNWCZzwSeAIIu5Bpi2y8L2nCdNvGFlfk7ob8\n" +
                    "Y0DR/fsoVaQSFMw50y4DmyX9AoGAMTGGnCsmWpY5tn9IJZ37JnQ+zLV2W/GSKuBI\n" +
                    "XyLYrBW56OkzUhKb3rStIMk+p+eQAbbq/rOxMIAqYYJIZ8RypJuM8ACuCqG19BA9\n" +
                    "BVbUQQyYf8Q/yZd6oQ/ZkYeClBjuWarlIMLXKEjkyL4D0xI4gXgzFI4FMT33Ceax\n" +
                    "Rn0yl4kCgYEAvJp/HeP1P6DltB21pALgpRhgjcIAh9/PybuF0QryatUtk2UulN2D\n" +
                    "9ypiebQKmIUg+l0HsZ1DcgZi+JoaqRisukILTV9ULjXkqIdjWEYRv1xhLqW32qnj\n" +
                    "zBF62Ef3YYQ6q/awi4kJU7+Ny/HCJ5uU3UejJ6OPlExSDLei5JkIiUU=\n" +
                    "-----END RSA PRIVATE KEY-----";

    public static byte[] TEST_IDP_SIGNER_KEY_BASE64 = getBase64FromPEM(TEST_IDP_SIGNER_KEY_PEM);

    public static String TEST_ROOT_CA_CRL_PEM =
            "-----BEGIN X509 CRL-----\n" +
                    "MIICpzCBkDANBgkqhkiG9w0BAQsFADBfMRswGQYDVQQDDBJUZXN0IFJvb3QgQ0Eg\n" +
                    "RFVNTVkxETAPBgNVBAsMCFNlY3VyaXR5MR0wGwYDVQQKDBRDZXJ0aWZpY2F0ZSBT\n" +
                    "ZXJ2aWNlczEOMAwGA1UEBwwFS2lzdGEXDTE5MDExMTEzNTcyMVoYDzIxMDEwMzAy\n" +
                    "MTM1NzIxWjANBgkqhkiG9w0BAQsFAAOCAgEAqUdgOwHqkG/Gd78HOkRIQ/Y93+2A\n" +
                    "JqGdrUgOcpScqBIL4ojLy8ILeoZpt6zrgx9qc3hpQPXxQyxStjGaz0Sh6ZLPpd1k\n" +
                    "fYCBoHldrQ2YmREihKGUMEIxNDtN6Ij78yR6HUvnhy1y3osiEYbdJ5qT8+bzhNN8\n" +
                    "n9yRdKKr+nmprUforeOvJWjn39Gze9mScwRGSFGzehffiPaqlI3cvnBXfm+ZogXM\n" +
                    "FtBYFyEeNkXMo/JfR3Qqc0bQ52DMWilw/XfRGOz2RQ0S0JCPzFmPITJk723Zx+u2\n" +
                    "zMTDPVMhTityLTHAU+UQEd2J1UrvrS2KK7PPwGXu7Qaf8mEVUXdK8Wm5rr5WS1Yk\n" +
                    "kbg+kvx9g3UkFhQxekTGj0YCaJTFw6qnBOMLAcaO/iyd1BFZw8An2K6s8Hp/92Lo\n" +
                    "4Owm9SC+111bffLFa4XfUz+9/1dXRmxk8HloX8IgtMhdJAqQVO2wLRD1aeHH7MaQ\n" +
                    "FzpIy0Yv84KH9TcAIhZzx7QieQX5KUz52LJh/sJQ1GiFnIc2P/f5E7KbSR/LCpr4\n" +
                    "TGMqNeyqWQbVxNE5lAk0YNZw3vQ4BZBP1YsQAOGnyJJdOa9kCerylFUwSLWC6hcO\n" +
                    "KvGZUKeWKx6azHbVuSTrBfohdSdyktxaRy/RyZeiMKmN7Gko/YzND6UJqn/MUnnh\n" +
                    "Zd6I85WpPlPy3G4=\n" +
                    "-----END X509 CRL-----";

    public static byte[] TEST_ROOT_CA_CRL_BASE64 = getBase64FromPEM(TEST_ROOT_CA_CRL_PEM);

    public static String TEST_POLICY_CA_CRL_PEM =
            "-----BEGIN X509 CRL-----\n" +
                    "MIICqTCBkjANBgkqhkiG9w0BAQsFADBhMR0wGwYDVQQDDBRUZXN0IFBvbGljeSBD\n" +
                    "QSBEVU1NWTEOMAwGA1UEBwwFS2lzdGExHTAbBgNVBAoMFENlcnRpZmljYXRlIFNl\n" +
                    "cnZpY2VzMREwDwYDVQQLDAhTZWN1cml0eRcNMTkwMTExMTM1NzIxWhgPMjA3MzEw\n" +
                    "MTQxMzU3MjFaMA0GCSqGSIb3DQEBCwUAA4ICAQBCNbc/U7c/KUnrEd/o9D6AwcQ+\n" +
                    "q7S7L+upmYjTau9w5Bcsx83+BWkWFvTKc/eYLXVhGbmL+h1rX2LLZDqrLX8KwnOF\n" +
                    "k63P9Av3LyIpnfVMqK1fBlidCDStM3jPz0tyj2FN0HAh8f8yo7b45x3hFpSbrIp9\n" +
                    "CfpFy2ykjqg89iThluPL5HT5dmzBe7SVFrtWBpzoKWKYxfWx7Uk7PXM3wAJFHa2R\n" +
                    "rmw5nbHpdh+WtPAD0/Mron8SSDM/FAmRxwReafZ+IguRNE2PlEjj4oJGfliJwDBa\n" +
                    "f1xd0c6DSm1TNkoD4ZMRZ8pXVecYvIpOkiEXgljKnmzkxH0PFH+qbwaTEXnc+8fv\n" +
                    "V8uh1x+DOiHEDgstS8NGaK34Teux3BuL2cugPMEyoZMDdD5i5ZW0Wwhcju6BZtPS\n" +
                    "6qwkZKaPDfIn9syyay0g25slMjiaCPSJu2vSxxIeOSlxeR7PhDWW8oRJ47hF+J0/\n" +
                    "B9k/yMv/KsDcs10oqrKJjSWKTv2qqBPCk//w2nnmY2v491OEhQaZnSLElS5YdCcz\n" +
                    "gvPhxOW7qnSo/yfGvNccVU2K/pmnXOYVh54Jr4zQW7HL6N51hTquR56GUJCwxK/M\n" +
                    "3hh4XBSoDsa141ycmmTQmB4eOLtuiq33+3oiF/1NadGQtjXeCgnDO+kWlGAslp1+\n" +
                    "ac5Gtl4IB0E7K/AW/Q==\n" +
                    "-----END X509 CRL-----";

    public static byte[] TEST_POLICY_CA_CRL_BASE64 = getBase64FromPEM(TEST_POLICY_CA_CRL_PEM);

    public static String TEST_SERVER_CA_CRL_PEM =
            "-----BEGIN X509 CRL-----\n" +
                    "MIICqTCBkjANBgkqhkiG9w0BAQsFADBhMR0wGwYDVQQDDBRUZXN0IFNlcnZlciBD\n" +
                    "QSBEVU1NWTEOMAwGA1UEBwwFS2lzdGExHTAbBgNVBAoMFENlcnRpZmljYXRlIFNl\n" +
                    "cnZpY2VzMREwDwYDVQQLDAhTZWN1cml0eRcNMTkwMTExMTM1NzIxWhgPMjA3MzEw\n" +
                    "MTQxMzU3MjFaMA0GCSqGSIb3DQEBCwUAA4ICAQBCW4zMstXqXrj9CKCkIRAMHyWj\n" +
                    "J5tfyp6LCilCl2AmK7mHWn+eZ/wES/ZzdOVhPyiLBtUfAMd/mNcIWp3uKBOL5ID+\n" +
                    "nYgVv4RaK2mCJYCyazIRcDsHZLQ+N7GFNki5dgKIZjMZ28GO/ioX6oTkz/hpMGdX\n" +
                    "b58eL4tSgRq5eM8xG9B2aYebW1t3jMMiF27rii1qBYUKzotZIMduhFSTJmdcz3L9\n" +
                    "CErYsvSf16TDxmi30dhkscMjC1rxlvYcMfRmeet4irwSLg4gpMQxuxosUPqoX8Li\n" +
                    "C5ANxadgHj3VfNtwv8S1idpb3UJ5oJBRkccBQ1EpZMpb71Y0n5O+N6pyNVjD6Vwx\n" +
                    "ZuR4PHZ6eUrBwO6bVDygU8RiJZ124ux87UuRramK33JfOVFtxHGYcuNAgyceD6+e\n" +
                    "jFIYbuqohTvNyAOUopChpDdMAmbEhO8eR3f8BuIxchSOenr8UgrVfCeWfyESOm+r\n" +
                    "Ix7+Z/nknt0VIq95bTnzGdwJkM1Fgi2RBSAYzZn+XXwk7qU1rH2fV4gSbicPlPZM\n" +
                    "XrPmXNFqZnxNzmSaLUW0pQ9ONnOzDW+hCT1ansgtQRwGVx/euCxk9W8buW+6igKs\n" +
                    "b7kzpLxJusUSyuzfprfwhyIgpTXY3VJRW2NpFWSZ4B7isrNoCWQO3y42DFhdbtp5\n" +
                    "lu/SLZdollUPI9qINg==\n" +
                    "-----END X509 CRL-----";

    public static byte[] TEST_SERVER_CA_CRL_BASE64 = getBase64FromPEM(TEST_SERVER_CA_CRL_PEM);

    public static String TEST_IDP_CA_CRL_PEM =
            "-----BEGIN X509 CRL-----\n" +
                    "MIICojCBizANBgkqhkiG9w0BAQsFADBaMRowGAYDVQQDDBFUZXN0IElkUCBDQSBE\n" +
                    "VU1NWTEOMAwGA1UEBwwFS2lzdGExHTAbBgNVBAoMFENlcnRpZmljYXRlIFNlcnZp\n" +
                    "Y2VzMQ0wCwYDVQQLDARET0lQFw0xOTAxMTExMzU3MjFaGA8yMDczMTAxNDEzNTcy\n" +
                    "MVowDQYJKoZIhvcNAQELBQADggIBAH4EiSreA/BLDUoULDIcRzmw6rIXY8GRGKVD\n" +
                    "bcmHLCK5egi61B5HYGeVFuwkVEgUUzkeB5GlX0PccSdsNPmZGzbLXjWxQJQnyiiY\n" +
                    "Tv5vnmVVVpml64CMMIedyeaNO6Sx9edoKbENLuJiinc7//zuOzkHyfJlp++lr1uv\n" +
                    "R5osXaspVZs8yXduACwaYAfIKhs9urJIwihWlRV5Foyy3bOySQ5QEtVXgvZztcla\n" +
                    "23lDenPCc8bsarj67M5VNa68e9NONMUhw57ECkrUpYRDXNpisEc3C7knG1moPJnx\n" +
                    "JwZ7yyXBCg4ZUvJXQHKMMsabOjfvuk6rEA3qQPrLXq2h12JGgZia9IkXCTB+pcCS\n" +
                    "orkC0WoP8JpVi3/vurI+arWwKpJJA7RhC9GBpMOt4FO7RyYLGJXSaM/P5pVViOvJ\n" +
                    "M2exL5Y0lb7K0hDWsxOmkK8WSjfEYkoSzxQHWRQM3F9mtslCZ5sa8+HaI335mZ/m\n" +
                    "/BH21F+6JM8KNpWfxl1R1HHOPZ3A0JpmPMRd8Te7ZjYC/1Pzv/Hs94whqCyfs7J2\n" +
                    "7dVe8eLoUxUfab4OdhJm2vZgFjLbbEBdXndx/geSRq/b75/w50/zv1Jfplpxx+Y5\n" +
                    "thZ6MqoOf7qHibZ0ReWGWmoBfh0rewLceLp62fBgosAzeV4P7KHG2sZ45UgwXW2I\n" +
                    "9omnAJo4\n" +
                    "-----END X509 CRL-----";

    public static String TEST_OCSP_ROOT_CA_KEY_PEM = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAIvsp4G8qEWFH2Ua\n" +
            "TJwwbgwH2LWs2TR30kw85PRDfb5eSWHf0iZBvMJdp++ox70mpx3iK2nD2dW3VOxQ\n" +
            "tTKFY9VaWg6YUyX9O8daJxSJjJqzLiCx7KvUs+5+gSLpEAbHO5veNzfwVETOUTAP\n" +
            "nEe40/39MjLIjMIzglkc3SVhtOxLAgMBAAECgYBg3wpo62+kEbHWkQqQ54aIlbYW\n" +
            "sP//LyVM2qu34DHh5ezv8cDP85r3BVgKt9LwxR3VtotPwePB7hbBNG799xNRz/2V\n" +
            "9Ar9rVCPFf4nMe43vbcLauIIYeANiZGuiFxYPFZIveD4710a5Z9l1QH/yltx5xes\n" +
            "Auo2Y2YeOXqhlRxwQQJBAMKc/qOPkQOXLjLumUSe27ik38BzLcID4kUCAU0ktCqw\n" +
            "C2Z+4R2j5a2jIWVcLulPEhC+8Lx9tSOVib1kgh2E9GMCQQC4D4p/G0Z6f879CD6x\n" +
            "kVyZz/S3iCTV87xGrmmpCcPQTeCQZp+g73YzSU/6NpdDPBcJ5NSHHWuMqTTvhjT+\n" +
            "6Wj5AkA9FgBLoLW49cw3inMred2n8ICXLNARFR0B4iY8a6ftukJp0qugnSBrx0el\n" +
            "RDEpZHtcLELuN1sTJ04L16+Lyn7XAkEAno3MqXfOe6Hzpabfksj8cwdf8GXYDXI7\n" +
            "4stF+7aMtrkPVHUC13jQYpepzIoQPXvbAMvdhFMEnZP5JMiAiIJ6yQJBAJCdNQ1A\n" +
            "+gUdhoV1fe2eSxy/hAaTWAJxbxEHPaaUILuM7iuaC8HIe2anMjpBiDDUMJQ2lzjS\n" +
            "VwhPCwsklHFDjYY=\n" +
            "-----END RSA PRIVATE KEY-----";
    public static byte[] TEST_OCSP_ROOT_CA_KEY_BASE64 = getBase64FromPEM(TEST_OCSP_ROOT_CA_KEY_PEM);

    public static String TEST_OCSP_ROOT_CA_CERT_PEM = "-----BEGIN CERTIFICATE-----\n" +
            "MIIENTCCAh2gAwIBAgIIYwQ1UUp/p9AwDQYJKoZIhvcNAQELBQAwXzEbMBkGA1UE\n" +
            "AwwSVGVzdCBSb290IENBIERVTU1ZMREwDwYDVQQLDAhTZWN1cml0eTEdMBsGA1UE\n" +
            "CgwUQ2VydGlmaWNhdGUgU2VydmljZXMxDjAMBgNVBAcMBUtpc3RhMB4XDTE5MDEx\n" +
            "NzA5NDE1N1oXDTQ2MDYwNDA5NDE1N1owYzEfMB0GA1UEAwwWT0NTUCBSZXNwb25k\n" +
            "ZXIgUm9vdCBDQTERMA8GA1UECwwIU2VjdXJpdHkxHTAbBgNVBAoMFENlcnRpZmlj\n" +
            "YXRlIFNlcnZpY2VzMQ4wDAYDVQQHDAVLaXN0YTCBnzANBgkqhkiG9w0BAQEFAAOB\n" +
            "jQAwgYkCgYEAi+yngbyoRYUfZRpMnDBuDAfYtazZNHfSTDzk9EN9vl5JYd/SJkG8\n" +
            "wl2n76jHvSanHeIracPZ1bdU7FC1MoVj1VpaDphTJf07x1onFImMmrMuILHsq9Sz\n" +
            "7n6BIukQBsc7m943N/BURM5RMA+cR7jT/f0yMsiMwjOCWRzdJWG07EsCAwEAAaN1\n" +
            "MHMwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUOdybTwSAhKpkeZ3AN4Bo4lrt41Iw\n" +
            "HwYDVR0jBBgwFoAUZ9QclwDP4vcqRMtQ4q9ZzDyMkwIwDgYDVR0PAQH/BAQDAgeA\n" +
            "MBMGA1UdJQQMMAoGCCsGAQUFBwMJMA0GCSqGSIb3DQEBCwUAA4ICAQAmZpAtFs4u\n" +
            "oubkAYt38gqfC5zqQtLRbiqVuLj3X1bWLMYs8epBfYpQqkI3WiJFhTw7c/Ntvo/p\n" +
            "cnbvHCKXsXgqzGHh+PwXnADKKPUX/gsvBapOITZyUPThWhnzqFUbeMX786J/B5az\n" +
            "kZ+c5f8KKgM165M0WRmjfEihYpP4LMNfU8BTMSJAxjm5WPQkV6Aog73U5uSCYcep\n" +
            "JRJvf20X4RwLHOi7Lqnpj39e2ozC0/bj/cf9Ail+8xGva1efSzOBZaCjIcRnQxxR\n" +
            "mNrbdfVCrpmRUnoHSbQRPBIAVuXLR4FWdLUTFxTMix4WaNcOWaSQsGXrLUp8DnwO\n" +
            "x5thkd8esE5f5s2bWAlyvolxc6MvArZ8cvl11wlgBUzN2lyBQcDoXJkTJ6HsYFdc\n" +
            "83rOIxbmnYboE3yVDwVkNdkyoF4HyYc1kiQHBW4unhZXGlLqlmWvLH83TlEH+wLq\n" +
            "KxP5AEa9Zj/PIyQgkuLr4hq5aemuVCl5IbC+PmBgJj+dHEG0qrHmBSsUuW3RyFcS\n" +
            "9R5NHRGCcF3aiC2C5mIR9wpV1Sh0tlah6bIfJY6BrtMo1IN4F0ThEevJHqtJ3K+6\n" +
            "KkwPJRkPLhkf3rsdUh9aqEmBZ4CjEhHfYsjxWHuEPlWXRmuI0uj/z7EKE03eA1J0\n" +
            "Nsx9laYsYS0+wLD+Ibv+sOr8q812uUhVjA==\n" +
            "-----END CERTIFICATE-----";

    public static byte[] TEST_OCSP_ROOT_CA_CERT_BASE64 = getBase64FromPEM(TEST_OCSP_ROOT_CA_CERT_PEM);


    public static String TEST_OCSP_POLICY_CA_KEY_PEM = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAIYptkYQlHQvAAru\n" +
            "VT/wS+J2MpkiB15baKfay/kSk6JdiL3jg0oqBbOMHSz7iqvKyoQ1pfi84tmeq+1B\n" +
            "4y82khdLigDt+ssUAMk9jus7G2xJ95jbjWDNthlI5P+UHRi+m5PhtqGs5YPkc2P/\n" +
            "tPISP/IOxQrFMXp/1v2FqssJW3IxAgMBAAECgYAKS4ceJ0WNCNJDBHjsOB9KmHFX\n" +
            "iOHx3qfQQZznVwKXMgA9OgkoFsNrPLQ8cGz6s8wIiylaRfxOYLumsCijxdc978LZ\n" +
            "HoC7THH32WXGSqK01IVh4BXHgYvog1iSUO/ZbmgQVkW1+UTrj5cVsOqnfp9SAwZG\n" +
            "ia2HjAzxgTcq2HXrRQJBAM8SZ34kMWYdj36Z2niPobpiKcHkuX7EC74t/9eGWKRL\n" +
            "6Jd5mUFheEd3E48Y+bktGvqeD0P+qilgx0k4hPUTc2sCQQCl3RwKZIhp3YJeTu2d\n" +
            "Yr0CNd2XNR7d938l+FO0IVhlkvpuBaLQq0Ar/r5K0gKQ0t8ap0jh3PoZ3DJb+R4J\n" +
            "PzPTAkEAl649jRLp9IkWwX/lnoZny2V4fQUUM51blLWRQMiySbco6zwxXMkPGBpL\n" +
            "g3iiBFjb+FSrjf0PnDu9/w6dpf/XfQJBAJXbLBaHtmhP5hXnIfBs4XA50rdnGzhZ\n" +
            "ANwBfT7mUcOUBAebt/roftZBFxTqob7PhxvBwKuwx5bNyAIpFeYs4FkCQCaxDQO+\n" +
            "91PxtMVXZoACwOtsf0QI0pR62lmVzehZiNPM6MsI+NuXbBokLipRQnktDie1Cz/6\n" +
            "RMnqLiYDSXZEQuQ=\n" +
            "-----END RSA PRIVATE KEY-----";
    public static byte[] TEST_OCSP_POLICY_CA_KEY_BASE64 = getBase64FromPEM(TEST_OCSP_POLICY_CA_KEY_PEM);

    public static String TEST_OCSP_POLICY_CA_CERT_PEM = "-----BEGIN CERTIFICATE-----\n" +
            "MIIEOTCCAiGgAwIBAgIIE1CQwZhyoBwwDQYJKoZIhvcNAQELBQAwYTEdMBsGA1UE\n" +
            "AwwUVGVzdCBQb2xpY3kgQ0EgRFVNTVkxDjAMBgNVBAcMBUtpc3RhMR0wGwYDVQQK\n" +
            "DBRDZXJ0aWZpY2F0ZSBTZXJ2aWNlczERMA8GA1UECwwIU2VjdXJpdHkwHhcNMTkw\n" +
            "MTE3MDk0MTU3WhcNNDYwNjA0MDk0MTU3WjBlMSEwHwYDVQQDDBhPQ1NQIFJlc3Bv\n" +
            "bmRlciBQb2xpY3kgQ0ExETAPBgNVBAsMCFNlY3VyaXR5MR0wGwYDVQQKDBRDZXJ0\n" +
            "aWZpY2F0ZSBTZXJ2aWNlczEOMAwGA1UEBwwFS2lzdGEwgZ8wDQYJKoZIhvcNAQEB\n" +
            "BQADgY0AMIGJAoGBAIYptkYQlHQvAAruVT/wS+J2MpkiB15baKfay/kSk6JdiL3j\n" +
            "g0oqBbOMHSz7iqvKyoQ1pfi84tmeq+1B4y82khdLigDt+ssUAMk9jus7G2xJ95jb\n" +
            "jWDNthlI5P+UHRi+m5PhtqGs5YPkc2P/tPISP/IOxQrFMXp/1v2FqssJW3IxAgMB\n" +
            "AAGjdTBzMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFEZaRlPveb/9Vjn9hPE5K5Xn\n" +
            "IUnAMB8GA1UdIwQYMBaAFO4eInGKmY9PItvL0bQDAZzVTKVqMA4GA1UdDwEB/wQE\n" +
            "AwIHgDATBgNVHSUEDDAKBggrBgEFBQcDCTANBgkqhkiG9w0BAQsFAAOCAgEAJggb\n" +
            "7pWygDoLwgP1ErXjfUz1mOEr/rZuriYMGjF0pQJwhpa5ehQqJfd3tiKEVJuUnrD1\n" +
            "h2atu3iPJVhkfAZNhixBl+2EFnWaC+A1i09+JaF4JGY+ZQPldK8TnSrCJOwXP35b\n" +
            "pKy7+ltpPk7lkZaL+Czoa+CUrM9Ntz92XhdhyWTc/Xu7WAVd/QKKpt6Kgcr1fynE\n" +
            "yuS6N3gfn7BU+UtdRWiKzhlVGbE7v+aAe8uLT2gq88b9kjODssQ1phQiRsMYfz72\n" +
            "fttOaGB+vNQcbdmUfMdrVOW0mtqQvwPsn89f6F+aPO/0d/TPFwjlVU7B4q0nF/EH\n" +
            "whjFSPHXExq3M4Okljwvpiljt8Fw9bJENk1PrcicSqm9PGOsSATqArnd5j4n4mKY\n" +
            "PdhDKYWndqMxywBuyzgvRD6ZkXPjYUXQ5okdL90JRnXurLTWnZmf1G5D6vNDiQ1D\n" +
            "UYjKGQI2WQsTSfx0Nlo65e6/C9loWnW8SdgYiox3zcS8tcoVWdoWHhv9couNMrze\n" +
            "tGYkP3a0HaBgFygLuxFGMR2X6Rh9ryIt9oscy1VOdYeRI7Tb+cLzMfD1gBFmyZhV\n" +
            "/keqi4CR/M42zJtQ5qn8LXBYK4JEHYZn4QIy+Hb5lvc0G7S9APcbwpqwvVZLTzpY\n" +
            "C53zCyryHpJC6JgLHdsFNx6eKSz5e38SWAFkmBc=\n" +
            "-----END CERTIFICATE-----";

    public static byte[] TEST_OCSP_POLICY_CA_CERT_BASE64 = getBase64FromPEM(TEST_OCSP_POLICY_CA_CERT_PEM);

    public static String TEST_OCSP_SERVER_CA_KEY_PEM = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALRFXInRfLNUgYq/\n" +
            "aCN+sZflfrXu/ERoGpQ/0agy7Ot6C+spkQZVkN3Hkad7/lp3JKJjZ5JMLp53pSlp\n" +
            "3B53uCFf/OFUzGViTIyn+bGCnOD3WvvfUWefi85C7Imwk0JtvyzEI9mTF4cldk8u\n" +
            "LoiUtF4/ZxInq0OCInikqQ+jCJgrAgMBAAECgYBv5yacfqf0Ah8v68VPU1QWwGU5\n" +
            "tpJuPFlTcZJJ4OLlAavoXLMjxXXZ1gp6dyPbMF5TV3VxgUznHcouvQHg/9wSAL5U\n" +
            "Bhk0uZiMBN+uNMatxvMcyv2XbLL6s/BHfRTZoWy95bzZW9Y4kwqN9BJa/xEaYxcI\n" +
            "1jcPzU21TzYCiZ1wwQJBAN/kYYUFBwn/pp+KcWN4rYzIQQrw69yXC+iBxgBDpcif\n" +
            "zfj9iDfb8vwf5EpjzJSiJkUyFVmT0lW8mlmpKBa9zzECQQDOH4rSOabLTEWPVu28\n" +
            "EDykzOBFRAM6qoJM2zs3ac9s6elkzOQ5UVLis3r+xeuGxbPnnzi0Ko8phNmK3/oT\n" +
            "fB4bAkEA2c+no64BbBO++OTJbLkBNb23sToya1ay6g4eHzGwfd4hloKn25fp6qfo\n" +
            "AwrWAx9AVf7kUFIDxQ8HpgRvkLg1cQJAaemlQE5lWTMQzw2AzNCfCKNJXe4Lprp0\n" +
            "h59itx+EeNdcmPH7F0SlTV2iBoWWd0LhJVQYI+N2eoQL8CMUcaymHwJBAMCKVqSr\n" +
            "0x3c/x/w6IgzVmc4ZiPXDoVOpYLEpbdjvYY1FgLZqopP9kugJnJGJFV81LL5VDgt\n" +
            "rlnWtqrAawaf3KA=\n" +
            "-----END RSA PRIVATE KEY-----";

    public static byte[] TEST_OCSP_SERVER_CA_KEY_BASE64 = getBase64FromPEM(TEST_OCSP_SERVER_CA_KEY_PEM);

    public static String TEST_OCSP_SERVER_CA_CERT_PEM = "-----BEGIN CERTIFICATE-----\n" +
            "MIIEOTCCAiGgAwIBAgIIMMRUqshC0ZQwDQYJKoZIhvcNAQELBQAwYTEdMBsGA1UE\n" +
            "AwwUVGVzdCBTZXJ2ZXIgQ0EgRFVNTVkxDjAMBgNVBAcMBUtpc3RhMR0wGwYDVQQK\n" +
            "DBRDZXJ0aWZpY2F0ZSBTZXJ2aWNlczERMA8GA1UECwwIU2VjdXJpdHkwHhcNMTkw\n" +
            "MTE3MDk0MTU3WhcNNDYwNjA0MDk0MTU3WjBlMSEwHwYDVQQDDBhPQ1NQIFJlc3Bv\n" +
            "bmRlciBTZXJ2ZXIgQ0ExETAPBgNVBAsMCFNlY3VyaXR5MR0wGwYDVQQKDBRDZXJ0\n" +
            "aWZpY2F0ZSBTZXJ2aWNlczEOMAwGA1UEBwwFS2lzdGEwgZ8wDQYJKoZIhvcNAQEB\n" +
            "BQADgY0AMIGJAoGBALRFXInRfLNUgYq/aCN+sZflfrXu/ERoGpQ/0agy7Ot6C+sp\n" +
            "kQZVkN3Hkad7/lp3JKJjZ5JMLp53pSlp3B53uCFf/OFUzGViTIyn+bGCnOD3Wvvf\n" +
            "UWefi85C7Imwk0JtvyzEI9mTF4cldk8uLoiUtF4/ZxInq0OCInikqQ+jCJgrAgMB\n" +
            "AAGjdTBzMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFPEY2NGiZIgfp9kWDBJjn7ah\n" +
            "jNXlMB8GA1UdIwQYMBaAFPrOATJykVEgUAmRtpNCClAMUJ3LMA4GA1UdDwEB/wQE\n" +
            "AwIHgDATBgNVHSUEDDAKBggrBgEFBQcDCTANBgkqhkiG9w0BAQsFAAOCAgEAWn7C\n" +
            "lbu/FEcves4zHRiqqOdw/A2y4MrLiyfzqaWJkY4gpBq4SP5bxulm0idwbqzkMq7f\n" +
            "Zeui6vnmyXzK6qt6XNk0R1PH35WJoumrJNM90NMewq1/luAl4EpifY+4Ky1R30e5\n" +
            "yEjlXSCz7VYwD4DzqUuCPq/Wp3hRxpdxd/f/kFmEZWvyGfowQyh/a9QFs5Vo+WSc\n" +
            "A9dFsv9OVQsTFACSgPIyuL+a+9sUc3/uYMIxEnJqK8B+9UBmZ/yLaNLF9yvJXqlj\n" +
            "wruL7X9JGB1wtR2DAz0Q860e4pb0mjmlADaVeKsVMHZ0u4gQ+D/P0wZIi/EoWbcq\n" +
            "h+boq0o8mLtEC0cqDI8zdl2V8gzH674n3WqjFwV7KokBfHGSui1076fTMaI+gEeR\n" +
            "jckOQJl25tlER5ukw9idcjiJVsZMJnoOCBv3Zvr4nW+BKyJltJXv+w3N05/WGW5G\n" +
            "0kBmDOxbU6Lae80lNIn0sdQr2FnwzNDKPi9MaoA1YeHVwF3j/0CR8hjhQCwYG97P\n" +
            "V6lBTUWDXeQbXtHe+MzdvW9dN2pTv4J82nNGTCqgOGIVwACBAa6JtpxKj035TDTL\n" +
            "+9Dkfa478TY/Vsa+GthzrCKokp+AgR1y5XYfiSmOPYxcTFT6r+QbZOmsa35/Sbse\n" +
            "0eDiZKFTYnejO62RPQrBehwHfoKWe8Bl+ow9eMw=\n" +
            "-----END CERTIFICATE-----";

    public static byte[] TEST_OCSP_SERVER_CA_CERT_BASE64 = getBase64FromPEM(TEST_OCSP_SERVER_CA_CERT_PEM);

    public static String TEST_OCSP_V2_SERVER_CA_KEY_PEM = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALIfdXrryh2hF+A7\n" +
            "4qHv6eehidW+Y5v3G++e+PElgcH2pS5hricYN3Ql/wK1xYHtO6CBzpcnDVcPXBlk\n" +
            "CNjlmeEbjsbdESWTvZkfA4KcE9KmwhbiJ9lGINy/fO+gH7777JXqpdhywF3W3Wh4\n" +
            "yf8xn5tblcfd4nrwzesgsRhaR/yXAgMBAAECgYABZO+le60EWFt4fN+ERv18u635\n" +
            "h1j+Qovsb0EhmhqO6yBV4ZvcYHsmpJl/au7V2oaJ9hoo4rxe/xbIeBj9oaZ3skV6\n" +
            "tvt7AaVrp/QG1RphxPaT/c9GTaM6vI/6WdYt5IPK6N04ba3uOeMoXVh6xikBfRI/\n" +
            "L5ar4VN+MsNUVPyhAQJBAOjg10cMkoTOxF4fVJcbhT0oorzt6wlcqBPHO6i7/DIy\n" +
            "O7cC5uf3eYjroDo2hjmsUkxGimTaddgBy9Ap4GVmwYECQQDDzuDiRXQOOIk20dKi\n" +
            "DlK6xGR7bMZb8G6pW2wzAhZHI+8VIYzJ+1cr0bgGQ5GZvpBhx+A8uHDjNyasFeR2\n" +
            "JZoXAkAD/ncyvMB2jqVHh/oHbW1nkx7XZq01R+WKEUywpCi7I6lqhh43tELdWk0x\n" +
            "MmYy7wWqUTtmZ2jF/6HjPBShKJYBAkAS/LWb22ZElsDfevs00bS9/ZtMyKB3e9oP\n" +
            "PBlC3PnyDg75+pXfZCrwydZRbS3qPatcf/hDixMPRWLPnxPXTRAjAkEAkpjc1dLj\n" +
            "plEOrzERnsYi7TRCGHMYWPQrnvZmSSXKg1XKlZGGrPTM7Vxo7x+WuKRR6zlgCYlW\n" +
            "drptepQ0Gt9MHA==\n" +
            "-----END RSA PRIVATE KEY-----";

    public static byte[] TEST_OCSP_V2_SERVER_CA_KEY_BASE64 = getBase64FromPEM(TEST_OCSP_V2_SERVER_CA_KEY_PEM);

    public static String TEST_OCSP_V2_SERVER_CA_CERT_PEM = "-----BEGIN CERTIFICATE-----\n" +
            "MIIEPDCCAiSgAwIBAgIIaGj8etB/kTwwDQYJKoZIhvcNAQELBQAwYTEdMBsGA1UE\n" +
            "AwwUVGVzdCBTZXJ2ZXIgQ0EgRFVNTVkxDjAMBgNVBAcMBUtpc3RhMR0wGwYDVQQK\n" +
            "DBRDZXJ0aWZpY2F0ZSBTZXJ2aWNlczERMA8GA1UECwwIU2VjdXJpdHkwHhcNMTkw\n" +
            "MTE3MDk1ODM3WhcNNDYwNjA0MDk1ODM3WjBoMSQwIgYDVQQDDBtPQ1NQIFYyIFJl\n" +
            "c3BvbmRlciBTZXJ2ZXIgQ0ExETAPBgNVBAsMCFNlY3VyaXR5MR0wGwYDVQQKDBRD\n" +
            "ZXJ0aWZpY2F0ZSBTZXJ2aWNlczEOMAwGA1UEBwwFS2lzdGEwgZ8wDQYJKoZIhvcN\n" +
            "AQEBBQADgY0AMIGJAoGBALIfdXrryh2hF+A74qHv6eehidW+Y5v3G++e+PElgcH2\n" +
            "pS5hricYN3Ql/wK1xYHtO6CBzpcnDVcPXBlkCNjlmeEbjsbdESWTvZkfA4KcE9Km\n" +
            "whbiJ9lGINy/fO+gH7777JXqpdhywF3W3Wh4yf8xn5tblcfd4nrwzesgsRhaR/yX\n" +
            "AgMBAAGjdTBzMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFCYtCmLyIDEa0C6+h65d\n" +
            "UWafe7V/MB8GA1UdIwQYMBaAFPrOATJykVEgUAmRtpNCClAMUJ3LMA4GA1UdDwEB\n" +
            "/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDCTANBgkqhkiG9w0BAQsFAAOCAgEA\n" +
            "m1avi4T+Go+S5Sz3+J0n9k6WBP/BsTlKIdUirpkzz+CbHJtjdHse4JyK7kvtXhW1\n" +
            "MEyfHm/TbDNyEpAYc2Zdi7dpJ1Wz9HfNg5WvakM1Rpb/UpOhoQtnGjGc6BnU/bhk\n" +
            "W3wzTU2pK3BQSLJNK/IunUUWs7mz2r2j/o5pSDd8TCCh507oucZO0cCQd+8Nc2QN\n" +
            "H/JuzBvv1JUenT2hVVlLgM76gDnvMM1MQztzq5StGxa90HHr2ivybcfSQobJiIUC\n" +
            "o03efMqFtZQeZqqHV/dicVmW2WLFLMbUQye6Mwrj5gtxqV+nQWyrTw47nUsU2vq2\n" +
            "kqFg5UvLKNeB7ImUv73ui3sdEaUn+3/Ygj2AQl06mtYD9LmjUyFUfysEGvXb/LYn\n" +
            "dx+Rgi/S9B/Nf0UXNjiCk/OSMe0OJ9ZMg0VKYvJEboDUVMawmxKn3Dc3TAotdQiA\n" +
            "AuKiV+yUlwmp5yYH85/T4O9oGmdSdA4D38k2zjl3AV5mRHRL7rcKOW/v6emq2LHZ\n" +
            "PkC0OZ+UQh0yIYkNun8YJ3IdfeaBO/CVQimLJkD3KAFRLMCYEvrAqLRK2o0WklP/\n" +
            "yZpYVc1CK+h7KY20uWuIAT0xlRR9wsmDx90O+8PxtFLPgBr9E8Yh3gZ96yK1KPPX\n" +
            "zMSN0H2yENTINMUITcWYUVnBxVpFU3wPMSuX4hkzkTw=\n" +
            "-----END CERTIFICATE-----";

    public static byte[] TEST_OCSP_V2_SERVER_CA_CERT_BASE64 = getBase64FromPEM(TEST_OCSP_V2_SERVER_CA_CERT_PEM);


    private static byte[] getBase64FromPEM(String pem){
        return pem.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace("-----BEGIN X509 CRL-----", "")
                .replace("-----END X509 CRL-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replaceAll("\n", "")
                .getBytes();
    }
}
