<?php

namespace PayU\ApplePay\Decoding\OpenSSL;

use PayU\ApplePay\ApplePaySettings;
use PayU\ApplePay\Decoding\TemporaryFile\TemporaryFile;

class OpenSslServiceTest extends \PHPUnit_Framework_TestCase
{
    /** @var OpenSslService */
    private $openSslService;

    private $leafCertificate = 'subject=/CN=ecc-smp-broker-sign_UC4-SANDBOX/OU=iOS Systems/O=Apple Inc./C=US
issuer=/CN=Apple Application Integration CA - G3/OU=Apple Certification Authority/O=Apple Inc./C=US
-----BEGIN CERTIFICATE-----
MIID5jCCA4ugAwIBAgIIaGD2mdnMpw8wCgYIKoZIzj0EAwIwejEuMCwGA1UEAwwl
QXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgLSBHMzEmMCQGA1UECwwd
QXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIElu
Yy4xCzAJBgNVBAYTAlVTMB4XDTE2MDYwMzE4MTY0MFoXDTIxMDYwMjE4MTY0MFow
YjEoMCYGA1UEAwwfZWNjLXNtcC1icm9rZXItc2lnbl9VQzQtU0FOREJPWDEUMBIG
A1UECwwLaU9TIFN5c3RlbXMxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgjD9q8Oc914gLFDZm0US5jfi
qQHdbLPgsc1LUmeY+M9OvegaJajCHkwz3c6OKpbC9q+hkwNFxOh6RCbOlRsSlaOC
AhEwggINMEUGCCsGAQUFBwEBBDkwNzA1BggrBgEFBQcwAYYpaHR0cDovL29jc3Au
YXBwbGUuY29tL29jc3AwNC1hcHBsZWFpY2EzMDIwHQYDVR0OBBYEFAIkMAua7u1G
MZekplopnkJxghxFMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUI/JJxE+T5O8n
5sT2KGw/orv9LkswggEdBgNVHSAEggEUMIIBEDCCAQwGCSqGSIb3Y2QFATCB/jCB
wwYIKwYBBQUHAgIwgbYMgbNSZWxpYW5jZSBvbiB0aGlzIGNlcnRpZmljYXRlIGJ5
IGFueSBwYXJ0eSBhc3N1bWVzIGFjY2VwdGFuY2Ugb2YgdGhlIHRoZW4gYXBwbGlj
YWJsZSBzdGFuZGFyZCB0ZXJtcyBhbmQgY29uZGl0aW9ucyBvZiB1c2UsIGNlcnRp
ZmljYXRlIHBvbGljeSBhbmQgY2VydGlmaWNhdGlvbiBwcmFjdGljZSBzdGF0ZW1l
bnRzLjA2BggrBgEFBQcCARYqaHR0cDovL3d3dy5hcHBsZS5jb20vY2VydGlmaWNh
dGVhdXRob3JpdHkvMDQGA1UdHwQtMCswKaAnoCWGI2h0dHA6Ly9jcmwuYXBwbGUu
Y29tL2FwcGxlYWljYTMuY3JsMA4GA1UdDwEB/wQEAwIHgDAPBgkqhkiG92NkBh0E
AgUAMAoGCCqGSM49BAMCA0kAMEYCIQDaHGOui+X2T44R6GVpN7m2nEcr6T6sMjOh
Z5NuSo1egwIhAL1a+/hp88DKJ0sv3eT3FxWcs71xmbLKD/QJ3mWagrJN
-----END CERTIFICATE-----';

    // Header formats differ in openssl 1.1.1
    private $leafCertificate_1_1_1 = 'subject=CN = ecc-smp-broker-sign_UC4-SANDBOX, OU = iOS Systems, O = Apple Inc., C = US
issuer=CN = Apple Application Integration CA - G3, OU = Apple Certification Authority, O = Apple Inc., C = US
-----BEGIN CERTIFICATE-----
MIID5jCCA4ugAwIBAgIIaGD2mdnMpw8wCgYIKoZIzj0EAwIwejEuMCwGA1UEAwwl
QXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgLSBHMzEmMCQGA1UECwwd
QXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIElu
Yy4xCzAJBgNVBAYTAlVTMB4XDTE2MDYwMzE4MTY0MFoXDTIxMDYwMjE4MTY0MFow
YjEoMCYGA1UEAwwfZWNjLXNtcC1icm9rZXItc2lnbl9VQzQtU0FOREJPWDEUMBIG
A1UECwwLaU9TIFN5c3RlbXMxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgjD9q8Oc914gLFDZm0US5jfi
qQHdbLPgsc1LUmeY+M9OvegaJajCHkwz3c6OKpbC9q+hkwNFxOh6RCbOlRsSlaOC
AhEwggINMEUGCCsGAQUFBwEBBDkwNzA1BggrBgEFBQcwAYYpaHR0cDovL29jc3Au
YXBwbGUuY29tL29jc3AwNC1hcHBsZWFpY2EzMDIwHQYDVR0OBBYEFAIkMAua7u1G
MZekplopnkJxghxFMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUI/JJxE+T5O8n
5sT2KGw/orv9LkswggEdBgNVHSAEggEUMIIBEDCCAQwGCSqGSIb3Y2QFATCB/jCB
wwYIKwYBBQUHAgIwgbYMgbNSZWxpYW5jZSBvbiB0aGlzIGNlcnRpZmljYXRlIGJ5
IGFueSBwYXJ0eSBhc3N1bWVzIGFjY2VwdGFuY2Ugb2YgdGhlIHRoZW4gYXBwbGlj
YWJsZSBzdGFuZGFyZCB0ZXJtcyBhbmQgY29uZGl0aW9ucyBvZiB1c2UsIGNlcnRp
ZmljYXRlIHBvbGljeSBhbmQgY2VydGlmaWNhdGlvbiBwcmFjdGljZSBzdGF0ZW1l
bnRzLjA2BggrBgEFBQcCARYqaHR0cDovL3d3dy5hcHBsZS5jb20vY2VydGlmaWNh
dGVhdXRob3JpdHkvMDQGA1UdHwQtMCswKaAnoCWGI2h0dHA6Ly9jcmwuYXBwbGUu
Y29tL2FwcGxlYWljYTMuY3JsMA4GA1UdDwEB/wQEAwIHgDAPBgkqhkiG92NkBh0E
AgUAMAoGCCqGSM49BAMCA0kAMEYCIQDaHGOui+X2T44R6GVpN7m2nEcr6T6sMjOh
Z5NuSo1egwIhAL1a+/hp88DKJ0sv3eT3FxWcs71xmbLKD/QJ3mWagrJN
-----END CERTIFICATE-----';

    private $intermediateCertificate = 'subject=/CN=Apple Application Integration CA - G3/OU=Apple Certification Authority/O=Apple Inc./C=US
issuer=/CN=Apple Root CA - G3/OU=Apple Certification Authority/O=Apple Inc./C=US
-----BEGIN CERTIFICATE-----
MIIC7jCCAnWgAwIBAgIISW0vvzqY2pcwCgYIKoZIzj0EAwIwZzEbMBkGA1UEAwwS
QXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9u
IEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcN
MTQwNTA2MjM0NjMwWhcNMjkwNTA2MjM0NjMwWjB6MS4wLAYDVQQDDCVBcHBsZSBB
cHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBD
ZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkG
A1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATwFxGEGddkhdUaXiWB
B3bogKLv3nuuTeCN/EuT4TNW1WZbNa4i0Jd2DSJOe7oI/XYXzojLdrtmcL7I6CmE
/1RFo4H3MIH0MEYGCCsGAQUFBwEBBDowODA2BggrBgEFBQcwAYYqaHR0cDovL29j
c3AuYXBwbGUuY29tL29jc3AwNC1hcHBsZXJvb3RjYWczMB0GA1UdDgQWBBQj8knE
T5Pk7yfmxPYobD+iu/0uSzAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFLuw
3qFYM4iapIqZ3r6966/ayySrMDcGA1UdHwQwMC4wLKAqoCiGJmh0dHA6Ly9jcmwu
YXBwbGUuY29tL2FwcGxlcm9vdGNhZzMuY3JsMA4GA1UdDwEB/wQEAwIBBjAQBgoq
hkiG92NkBgIOBAIFADAKBggqhkjOPQQDAgNnADBkAjA6z3KDURaZsYb7NcNWymK/
9Bft2Q91TaKOvvGcgV5Ct4n4mPebWZ+Y1UENj53pwv4CMDIt1UQhsKMFd2xd8zg7
kGf9F3wsIW2WT8ZyaYISb1T4en0bmcubCYkhYQaZDwmSHQ==
-----END CERTIFICATE-----';

    // Header formats differ in openssl 1.1.1
    private $intermediateCertificate_1_1_1 = 'subject=CN = Apple Application Integration CA - G3, OU = Apple Certification Authority, O = Apple Inc., C = US
issuer=CN = Apple Root CA - G3, OU = Apple Certification Authority, O = Apple Inc., C = US
-----BEGIN CERTIFICATE-----
MIIC7jCCAnWgAwIBAgIISW0vvzqY2pcwCgYIKoZIzj0EAwIwZzEbMBkGA1UEAwwS
QXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9u
IEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcN
MTQwNTA2MjM0NjMwWhcNMjkwNTA2MjM0NjMwWjB6MS4wLAYDVQQDDCVBcHBsZSBB
cHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBD
ZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkG
A1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATwFxGEGddkhdUaXiWB
B3bogKLv3nuuTeCN/EuT4TNW1WZbNa4i0Jd2DSJOe7oI/XYXzojLdrtmcL7I6CmE
/1RFo4H3MIH0MEYGCCsGAQUFBwEBBDowODA2BggrBgEFBQcwAYYqaHR0cDovL29j
c3AuYXBwbGUuY29tL29jc3AwNC1hcHBsZXJvb3RjYWczMB0GA1UdDgQWBBQj8knE
T5Pk7yfmxPYobD+iu/0uSzAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFLuw
3qFYM4iapIqZ3r6966/ayySrMDcGA1UdHwQwMC4wLKAqoCiGJmh0dHA6Ly9jcmwu
YXBwbGUuY29tL2FwcGxlcm9vdGNhZzMuY3JsMA4GA1UdDwEB/wQEAwIBBjAQBgoq
hkiG92NkBgIOBAIFADAKBggqhkjOPQQDAgNnADBkAjA6z3KDURaZsYb7NcNWymK/
9Bft2Q91TaKOvvGcgV5Ct4n4mPebWZ+Y1UENj53pwv4CMDIt1UQhsKMFd2xd8zg7
kGf9F3wsIW2WT8ZyaYISb1T4en0bmcubCYkhYQaZDwmSHQ==
-----END CERTIFICATE-----';

    private $publicKey = '-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEE2bliUppPzZ514eAP3VchGbxAHWD
9Mg8bYTHqmQCPRVhKhA9ePuZ6wvBOM97fMu9sHo6GFr00mPAhoT+vww+jg==
-----END PUBLIC KEY-----
';

    private $privateKey = '-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEV17KjFHD0W014fRRnbM4Un9gkOEYhJz/A/qWPd9PIloAoGCCqGSM49
AwEHoUQDQgAESRBiGT+GnbM3r1M4fhYEFUKe6EHA+z6r2ctjtWqeAs9wI48MBoGK
FrwWqY/zbzMNYgaOm+DnUMjF8v8v1nMtag==
-----END EC PRIVATE KEY-----
';

    public function setUp()
    {
        $this->openSslService = new OpenSslService();
    }

    public function testValidateCertificateChainSuccess()
    {
        $intermediateCertificate = new TemporaryFile();
        $intermediateCertificate->write($this->intermediateCertificate);

        $leafCertificate = new TemporaryFile();
        $leafCertificate->write($this->leafCertificate);

        $response = $this->openSslService->validateCertificateChain(__DIR__ . '/../../../examples/AppleRootCA-G3.pem', $intermediateCertificate->getPath(), $leafCertificate->getPath());

        $this->assertTrue($response);
    }

    /**
     * @expectedException \Exception
     */
    public function testValidateCertificateChainFail()
    {
        $intermediateCertificate = new TemporaryFile();
        $intermediateCertificate->write($this->intermediateCertificate);

        $leafCertificate = new TemporaryFile();
        $leafCertificate->write('invalid certificate');

        $this->openSslService->validateCertificateChain(__DIR__ . '/../../../examples/AppleRootCA-G3.pem', $intermediateCertificate->getPath(), $leafCertificate->getPath());
    }

    public function testVerifySignatureSuccess()
    {
        $signedAttributes = base64_decode('MYGVMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE3MTIxMTE2MTAyNVowKgYJKoZIhvcNAQk0MR0wGzANBglghkgBZQMEAgEFAKEKBggqhkjOPQQDAjAvBgkqhkiG9w0BCQQxIgQgwsYUbK8j9xu7zed2B5jbOYSNaenOmC5cf1ZV01+DHOY=');
        $signature = base64_decode('MEUCIEZvNK+I5N/EE6yYCHJqijamwaHHhW9pQAlsCSFocosWAiEAmzl1jc20RxbfVtiD1Z7C5u2UtmKCDHO2s5Eab0fnyys=');

        $publicKey = '-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgjD9q8Oc914gLFDZm0US5jfiqQHd
bLPgsc1LUmeY+M9OvegaJajCHkwz3c6OKpbC9q+hkwNFxOh6RCbOlRsSlQ==
-----END PUBLIC KEY-----';

        $response = $this->openSslService->verifySignature($signedAttributes, $signature, $publicKey);

        $this->assertTrue($response);
    }

    /**
     * @expectedException \Exception
     */
    public function testVerifySignatureFail()
    {
        $signedAttributes = 'invalid_value';
        $signature = 'invalid_value';

        $this->openSslService->verifySignature($signedAttributes, $signature, $this->publicKey);
    }

    public function testGetCertificatesFromPkcs7Success()
    {
        $expectedResponse = $this->leafCertificate . PHP_EOL . PHP_EOL . $this->intermediateCertificate;

        if (getenv('OPENSSL_VERSION') === '1.1.1') {
            $expectedResponse = $this->leafCertificate_1_1_1 . PHP_EOL . PHP_EOL . $this->intermediateCertificate_1_1_1;
        }

        $signature = base64_decode('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');

        $certificateFile = new TemporaryFile();
        $certificateFile->write($signature);

        $response = $this->openSslService->getCertificatesFromPkcs7($certificateFile->getPath());

        $this->assertEquals($expectedResponse, $response);
    }

    /**
     * @expectedException \Exception
     */
    public function testGetCertificatesFromPkcs7Fail()
    {
        $certificateFile = new TemporaryFile();
        $certificateFile->write('invalid signature');

        $this->openSslService->getCertificatesFromPkcs7($certificateFile->getPath());
    }

    public function testGetCertificateExtensionsSuccess()
    {
        $response = $this->openSslService->getCertificateExtensions($this->leafCertificate);
        $this->assertNotEmpty($response);

    }

    /**
     * @expectedException \Exception
     */
    public function testGetCertificateExtensionsFail()
    {
        $this->openSslService->getCertificateExtensions('invalid certificate');
    }

    public function testDeriveKeySuccess()
    {
        $privateKeyFile = new TemporaryFile();
        $privateKeyFile->write($this->privateKey);

        $publicKeyFile = new TemporaryFile();
        $publicKeyFile->write($this->publicKey);

        $expectedKey = base64_decode('hkyWug8AlSS7Nr9fR1TcoDWO9NbicLOui7RXNskAYXc=');

        $response = $this->openSslService->deriveKey($privateKeyFile->getPath(), $publicKeyFile->getPath());

        $this->assertEquals($expectedKey, $response);
    }

    /**
     * @expectedException \Exception
     */
    public function testDeriveKeyFailIfPrivateKeyIsInvalid()
    {
        $privateKeyData = 'invalid key';

        $privateKeyFile = new TemporaryFile();
        $privateKeyFile->write($privateKeyData);

        $publicKeyFile = new TemporaryFile();
        $publicKeyFile->write($this->publicKey);

        $this->openSslService->deriveKey($privateKeyFile->getPath(), $publicKeyFile->getPath());
    }

    /**
     * @expectedException \Exception
     */
    public function testDeriveKeyFailIfPublicKeyIsInvalid()
    {
        $publicKey = 'invalid key';

        $privateKeyFile = new TemporaryFile();
        $privateKeyFile->write($this->privateKey);

        $publicKeyFile = new TemporaryFile();
        $publicKeyFile->write($publicKey);

        $this->openSslService->deriveKey($privateKeyFile->getPath(), $publicKeyFile->getPath());
    }
}
