<?php

namespace PayU\ApplePay\Decoding;

use PayU\ApplePay\Decoding\OpenSSL\OpenSslService;
use PayU\ApplePay\Decoding\SignatureVerifier\SignatureVerifierFactory;
use PayU\ApplePay\Decoding\TemporaryFile\TemporaryFile;
use PayU\ApplePay\Decoding\TemporaryFile\TemporaryFileService;

class PKCS7SignatureValidatorTest extends \PHPUnit_Framework_TestCase
{
    /** @var SignatureVerifierFactory */
    private $signatureVerifierFactoryMock;

    /** @var Asn1Wrapper */
    private $asn1WrapperMock;

    /** @var TemporaryFileService */
    private $temporaryFileServiceMock;

    /** @var OpenSslService */
    private $openSslServiceMock;

    /** @var PKCS7SignatureValidatorSettings */
    private $pkcs7SignatureValidatorSettingsMock;

    /** @var PKCS7SignatureValidator */
    private $pkcs7SignatureValidator;

    public function setUp()
    {
        $this->signatureVerifierFactoryMock = $this->getMockBuilder(SignatureVerifierFactory::class)
            ->disableOriginalConstructor()
            ->getMock();

        $this->asn1WrapperMock = $this->getMockBuilder(Asn1Wrapper::class)
            ->disableOriginalConstructor()
            ->getMock();

        $this->temporaryFileServiceMock = $this->getMockBuilder(TemporaryFileService::class)
            ->disableOriginalConstructor()
            ->getMock();

        $this->openSslServiceMock = $this->getMockBuilder(OpenSslService::class)
            ->disableOriginalConstructor()
            ->getMock();

        $this->pkcs7SignatureValidatorSettingsMock = $this->getMockBuilder(PKCS7SignatureValidatorSettings::class)
            ->disableOriginalConstructor()
            ->getMock();

      $this->pkcs7SignatureValidator = new PKCS7SignatureValidator(
          $this->signatureVerifierFactoryMock,
          $this->asn1WrapperMock,
          $this->temporaryFileServiceMock,
          $this->openSslServiceMock,
          $this->pkcs7SignatureValidatorSettingsMock
      );
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Signature is not a valid base64 value
     */
    public function testValidateThrowsExceptionIfSignatureIsNotBase64() {
        $invalidSignature = '====';

        $this->pkcs7SignatureValidator->validate(
            ['signature' => $invalidSignature],
            'dummy path',
            99999
        );
    }


    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Missing OID OID_VALUE from certificate
     */
    public function testValidateThrowsExceptionIfOidIsMissing() {
        $certificates = 'subject=/CN=ecc-smp-broker-sign_UC4-SANDBOX/OU=iOS Systems/O=Apple Inc./C=US
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
-----END CERTIFICATE-----

subject=/CN=Apple Application Integration CA - G3/OU=Apple Certification Authority/O=Apple Inc./C=US
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


        $this->pkcs7SignatureValidatorSettingsMock->method('getLeafCertificateOid')->willReturn('OID_VALUE');
        $this->temporaryFileServiceMock->method('createFile')->willReturn(new TemporaryFile());
        $this->openSslServiceMock->method('getCertificatesFromPkcs7')->willReturn($certificates);

        $this->pkcs7SignatureValidator->validate(
            ['signature' => base64_encode('dummy_data')],
            'dummy path',
            99999
        );
    }
}
