<?php

namespace PayU\ApplePay\Decoding\OpenSSL;

use Exception;
use PayU\ApplePay\Decoding\TemporaryFile\TemporaryFile;

use PHPUnit\Framework\TestCase;

class OpenSslServiceTest extends TestCase
{
    /** @var OpenSslService */
    private $openSslService;

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

    protected function setUp(): void
    {
        $this->openSslService = new OpenSslService();
    }

    public function testValidateCertificateChainSuccess(): void
    {
        $rootCertPath = realpath(__DIR__ . '/root.crt');
        $intermediateCertPath = realpath(__DIR__ . '/intermediate.crt');
        $leafCertPath = realpath(__DIR__ . '/leaf.crt');

        $response = $this->openSslService->validateCertificateChain($rootCertPath, $intermediateCertPath, $leafCertPath);

        $this->assertTrue($response);
    }

    public function testValidateCertificateChainFail(): void
    {
        $this->expectException(Exception::class);

        $rootCertPath = realpath(__DIR__ . '/root.crt');
        $intermediateCertPath = realpath(__DIR__ . '/intermediate.crt');
        $leafCertPath = realpath(__DIR__ . '/leaf-bad.crt');

        $this->openSslService->validateCertificateChain($rootCertPath, $intermediateCertPath, $leafCertPath);
    }

    public function testVerifySignatureSuccess(): void
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

    public function testVerifySignatureFail(): void
    {
        $this->expectException(Exception::class);

        $signedAttributes = 'invalid_value';
        $signature = 'invalid_value';

        $this->openSslService->verifySignature($signedAttributes, $signature, $this->publicKey);
    }

    public function testGetCertificatesFromPkcs7Success()
    {
        $leafHeader = 'subject=C = RO, ST = BUH, L = Bucuresti, O = Internet Widgits Pty Ltd, CN = leaflet' .
            PHP_EOL . 'issuer=C = RO, ST = BUH, O = PayU, CN = intermediate-cert' . PHP_EOL;
        $leafCert = file_get_contents(__DIR__ . '/leaf.crt');
        $intermediateHeader = 'subject=C = RO, ST = BUH, O = PayU, CN = intermediate-cert' . PHP_EOL .
            'issuer=C = RO, ST = BUH, O = PayU ROOT, CN = root-cert' . PHP_EOL;
        $intermediateCert = file_get_contents(__DIR__ . '/intermediate.crt');

        $expectedResponse = $leafHeader . $leafCert . PHP_EOL . PHP_EOL . $intermediateHeader . $intermediateCert;

        $pkcs7DerCert = realpath(__DIR__ . '/leaf.p7b');

        $response = $this->openSslService->getCertificatesFromPkcs7($pkcs7DerCert);

        $this->assertEquals($expectedResponse, $response);
    }

    public function testGetCertificatesFromPkcs7Fail()
    {
        $this->expectException(Exception::class);

        $nonPkcs7DerCert = realpath(__DIR__ . '/leaf.crt');

        $this->openSslService->getCertificatesFromPkcs7($nonPkcs7DerCert);
    }

    public function testGetCertificateExtensionsSuccess()
    {
        $leafCert = file_get_contents(__DIR__ . '/leaf.crt');
        $response = $this->openSslService->getCertificateExtensions($leafCert);
        $this->assertNotEmpty($response);
    }

    public function testGetCertificateExtensionsFail()
    {
        $this->expectException(Exception::class);
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

    public function testDeriveKeyFailIfPrivateKeyIsInvalid()
    {
        $this->expectException(Exception::class);
        $privateKeyData = 'invalid key';

        $privateKeyFile = new TemporaryFile();
        $privateKeyFile->write($privateKeyData);

        $publicKeyFile = new TemporaryFile();
        $publicKeyFile->write($this->publicKey);

        $this->openSslService->deriveKey($privateKeyFile->getPath(), $publicKeyFile->getPath());
    }

    public function testDeriveKeyFailIfPublicKeyIsInvalid()
    {
        $this->expectException(Exception::class);
        $publicKey = 'invalid key';

        $privateKeyFile = new TemporaryFile();
        $privateKeyFile->write($this->privateKey);

        $publicKeyFile = new TemporaryFile();
        $publicKeyFile->write($publicKey);

        $this->openSslService->deriveKey($privateKeyFile->getPath(), $publicKeyFile->getPath());
    }
}
