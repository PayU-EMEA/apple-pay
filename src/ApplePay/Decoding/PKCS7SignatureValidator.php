<?php

namespace PayU\ApplePay\Decoding;

use PayU\ApplePay\Decoding\OpenSSL\OpenSslService;
use PayU\ApplePay\Decoding\SignatureVerifier\SignatureVerifierFactory;
use PayU\ApplePay\Decoding\TemporaryFile\TemporaryFileService;

class PKCS7SignatureValidator
{
    /** @var Asn1Wrapper */
    private $asn1Wrapper;

    /** @var TemporaryFileService */
    private $temporaryFileService;

    /** @var SignatureVerifierFactory */
    private $signatureVerifierFactory;

    /** @var OpenSslService */
    private $openSslService;

    /** @var PKCS7SignatureValidatorSettings */
    private $pkcs7SignatureValidatorSettings;

    public function __construct(SignatureVerifierFactory $signatureVerifierFactory, Asn1Wrapper $asn1Wrapper, TemporaryFileService $temporaryFileService, OpenSslService $openSslService, PKCS7SignatureValidatorSettings $pkcs7SignatureValidatorSettings)
    {
        $this->signatureVerifierFactory = $signatureVerifierFactory;
        $this->asn1Wrapper = $asn1Wrapper;
        $this->temporaryFileService = $temporaryFileService;
        $this->openSslService = $openSslService;
        $this->pkcs7SignatureValidatorSettings = $pkcs7SignatureValidatorSettings;
    }

    /**
     * @param array $paymentData
     * @param $rootCertificatePath
     * @param $signatureExpirationTime
     * @return bool
     * @throws \PayU\ApplePay\Decoding\SignatureVerifier\Exception\SignatureException
     * @throws \Exception
     * @throws \RuntimeException
     */
    public function validate(array $paymentData, $rootCertificatePath, $signatureExpirationTime)
    {
        $signature = base64_decode($paymentData['signature']);

        if(empty($signature)) {
            throw new \RuntimeException('Signature is not a valid base64 value');
        }

        $certificates = $this->extractCertificates($signature);

        // 1.a. Ensure that the certificates contain the correct custom OIDs: 1.2.840.113635.100.6.29 for the leaf certificate and 1.2.840.113635.100.6.2.14 for the intermediate CA. The value for these marker OIDs doesn’t matter, only their presence.
        $this->checkIfCertificateContainOID($certificates[0], $this->pkcs7SignatureValidatorSettings->getLeafCertificateOid());
        $this->checkIfCertificateContainOID($certificates[1], $this->pkcs7SignatureValidatorSettings->getIntermediateCertificateOid());

        // 1.b. Ensure that the root CA is the Apple Root CA - G3. This certificate is available from apple.com/certificateauthority.
        // 1.c. Ensure that there is a valid X.509 chain of trust from the signature to the root CA. Specifically, ensure that the signature was created using the private key corresponding to the leaf certificate, that the leaf certificate is signed by the intermediate CA, and that the intermediate CA is signed by the Apple Root CA - G3.
        $this->validateChainOfTrust($certificates, $rootCertificatePath);

        // 1.d
        // For ECC (EC_v1), ensure that the signature is a valid ECDSA signature (ecdsa-with-SHA256 1.2.840.10045.4.3.2) of the concatenated values of the ephemeralPublicKey, data, transactionId, and applicationData keys.
        // For RSA (RSA_v1), ensure that the signature is a valid RSA signature (RSA-with-SHA256 1.2.840.113549.1.1.11) of the concatenated values of the wrappedKey, data, transactionId, and applicationData keys.
        $verifier = $this->signatureVerifierFactory->make($paymentData['version']);
        $verifier->verify($paymentData);

        // 1.e Inspect the CMS signing time of the signature, as defined by section 11.3 of RFC 5652. If the time signature and the transaction time differ by more than a few minutes, it's possible that the token is a replay attack.
        if (!$this->validateTime($signature, $signatureExpirationTime)) {
            throw new \RuntimeException('Signing time older than ' . $signatureExpirationTime . ' seconds');
        }

        return true;
    }

    /**
     * @param string $certificate
     * @param $oid
     * @return bool
     * @throws \RuntimeException
     */
    private function checkIfCertificateContainOID($certificate, $oid)
    {
        $extensions = $this->openSslService->getCertificateExtensions($certificate);
        if (!isset($extensions[$oid])) {
            throw new \RuntimeException('Missing OID ' . $oid . ' from certificate');
        }

        return true;
    }

    /**
     * @param array $certificates
     * @param string $caCertificatePath
     * @return bool
     * @throws \RuntimeException
     */
    private function validateChainOfTrust(array $certificates, $caCertificatePath)
    {
        $leafCertificateFile = $this->temporaryFileService->createFile($certificates[0]);
        $intermediateCertificateFile = $this->temporaryFileService->createFile($certificates[1]);

        return $this->openSslService->validateCertificateChain($caCertificatePath, $intermediateCertificateFile->getPath(), $leafCertificateFile->getPath());
    }

    /**
     * @param string $signature
     * @param $signatureExpirationTime
     * @return bool
     */
    private function validateTime($signature, $signatureExpirationTime)
    {
        $this->asn1Wrapper->loadFromString($signature);
        $signingTime = $this->asn1Wrapper->getSigningTime();

        $secondsElapsedSinceSigning = time() - strtotime($signingTime);

        return $secondsElapsedSinceSigning <= $signatureExpirationTime;
    }

    /**
     * @param string $signature
     * @return array
     * @throws \RuntimeException
     */
    private function extractCertificates($signature)
    {
        $pkcs7TemporaryFile = $this->temporaryFileService->createFile($signature);

        $certificates = $this->openSslService->getCertificatesFromPkcs7($pkcs7TemporaryFile->getPath());

        return explode("\n\n", $certificates); // the response contains 2 certificates; separate them into an array
    }

}