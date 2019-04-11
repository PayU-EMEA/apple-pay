<?php

namespace PayU\ApplePay\Decoding\SignatureVerifier;

use PayU\ApplePay\Decoding\Asn1Wrapper;
use PayU\ApplePay\Decoding\OpenSSL\OpenSslService;
use PayU\ApplePay\Decoding\SignatureVerifier\Exception\SignatureException;

class EccSignatureVerifier implements SignatureVerifierInterface
{

    /** @var Asn1Wrapper */
    private $asn1Wrapper;

    /** @var OpenSslService */
    private $openSslService;

    /**
     * EccSignatureVerifier constructor.
     * @param Asn1Wrapper $asn1Wrapper
     * @param OpenSslService $openSslService
     */
    public function __construct(Asn1Wrapper $asn1Wrapper, OpenSslService $openSslService)
    {
        $this->asn1Wrapper = $asn1Wrapper;
        $this->openSslService = $openSslService;
    }

    /**
     * @param array $paymentData
     * @return bool
     * @throws SignatureException
     */
    public function verify(array $paymentData)
    {
        $signedData = base64_decode($paymentData['header']['ephemeralPublicKey']) . base64_decode($paymentData['data']) . hex2bin($paymentData['header']['transactionId']);
        $signedHash = hash('sha256', $signedData, true);

        $this->asn1Wrapper->loadFromString(base64_decode($paymentData['signature']));

        if (!hash_equals($signedHash, $this->asn1Wrapper->getDigestMessage())) {
            throw new SignatureException('Invalid digest');
        }

        $leafPublicKey = $this->asn1Wrapper->getLeafCertificatePublicKey();
        $pemFormattedPublicKey = '-----BEGIN PUBLIC KEY-----' . PHP_EOL . chunk_split(base64_encode($leafPublicKey), 64, PHP_EOL) . '-----END PUBLIC KEY-----';

        return $this->openSslService->verifySignature($this->asn1Wrapper->getSignedAttributes(), $this->asn1Wrapper->getSignature(), $pemFormattedPublicKey);
    }
}