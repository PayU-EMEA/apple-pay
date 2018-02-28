<?php

namespace PayU\ApplePay\Decoding;

use PayU\ApplePay\Decoding\Decoder\ApplePayDecoderFactory;
use PayU\ApplePay\Exception\DecodingFailedException;
use PayU\ApplePay\Exception\InvalidFormatException;

class ApplePayDecodingService
{
    /** @var ApplePayDecoderFactory */
    private $applePayDecoderFactory;

    /** @var PKCS7SignatureValidator */
    private $PKCS7SignatureValidator;

    public function __construct(ApplePayDecoderFactory $applePayDecoderFactory, PKCS7SignatureValidator $PKCS7SignatureValidator)
    {
        $this->applePayDecoderFactory = $applePayDecoderFactory;
        $this->PKCS7SignatureValidator = $PKCS7SignatureValidator;
    }

    /**
     * @param $privateKey - the key used by PayU for generating the CSR. just the private key, no other formatting options: MHcCAQEEI.....8v8v1nMtag==
     * @param $merchantAppleId - hex value taken from Payment Processing Certificate, OID 1.2.840.113635.100.6.32 ex: 2D9940....5B844
     * @param array $paymentData - paymentData node from the token
     * @param $applePayRootCertificatePath
     * @param $tokenSignatureExpirationTime
     * @return ApplePayPaymentData
     * @throws DecodingFailedException
     * @throws InvalidFormatException
     */
    public function decode($privateKey, $merchantAppleId, array $paymentData, $applePayRootCertificatePath, $tokenSignatureExpirationTime)
    {
        try {
            $decoder = $this->applePayDecoderFactory->make($paymentData['version']);
            $this->PKCS7SignatureValidator->validate($paymentData, $applePayRootCertificatePath, $tokenSignatureExpirationTime);
        } catch (\Exception $e) {
            throw new DecodingFailedException($e->getMessage(), $e->getCode(), $e);
        }

        return $decoder->decode($privateKey, $merchantAppleId, $paymentData);
    }

}