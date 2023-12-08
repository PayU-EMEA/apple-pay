<?php

namespace PayU\ApplePay;

use PayU\ApplePay\Decoding\ApplePayDecodingService;
use PayU\ApplePay\Decoding\Asn1Wrapper;
use PayU\ApplePay\Decoding\Decoder\ApplePayDecoderFactory;
use PayU\ApplePay\Decoding\OpenSSL\OpenSslService;
use PayU\ApplePay\Decoding\PKCS7SignatureValidator;
use PayU\ApplePay\Decoding\PKCS7SignatureValidatorSettings;
use PayU\ApplePay\Decoding\SignatureVerifier\SignatureVerifierFactory;
use PayU\ApplePay\Decoding\TemporaryFile\TemporaryFileService;

class ApplePayDecodingServiceFactory
{
    /**
     * @return ApplePayDecodingService
     */
    public function make()
    {
        $decoderFactory = new ApplePayDecoderFactory();
        $signatureVerifierFactory = new SignatureVerifierFactory();
        $asn1Wrapper = new Asn1Wrapper();
        $temporaryFileService = new TemporaryFileService();
        $openSslService = new OpenSslService();
        $pkcs7SignatureValidatorSettings = new PKCS7SignatureValidatorSettings();
        $pkcs7SignatureValidator = new PKCS7SignatureValidator($signatureVerifierFactory, $asn1Wrapper, $temporaryFileService, $openSslService, $pkcs7SignatureValidatorSettings);

        return new ApplePayDecodingService($decoderFactory, $pkcs7SignatureValidator);
    }

}