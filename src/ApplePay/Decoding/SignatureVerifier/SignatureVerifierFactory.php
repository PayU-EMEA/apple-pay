<?php

namespace PayU\ApplePay\Decoding\SignatureVerifier;

use Exception;
use PayU\ApplePay\Decoding\Asn1Wrapper;
use PayU\ApplePay\Decoding\OpenSSL\OpenSslService;
use phpseclib\File\ASN1;

class SignatureVerifierFactory
{
    const ECC = 'EC_v1';
    const RSA = 'rsa';

    public function __construct()
    {
    }

    /**
     * @param $version
     * @return mixed|EccSignatureVerifier
     * @throws Exception
     */
    public function make($version)
    {
        switch ($version) {
            case self::ECC:
                $asn1 = new ASN1();
                $asn1Wrapper = new Asn1Wrapper($asn1);
                $openSslService = new OpenSslService();
                return new EccSignatureVerifier($asn1Wrapper, $openSslService);
            case self::RSA:
                throw new \RuntimeException('Unsupported type ' . $version);
            default:
                throw new \RuntimeException('Unknown type ' . $version);
        }
    }
}