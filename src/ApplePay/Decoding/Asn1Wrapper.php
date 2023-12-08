<?php

namespace PayU\ApplePay\Decoding;

use phpseclib3\File\ASN1;

class Asn1Wrapper
{
    /** @var array */
    private $asn1;

    public function loadFromString($value): void
    {
        $this->asn1 = ASN1::decodeBER($value);
    }

    public function getSignature()
    {
        return $this->asn1[0]['content'][1]['content'][0]['content'][4]['content'][0]['content'][5]['content'];
    }

    public function getSignedAttributes(): string
    {
        $signedAttributes = $this->asn1[0]['content'][1]['content'][0]['content'][4]['content'][0]['content'][3]; // ['content'];
        $signedAttr = ASN1::asn1map($signedAttributes, ['type' => ASN1::TYPE_ANY, 'implicit' => true])->element;
        $signedAttr[0] = chr(0x31);

        return $signedAttr;
    }

    public function getDigestMessage()
    {
        $object = $this->asn1[0]['content'][1]['content'][0]['content'][4]['content'][0]['content'][3];

        return $object['content'][3]['content'][1]['content'][0]['content'];
    }

    public function getLeafCertificatePublicKey(): string
    {
        $content = $this->asn1[0]['content'][1]['content'][0]['content'][3] // certificates tag
        ['content'][0] // leaf certificate index
        ['content'][0] // cert_info tag
        ['content'][6]; // key tag, all contents, including headers

        $publicKey = ASN1::asn1map($content, ['type' => ASN1::TYPE_ANY, 'implicit' => true])->element;

        return trim($publicKey);
    }

    public function getSigningTime(): string
    {
        $timeAttribute = $this->asn1[0]['content'][1]['content'][0]['content'][4]['content'][0]['content'][3]['content'][1]['content'][1]['content'][0];

        return ASN1::asn1map($timeAttribute, ['type' => ASN1::TYPE_UTC_TIME]);
    }

}