<?php

namespace PayU\ApplePay\Decoding;

use phpseclib\File\ASN1;

class Asn1Wrapper
{
    /** @var */
    private $asn1;

    /** @var */
    private $asn1Parser;

    public function __construct(ASN1 $asn1)
    {
        $this->asn1Parser = $asn1;
    }

    public function loadFromString($value) {
        $this->asn1 = $this->asn1Parser->decodeBER($value);
    }

    public function getSignature() {
        return $this->asn1[0]['content'][1]['content'][0]['content'][4]['content'][0]['content'][5]['content'];
    }

    public function getSignedAttributes() {
        $signedAttributes = $this->asn1[0]['content'][1]['content'][0]['content'][4]['content'][0]['content'][3]; // ['content'];
        $signedAttr = $this->asn1Parser->asn1map($signedAttributes, [
            'type' => ASN1::TYPE_ANY,
            'implicit' => true
        ])->element;
        $signedAttr[0] = chr(0x31);

        return $signedAttr;
    }

    public function getDigestMessage() {
        $object = $this->asn1[0]['content'][1]['content'][0]['content'][4]['content'][0]['content'][3];
        return $object['content'][3]['content'][1]['content'][0]['content'];
    }

    public function getLeafCertificatePublicKey() {
        $content = $this->asn1[0]['content'][1]['content'][0]['content'][3] // certificates tag
                        ['content'][0] // leaf certificate index
                        ['content'][0] // cert_info tag
                        ['content'][6]; // key tag, all contents, including headers

        $publicKey = $this->asn1Parser->asn1map($content, [
            'type' => ASN1::TYPE_ANY,
            'implicit' => true
        ])->element;

        return trim($publicKey);
    }

    /**
     * @return string
     */
    public function getSigningTime() {
        $timeAttribute = $this->asn1[0]['content'][1]['content'][0]['content'][4]['content'][0]['content'][3]['content'][1]['content'][1]['content'][0];
        $signTime = $this->asn1Parser->asn1map($timeAttribute, [
            'type' => ASN1::TYPE_UTC_TIME
        ]);

        return $signTime;
    }

}