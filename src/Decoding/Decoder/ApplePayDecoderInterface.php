<?php

namespace PayU\Decoding\Decoder;

interface ApplePayDecoderInterface
{
    /**
     * @param string $privateKey
     * @param string $merchantAppleId
     * @param array $paymentData
     * @return mixed
     */
    public function decode($privateKey, $merchantAppleId, array $paymentData);
}