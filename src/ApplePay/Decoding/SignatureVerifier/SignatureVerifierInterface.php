<?php

namespace PayU\ApplePay\Decoding\SignatureVerifier;

interface SignatureVerifierInterface
{
    public function verify(array $paymentData);
}