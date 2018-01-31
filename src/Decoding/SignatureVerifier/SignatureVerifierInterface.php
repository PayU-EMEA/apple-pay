<?php

namespace PayU\Decoding\SignatureVerifier;

interface SignatureVerifierInterface
{
    public function verify(array $paymentData);
}