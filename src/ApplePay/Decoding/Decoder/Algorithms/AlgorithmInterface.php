<?php

namespace PayU\ApplePay\Decoding\Decoder\Algorithms;

interface AlgorithmInterface
{

    public function getSecret($privateKey, $ephemeralPublicKey);

    public function getSymmetricKey($kdfInfo, $sharedSecret);

    public function decrypt($symmetricKey, $dataToDecode, $iv);

}