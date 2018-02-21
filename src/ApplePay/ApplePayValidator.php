<?php

namespace PayU\ApplePay;

use PayU\ApplePay\Exception\InvalidFormatException;

class ApplePayValidator
{
    const REQUIRED_KEYS_PAYMENT_DATA = [
        'version',
        'data',
        'signature',
        'header' => [
            'ephemeralPublicKey', 'publicKeyHash', 'transactionId',
        ]
    ];

    /**
     * @param $input
     * @return bool
     * @throws \PayU\ApplePay\Exception\InvalidFormatException
     */
    public function validatePaymentDataStructure($input)
    {
        return $this->isValidStructure($input, self::REQUIRED_KEYS_PAYMENT_DATA);
    }


    /**
     * @param $input
     * @param array $format
     * @return bool
     * @throws InvalidFormatException
     */
    private function isValidStructure($input, array $format)
    {
        foreach ($format as $key => $value) {

            if (is_numeric($key)) {
                $key = $value;
            }
            if (!isset($input[$key])) {
                throw new InvalidFormatException('Parameter *' . $key . '* is missing', 400);
            }

            if (is_array($value)) {
                $this->isValidStructure($input[$key], $value);
            }
        }

        return true;
    }

}