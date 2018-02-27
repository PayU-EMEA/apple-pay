<?php

namespace PayU\ApplePay;

use PayU\ApplePay\Exception\InvalidFormatException;

class ApplePayValidatorTest extends \PHPUnit_Framework_TestCase
{
    /** @var ApplePayValidator */
    private $applePayValidator;

    public function setUp()
    {
        $this->applePayValidator = new ApplePayValidator();
    }

    public function testValidatePaymentDataStructureSuccess()
    {
        $paymentData = [
            'version' => 'v1',
            'data' => 'dummy data',
            'signature' => 'dummy signature',
            'header' => [
                'ephemeralPublicKey' => 'key',
                'publicKeyHash' => 'dummy hash',
                'transactionId' => 3
            ]
        ];

        $isValid = $this->applePayValidator->validatePaymentDataStructure($paymentData);

        $this->assertEquals(true, $isValid);
    }


    public function testValidatePaymentWhenVersionMissing()
    {
        $paymentData = [
            'data' => 'dummy data',
            'signature' => 'dummy signature',
            'header' => [
                'ephemeralPublicKey' => 'key',
                'publicKeyHash' => 'dummy hash',
                'transactionId' => 3
            ]
        ];

        $this->expectException(InvalidFormatException::class);
        $this->expectExceptionMessage("Parameter *version* is missing");

        $this->applePayValidator->validatePaymentDataStructure($paymentData);
    }

    public function testValidatePaymentWhenDataMissing()
    {
        $paymentData = [
            'version' => 'v1',
            'signature' => 'dummy signature',
            'header' => [
                'ephemeralPublicKey' => 'key',
                'publicKeyHash' => 'dummy hash',
                'transactionId' => 3
            ]
        ];

        $this->expectException(InvalidFormatException::class);
        $this->expectExceptionMessage("Parameter *data* is missing");

        $this->applePayValidator->validatePaymentDataStructure($paymentData);
    }

    public function testValidatePaymentWhenSignatureMissing()
    {
        $paymentData = [
            'version' => 'v1',
            'data' => 'dummy data',
            'header' => [
                'ephemeralPublicKey' => 'key',
                'publicKeyHash' => 'dummy hash',
                'transactionId' => 3
            ]
        ];

        $this->expectException(InvalidFormatException::class);
        $this->expectExceptionMessage("Parameter *signature* is missing");

        $this->applePayValidator->validatePaymentDataStructure($paymentData);
    }

    public function testValidatePaymentWhenPublicKeyMissing()
    {
        $paymentData = [
            'version' => 'v1',
            'data' => 'dummy data',
            'signature' => 'dummy signature',
            'header' => [
                'publicKeyHash' => 'dummy hash',
                'transactionId' => 3
            ]
        ];

        $this->expectException(InvalidFormatException::class);
        $this->expectExceptionMessage("Parameter *ephemeralPublicKey* is missing");

        $this->applePayValidator->validatePaymentDataStructure($paymentData);
    }

    public function testValidatePaymentWhenPublicKeyHashMissing()
    {
        $paymentData = [
            'version' => 'v1',
            'data' => 'dummy data',
            'signature' => 'dummy signature',
            'header' => [
                'ephemeralPublicKey' => 'key',
                'transactionId' => 3
            ]
        ];

        $this->expectException(InvalidFormatException::class);
        $this->expectExceptionMessage("Parameter *publicKeyHash* is missing");

        $this->applePayValidator->validatePaymentDataStructure($paymentData);
    }

    public function testValidatePaymentWhenTransactionIdMissing()
    {
        $paymentData = [
            'version' => 'v1',
            'data' => 'dummy data',
            'signature' => 'dummy signature',
            'header' => [
                'ephemeralPublicKey' => 'key',
                'publicKeyHash' => 'dummy hash',
            ]
        ];

        $this->expectException(InvalidFormatException::class);
        $this->expectExceptionMessage("Parameter *transactionId* is missing");

        $this->applePayValidator->validatePaymentDataStructure($paymentData);
    }

    public function testValidatePaymentWhenHeaderMissing()
    {
        $paymentData = [
            'version' => 'v1',
            'data' => 'dummy data',
            'signature' => 'dummy signature',
        ];

        $this->expectException(InvalidFormatException::class);
        $this->expectExceptionMessage("Parameter *header* is missing");

        $this->applePayValidator->validatePaymentDataStructure($paymentData);
    }


}
