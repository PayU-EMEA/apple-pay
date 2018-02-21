<?php

namespace PayU\ApplePay\Decoding\Decoder;

use InvalidArgumentException;
use PayU\ApplePay\Decoding\ApplePayPaymentData;
use PayU\ApplePay\Decoding\Decoder\Algorithms\Ecc;
use PayU\ApplePay\Exception\DecodingFailedException;

class ApplePayEccDecoder implements ApplePayDecoderInterface
{

    const IV = '00000000000000000000000000000000';
    const CYPHER = 'id-aes256-GCM';

    /** @var Ecc */
    private $ecc;

    public function __construct(Ecc $ecc)
    {
        $this->ecc = $ecc;
    }

    /**
     * @param string $privateKey
     * @param string $merchantAppleId
     * @param array $paymentData
     * @return ApplePayPaymentData
     * @throws DecodingFailedException
     */
    public function decode($privateKey, $merchantAppleId, array $paymentData)
    {
        try {
            $sharedSecret = $this->ecc->getSecret($privateKey, $paymentData['header']['ephemeralPublicKey']);

            $kdfInfo = $this->getKdfInfo($merchantAppleId);
            $symmetricKey = $this->ecc->getSymmetricKey($kdfInfo, $sharedSecret);

            $decodedText = $this->ecc->decrypt($symmetricKey, base64_decode($paymentData['data']), self::IV);

            return $this->createPaymentData($decodedText);
        } catch (\Exception $e) {
            throw new DecodingFailedException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * @param $merchantAppleId
     * @return string
     */
    private function getKdfInfo($merchantAppleId)
    {
        return chr(0x0D) . self::CYPHER . 'Apple' . hash('sha256', trim($merchantAppleId), true);
    }

    /**
     * @param $decodedText
     * @return ApplePayPaymentData
     * @throws InvalidArgumentException
     */
    private function createPaymentData($decodedText)
    {
        $decodedData = json_decode($decodedText, true);

        if (null === $decodedData) {
            throw new InvalidArgumentException('Invalid decoded text.');
        }

        return new ApplePayPaymentData(
            $decodedData['applicationPrimaryAccountNumber'],
            $decodedData['applicationExpirationDate'],
            $decodedData['currencyCode'],
            $decodedData['transactionAmount'],
            $decodedData['deviceManufacturerIdentifier'],
            $decodedData['paymentDataType'],
            $decodedData['paymentData']['onlinePaymentCryptogram'],
            isset($decodedData['paymentData']['eciIndicator']) ? $decodedData['paymentData']['eciIndicator'] : null,
            1
        );
    }
}