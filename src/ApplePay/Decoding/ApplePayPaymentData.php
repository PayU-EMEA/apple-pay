<?php

namespace PayU\ApplePay\Decoding;

class ApplePayPaymentData
{
    /** @var string */
    private $version;

    /** @var string */
    private $applicationPrimaryAccountNumber;

    /** @var string */
    private $applicationExpirationDate;

    /** @var string */
    private $currencyCode;

    /** @var string */
    private $transactionAmount;

    /** @var string */
    private $deviceManufacturerIdentifier;

    /** @var string */
    private $paymentDataType;

    /** @var string */
    private $onlinePaymentCryptogram;

    /** @var string */
    private $eciIndicator;

    public function __construct(
        $applicationPrimaryAccountNumber,
        $applicationExpirationDate,
        $currencyCode,
        $transactionAmount,
        $deviceManufacturerIdentifier,
        $paymentDataType,
        $onlinePaymentCryptogram,
        $eciIndicator,
        $version
    )
    {
        $this->applicationPrimaryAccountNumber = $applicationPrimaryAccountNumber;
        $this->applicationExpirationDate = $applicationExpirationDate;
        $this->currencyCode = $currencyCode;
        $this->transactionAmount = $transactionAmount;
        $this->deviceManufacturerIdentifier = $deviceManufacturerIdentifier;
        $this->paymentDataType = $paymentDataType;
        $this->onlinePaymentCryptogram = $onlinePaymentCryptogram;
        $this->eciIndicator = $eciIndicator;
        $this->version = $version;
    }

    /**
     * @return string
     */
    public function getVersion()
    {
        return $this->version;
    }

    /**
     * @return string
     */
    public function getApplicationPrimaryAccountNumber()
    {
        return $this->applicationPrimaryAccountNumber;
    }

    /**
     * @return string
     */
    public function getApplicationExpirationDate()
    {
        return $this->applicationExpirationDate;
    }

    /**
     * @return string
     */
    public function getCurrencyCode()
    {
        return $this->currencyCode;
    }

    /**
     * @return string
     */
    public function getTransactionAmount()
    {
        return $this->transactionAmount;
    }

    /**
     * @return string
     */
    public function getDeviceManufacturerIdentifier()
    {
        return $this->deviceManufacturerIdentifier;
    }

    /**
     * @return string
     */
    public function getPaymentDataType()
    {
        return $this->paymentDataType;
    }

    /**
     * @return string
     */
    public function getOnlinePaymentCryptogram()
    {
        return $this->onlinePaymentCryptogram;
    }

    /**
     * @return string
     */
    public function getEciIndicator()
    {
        return $this->eciIndicator;
    }

}