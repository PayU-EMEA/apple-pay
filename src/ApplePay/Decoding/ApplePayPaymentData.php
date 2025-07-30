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

    /** @var string|null */
    private $merchantTokenIdentifier;

    /** @var array|null */
    private $merchantTokenMetadata;

    public function __construct(
        $applicationPrimaryAccountNumber,
        $applicationExpirationDate,
        $currencyCode,
        $transactionAmount,
        $deviceManufacturerIdentifier,
        $paymentDataType,
        $onlinePaymentCryptogram,
        $eciIndicator,
        $version,
        $merchantTokenIdentifier = null,
        $merchantTokenMetadata = null
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
        $this->merchantTokenIdentifier = $merchantTokenIdentifier;
        $this->merchantTokenMetadata = $merchantTokenMetadata;
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

    /**
     * @return string|null
     */
    public function getMerchantTokenIdentifier()
    {
        return $this->merchantTokenIdentifier;
    }

    /**
     * @return array|null
     */
    public function getMerchantTokenMetadata()
    {
        return $this->merchantTokenMetadata;
    }

    /**
     * Get card metadata from merchant token metadata
     * @return array|null
     */
    public function getCardMetadata()
    {
        return isset($this->merchantTokenMetadata['cardMetadata'])
            ? $this->merchantTokenMetadata['cardMetadata']
            : null;
    }

    /**
     * Get card art from merchant token metadata
     * @return array|null
     */
    public function getCardArt()
    {
        return isset($this->merchantTokenMetadata['cardArt'])
            ? $this->merchantTokenMetadata['cardArt']
            : null;
    }

    /**
     * Get card country from card metadata
     * @return string|null
     */
    public function getCardCountry()
    {
        $cardMetadata = $this->getCardMetadata();
        return isset($cardMetadata['cardCountry']) ? $cardMetadata['cardCountry'] : null;
    }

    /**
     * Get short description from card metadata
     * @return string|null
     */
    public function getShortDescription()
    {
        $cardMetadata = $this->getCardMetadata();
        return isset($cardMetadata['shortDescription']) ? $cardMetadata['shortDescription'] : null;
    }

    /**
     * Get FPAN suffix from card metadata
     * @return string|null
     */
    public function getFpanSuffix()
    {
        $cardMetadata = $this->getCardMetadata();
        return isset($cardMetadata['fpanSuffix']) ? $cardMetadata['fpanSuffix'] : null;
    }

}
