**Apple Pay Token Decoder**

This library is used to decode tokens for Apple Pay.

It takes a payment token data and returns an ApplePayPaymentData object.
ex:
```
class PayU\ApplePay\Decoding\ApplePayPaymentData#19 (9) {
  private $version =>
  int(1)
  private $applicationPrimaryAccountNumber =>
  string(16) "5204242750270010"
  private $applicationExpirationDate =>
  string(6) "190731"
  private $currencyCode =>
  string(3) "643"
  private $transactionAmount =>
  int(100000)
  private $deviceManufacturerIdentifier =>
  string(12) "050110030273"
  private $paymentDataType =>
  string(8) "3DSecure"
  private $onlinePaymentCryptogram =>
  string(28) "AOm+7lPDSbobAGVT7hmNAoABFA=="
  private $eciIndicator =>
  NULL
}
```


**Install:**

Run `composer require payu/apple-pay` (not final)

**Usage:**

See https://github.com/PayU/apple-pay/blob/master/examples/decode_token.php

For more information about how Apple Pay tokens decoding works go to:
https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html
