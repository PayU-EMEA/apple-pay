[![Travis CI](https://travis-ci.org/PayU-EMEA/apple-pay.svg)](https://travis-ci.org/PayU-EMEA/apple-pay) [![Latest Stable Version](https://poser.pugx.org/payu/apple-pay/v/stable.svg)](https://packagist.org/packages/payu/apple-pay) [![Total Downloads](https://poser.pugx.org/payu/apple-pay/downloads.svg)](https://packagist.org/packages/payu/apple-pay) [![License](https://poser.pugx.org/payu/apple-pay/license.svg)](https://packagist.org/packages/payu/apple-pay)


**Apple Pay Token Decoder**

This library is used to decode tokens for Apple Pay.

It takes a payment token data and returns an ApplePayPaymentData object.
ex:
```
class PayU\ApplePay\Decoding\ApplePayPaymentData#19 (9) {
  private $version =>
  int(1)
  private $applicationPrimaryAccountNumber =>
  string(16) "20427527000"
  private $applicationExpirationDate =>
  string(6) "190731"
  private $currencyCode =>
  string(3) "643"
  private $transactionAmount =>
  int(100000)
  private $deviceManufacturerIdentifier =>
  string(12) "050103073"
  private $paymentDataType =>
  string(8) "3DSecure"
  private $onlinePaymentCryptogram =>
  string(28) "Am+7lPDbobAGVT7hNAoABA=="
  private $eciIndicator =>
  NULL
}
```


**Install:**

Run `composer require payu/apple-pay`

**Usage:**

See https://github.com/PayU/apple-pay/blob/master/examples/decode_token.php

For more information about how Apple Pay tokens decoding works go to:
https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html

Only works on Linux hosts with openssl installed

For open pull requests please make sure the Travis build does not fail!
