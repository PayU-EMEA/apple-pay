<?php

namespace PayU\ApplePay\Decoding;

use PayU\ApplePay\Decoding\Decoder\Algorithms\Ecc;
use PayU\ApplePay\Decoding\OpenSSL\OpenSslService;
use PayU\ApplePay\Decoding\TemporaryFile\TemporaryFileService;
use PHPUnit_Framework_MockObject_MockObject;

class EccTest extends \PHPUnit_Framework_TestCase
{
    /** @var PHPUnit_Framework_MockObject_MockObject|TemporaryFileService */
    private $temporaryFileServiceMock;

    /** @var PHPUnit_Framework_MockObject_MockObject|OpenSslService */
    private $openSslServiceMock;

    /** @var PHPUnit_Framework_MockObject_MockObject|Ecc */
    private $ecc;

    private $validSymmetricKey = 'EjMmct+Bd2UW9JHRFqjpP0SeuQduS9gtUq98SKNWZl8='; // base64 encoded.
    private $validKdfInfo = 'DWlkLWFlczI1Ni1HQ01BcHBsZS2ZQOrgftlEvydwh/tmGzbBP+ggEJpR0YQJKly5JbhE'; // base64 encoded
    private $validIV = '00000000000000000000000000000000';
    private $validEncryptedData = 'fkKI2Qyp9UpeiYDBnv5h4XYAKTVvpcXszwtU9Gojv8UThuDgCkQnWW/x15ce71IqR3CmtCttjECagbl270ND0FqALusWNYBobmPj8c9z/jZhfFw2frxZXVirKpzMX6qEEzFf0JDhMo9CT9ukLGJvg/8c0j5S9xSLMjgiszRVht0kxKGh6QblE58rSXagcdihtbJgPORTRJ13kNIMqqGOpGhpUFgVF3h4LAwoYozhxK4K4nunNjPVP9g0BePBgGiBq1Dh4yriOxbQQDtFy6/CQ9zZSZbMtuyZK7uFZ+FPp8K48b8xKaq+cQR5YJxC2lxKgI+W5GHIL9foPKPGBaZqOnZ14VYBtTxmps0jdjE5HvWqecLgFKs6PHdTf/3uYY7i1zCM9tcTYgBFlXzdVI4iVYfmLJiPlM2n0xjs8PPldyU='; // base64 encoded
    private $decryptedData = '{"applicationPrimaryAccountNumber":"4818528840010767","applicationExpirationDate":"231231","currencyCode":"643","transactionAmount":1000,"deviceManufacturerIdentifier":"040010030273","paymentDataType":"3DSecure","paymentData":{"onlinePaymentCryptogram":"Ao/fzpIAFvp1eB9y8WVDMAACAAA=","eciIndicator":"7"}}';

    public function setUp()
    {
        $this->temporaryFileServiceMock = $this->getMockBuilder(TemporaryFileService::class)
            ->disableOriginalConstructor()
            ->getMock();

        $this->openSslServiceMock = $this->getMockBuilder(OpenSslService::class)
            ->disableOriginalConstructor()
            ->getMock();

        $this->ecc = new Ecc($this->temporaryFileServiceMock, $this->openSslServiceMock);

    }

    public function testGetSymmetricKeyComputesTheKeyCorrectly() {
        $sharedSecret = '864c96ba0f009524bb36bf5f4754dca0358ef4d6e270b3ae8bb45736c9006177';

        $actualSymmetricKey = $this->ecc->getSymmetricKey(base64_decode($this->validKdfInfo), $sharedSecret);

        $this->assertEquals(base64_decode($this->validSymmetricKey), $actualSymmetricKey);

    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Shared secret is not a valid hex value
     */
    public function testGetSymmetricKeyThrowsExceptionOnInvalidSharedSecret() {
        $kdfInfoBase64Encoded = base64_decode($this->validKdfInfo);
        $sharedSecret = 'invalid shared secret';

        $this->ecc->getSymmetricKey(base64_decode($kdfInfoBase64Encoded), $sharedSecret);
    }

    public function testDecryptSuccess() {
        $actualDecryptedData = $this->ecc->decrypt(base64_decode($this->validSymmetricKey), base64_decode($this->validEncryptedData), $this->validIV);

        $this->assertEquals($this->decryptedData, $actualDecryptedData);
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage IV is not a valid hex value
     */
    public function testDecryptThrowsExceptionOnInvalidIV() {
        $invalidIV = 'dummy data';
        $this->ecc->decrypt(base64_decode($this->validSymmetricKey), base64_decode($this->validEncryptedData), $invalidIV);
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Unable to decrypt or to verify the tag.
     */
    public function testDecryptThrowsExceptionIfEncryptedMessageIsNotValid() {
        $invalidEncryptedData = 'invalid message';
        $this->ecc->decrypt(base64_decode($this->validSymmetricKey), $invalidEncryptedData, $this->validIV);
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testDecryptThrowsExceptionIfSymmetricKeyIsNotValid() {
        $invalidSymmetricKey = 'invalid key';
        $this->ecc->decrypt($invalidSymmetricKey, base64_decode($this->validEncryptedData), $this->validIV);
    }

}
