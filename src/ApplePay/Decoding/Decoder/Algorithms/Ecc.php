<?php

namespace PayU\ApplePay\Decoding\Decoder\Algorithms;

use AESGCM\AESGCM;
use Exception;
use PayU\ApplePay\Decoding\OpenSSL\OpenSslService;
use PayU\ApplePay\Decoding\TemporaryFile\TemporaryFileService;

class Ecc implements AlgorithmInterface
{
    /** @var TemporaryFileService */
    private $temporaryFileService;

    /** @var OpenSslService */
    private $openSslService;

    public function __construct(TemporaryFileService $temporaryFileService, OpenSslService $openSslService)
    {
        $this->temporaryFileService = $temporaryFileService;
        $this->openSslService = $openSslService;
    }

    /**
     * @param $privateKey
     * @param $ephemeralPublicKey
     * @return string
     * @throws \RuntimeException
     */
    public function getSecret($privateKey, $ephemeralPublicKey) {
        $publickeyData = $this->formatKey($ephemeralPublicKey, 'PUBLIC KEY');
        $temporaryPublicKeyFile = $this->temporaryFileService->createFile($publickeyData);

        $privateKeyData = $this->formatKey($privateKey, 'EC PRIVATE KEY');
        $temporaryPrivateKeyFile = $this->temporaryFileService->createFile($privateKeyData);

        $key = $this->openSslService->deriveKey($temporaryPrivateKeyFile->getPath(), $temporaryPublicKeyFile->getPath());

        return bin2hex($key);
    }

    /**
     * @param $kdfInfo
     * @param $sharedSecret
     * @return string
     * @throws \RuntimeException
     */
    public function getSymmetricKey($kdfInfo, $sharedSecret) {

        $sharedSecretBin = @hex2bin($sharedSecret);

        if($sharedSecretBin === false) {
            throw new \RuntimeException('Shared secret is not a valid hex value');
        }

        $hashRes = hash_init('sha256');
        hash_update ( $hashRes, base64_decode('AAAA'));
        hash_update ( $hashRes, base64_decode('AQ=='));
        hash_update ( $hashRes, $sharedSecretBin);
        hash_update ( $hashRes, $kdfInfo);

        return hash_final( $hashRes, true);
    }

    /**
     * @param $symmetricKey
     * @param $dataToDecode
     * @param $iv
     * @return string
     * @throws \RuntimeException
     */
    public function decrypt($symmetricKey, $dataToDecode, $iv) {
        $ivBinary = @hex2bin($iv);

        if($ivBinary === false) {
            throw new \RuntimeException('IV is not a valid hex value');
        }

        try {
            $data = AESGCM::decryptWithAppendedTag($symmetricKey, $ivBinary, $dataToDecode);
        } catch(Exception $e) {
            throw new \RuntimeException($e->getMessage());
        }

        return $data;
    }

    /**
     * @param $key
     * @param $type
     * @return string
     */
    private function formatKey($key, $type)
    {
        $formattedData = '-----BEGIN ' . $type . '-----' . PHP_EOL;
        $formattedData .= chunk_split($key, 64);
        $formattedData .= '-----END ' . $type . '-----' . PHP_EOL;

        return $formattedData;
    }
}