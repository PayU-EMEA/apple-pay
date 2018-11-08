<?php

namespace PayU\ApplePay\Decoding\OpenSSL;

use PayU\ApplePay\Decoding\SignatureVerifier\Exception\SignatureException;

class OpenSslService
{

    public function __construct()
    {

    }

    /**
     * @param string $caCertificatePath
     * @param string $intermediateCertificatePath
     * @param string $leafCertificatePath
     * @return bool
     * @throws \RuntimeException
     */
    public function validateCertificateChain($caCertificatePath, $intermediateCertificatePath, $leafCertificatePath) {
        $verifyCertificateCommand = 'openssl verify -CAfile ' . $caCertificatePath . ' -untrusted ' . $intermediateCertificatePath . ' ' . $leafCertificatePath;

        $verifyStatus = null;
        $verifyOutput = null;
        exec($verifyCertificateCommand, $verifyOutput, $verifyStatus);

        if ($verifyStatus !== 0) {
            throw new \RuntimeException(implode(' *** ', $verifyOutput));
        }

        return true;
    }

    /**
     * @param $signedAttributes
     * @param $signature
     * @param $publicKey
     * @return bool
     * @throws SignatureException
     */
    public function verifySignature($signedAttributes, $signature, $publicKey) {
        $verifyResult = openssl_verify($signedAttributes, $signature, $publicKey, OPENSSL_ALGO_SHA256);

        if ($verifyResult === 1) {
            return true;
        }

        if ($verifyResult === -1) {
            throw new SignatureException(openssl_error_string());
        }

        throw new SignatureException('Invalid signature');
    }

    /**
     * @param $certificatePath
     * @return string
     * @throws \RuntimeException
     */
    public function getCertificatesFromPkcs7($certificatePath) {
        $getCertificatesCommand = 'openssl pkcs7 -inform DER -in ' . $certificatePath . ' -print_certs';

        $commandStatus = null;
        $commandOutput = null;
        exec($getCertificatesCommand, $commandOutput, $commandStatus);

        if ($commandStatus !== 0) {
            if(empty($commandOutput)) {
                throw new \RuntimeException('Openssl command failed. Is OpenSsl installed?');
            }

            throw new \RuntimeException(implode(' *** ', $commandOutput));
        }

        return trim(implode(PHP_EOL, $commandOutput));
    }

    /**
     * @param $certificate
     * @return mixed
     * @throws \RuntimeException
     */
    public function getCertificateExtensions($certificate) {
        $certificateResource = @openssl_x509_read($certificate);

        if(empty($certificateResource)) {
            throw new \RuntimeException("Can't load x509 certificate");
        }
        $certificateData = openssl_x509_parse($certificateResource, false);
        return $certificateData['extensions'];
    }

    /**
     * @param $privateKeyFilePath
     * @param $publicKeyFilePath
     * @return null
     * @throws \RuntimeException
     */
    public function deriveKey($privateKeyFilePath, $publicKeyFilePath) {
        // note: use base64 encoding for binary safe output
        $command = 'openssl pkeyutl -derive -inkey '.$privateKeyFilePath.' -peerkey '.$publicKeyFilePath . ' | base64 -w 0';

        $execStatus = null;
        $execOutput = null;
        exec($command, $execOutput, $execStatus);

        if ($execStatus !== 0) {
            throw new \RuntimeException("Can't derive secret");
        }

        if (empty($execOutput)) {
            throw new \RuntimeException("Unexpected empty result");
        }

        return base64_decode($execOutput[0]);
    }

}
