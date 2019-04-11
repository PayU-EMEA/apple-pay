<?php

namespace PayU\ApplePay\Decoding\OpenSSL;

use PayU\ApplePay\Decoding\SignatureVerifier\Exception\SignatureException;

class OpenSslService
{
    /**
     * @param string $caCertificatePath
     * @param string $intermediateCertificatePath
     * @param string $leafCertificatePath
     * @return bool
     * @throws \RuntimeException
     */
    public function validateCertificateChain($caCertificatePath, $intermediateCertificatePath, $leafCertificatePath) {
        $verifyCertificateCommand = 'openssl verify -CAfile ' . escapeshellarg($caCertificatePath) . ' -untrusted ' . escapeshellarg($intermediateCertificatePath) . ' ' . escapeshellarg($leafCertificatePath);

        list($verifyStatus) = $this->runCommand($verifyCertificateCommand);

        if ($verifyStatus !== 0) {
            throw new \RuntimeException("Can't validate certificate chain");
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
        $getCertificatesCommand = 'openssl pkcs7 -inform DER -in ' . escapeshellarg($certificatePath) . ' -print_certs';

        list($commandStatus, $commandOutput) = $this->runCommand($getCertificatesCommand);

        if ($commandStatus !== 0) {
            throw new \RuntimeException("Cant't get certificates");
        }

        return rtrim($commandOutput);
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
        $command = 'openssl pkeyutl -derive -inkey '.escapeshellarg($privateKeyFilePath).' -peerkey '.escapeshellarg($publicKeyFilePath);

        list($execStatus, $execOutput) = $this->runCommand($command);

        if ($execStatus !== 0) {
            throw new \RuntimeException("Can't derive secret");
        }

        if (empty($execOutput)) {
            throw new \RuntimeException("Unexpected empty result");
        }

        return $execOutput;
    }

    private function runCommand($command)
    {
        $descriptorspec = [
            1 => ["pipe", "w"],
            2 => ["file", "/dev/null", "a"]
        ];

        $process = proc_open($command, $descriptorspec, $pipes);

        if (!is_resource($process)) {
            throw new \RuntimeException("Unable to invoke openssl");
        }

        $execOutput = stream_get_contents($pipes[1]);
        fclose($pipes[1]);

        $execStatus = proc_close($process);

        return [$execStatus, $execOutput];
    }
}
