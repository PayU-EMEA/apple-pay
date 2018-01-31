<?php

namespace PayU\Decoding\SignatureVerifier;

use DI\Container;
use Exception;

class SignatureVerifierFactory
{
    const ECC = 'EC_v1';
    const RSA = 'rsa';

    /** @var Container */
    private $container;

    public function __construct(Container $container)
    {
        $this->container = $container;
    }

    /**
     * @param $version
     * @return mixed|EccSignatureVerifier
     * @throws Exception
     * @throws \Interop\Container\Exception\ContainerException
     * @throws \Interop\Container\Exception\NotFoundException
     */
    public function make($version)
    {
        switch ($version) {
            case self::ECC:
                return $this->container->get(EccSignatureVerifier::class);
            case self::RSA:
                throw new Exception('Unsupported type ' . $version);
            default:
                throw new Exception('Unknown type ' . $version);
        }
    }
}