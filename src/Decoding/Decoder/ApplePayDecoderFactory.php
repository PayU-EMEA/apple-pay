<?php

namespace PayU\Decoding\Decoder;

use DI\Container;
use Interop\Container\Exception\NotFoundException;
use Interop\Container\Exception\ContainerException;

class ApplePayDecoderFactory
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
     * @return mixed|ApplePayEccDecoder
     * @throws \RuntimeException
     */
    public function make($version)
    {
        switch ($version) {
            case self::ECC:
                try {
                    return $this->container->get(ApplePayEccDecoder::class);
                } catch (ContainerException $e) {
                    throw new \RuntimeException($e->getMessage(), $e->getCode(), $e);
                } catch (NotFoundException $e) {
                    throw new \RuntimeException($e->getMessage(), $e->getCode(), $e);
                }
            case self::RSA:
                throw new \RuntimeException('Unsupported type ' . $version);
            default:
                throw new \RuntimeException('Unknown type ' . $version);
        }
    }
}