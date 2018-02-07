<?php

namespace PayU\ApplePay\Decoding;

class PKCS7SignatureValidatorSettings
{
    const LEAF_CERTIFICATE_OID = '1.2.840.113635.100.6.29';
    const INTERMEDIATE_CERTIFICATE_OID = '1.2.840.113635.100.6.2.14';

    public function __construct()
    {

    }

    /**
     * @return string
     */
    public function getLeafCertificateOid()
    {
        return self::LEAF_CERTIFICATE_OID;
    }

    /**
     * @return string
     */
    public function getIntermediateCertificateOid()
    {
        return self::INTERMEDIATE_CERTIFICATE_OID;
    }

}