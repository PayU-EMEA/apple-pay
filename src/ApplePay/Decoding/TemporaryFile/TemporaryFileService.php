<?php

namespace PayU\ApplePay\Decoding\TemporaryFile;


class TemporaryFileService
{
    public function __construct()
    {
    }

    /**
     * @param $initialContent
     * @return TemporaryFile
     */
    public function createFile($initialContent)
    {
        $file = new TemporaryFile();
        $file->write($initialContent);

        return $file;
    }

}