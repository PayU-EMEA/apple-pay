<?php

namespace PayU\ApplePay\Decoding\TemporaryFile;


class TemporaryFile
{
    /** @var resource */
    private $fileHandle;

    /**
     * TemporaryFile constructor.
     */
    public function __construct()
    {
        $this->fileHandle = tmpfile();
    }

    /**
     * @return string
     */
    public function getPath()
    {
        $fileMetadata = stream_get_meta_data($this->fileHandle);

        return $fileMetadata['uri'];
    }

    /**
     * @param string $content
     */
    public function write($content)
    {
        fwrite($this->fileHandle, $content);
    }

}