<?php

namespace Paperscissorsandglue\EncryptionAtRest;

use Illuminate\Contracts\Encryption\Encrypter;

class EncryptionService
{
    /**
     * The encrypter instance.
     *
     * @var \Illuminate\Contracts\Encryption\Encrypter
     */
    protected $encrypter;

    /**
     * Create a new encryption service instance.
     *
     * @param  \Illuminate\Contracts\Encryption\Encrypter  $encrypter
     * @return void
     */
    public function __construct(Encrypter $encrypter)
    {
        $this->encrypter = $encrypter;
    }

    /**
     * Encrypt the given value.
     *
     * @param  mixed  $value
     * @return string
     */
    public function encrypt($value)
    {
        return $this->encrypter->encrypt($value);
    }

    /**
     * Decrypt the given value.
     *
     * @param  string  $value
     * @return mixed
     */
    public function decrypt($value)
    {
        return $this->encrypter->decrypt($value);
    }
}
