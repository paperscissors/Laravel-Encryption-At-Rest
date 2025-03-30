<?php

namespace Paperscissorsandglue\GdprLaravel;

use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Facades\Config;

class EncryptionAtRestEncrypter extends Encrypter
{
    /**
     * Create a new encrypter instance.
     *
     * @return void
     */
    public function __construct()
    {
        $key = Config::get('encryption-at-rest.encryption_key') ?: Config::get('app.key');
        
        if (strpos($key, 'base64:') === 0) {
            $key = base64_decode(substr($key, 7));
        }
        
        parent::__construct($key, Config::get('encryption-at-rest.cipher'));
    }
}