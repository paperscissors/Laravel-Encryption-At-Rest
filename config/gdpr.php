<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Encryption Key
    |--------------------------------------------------------------------------
    |
    | This option controls the encryption key that will be used for encrypting
    | and decrypting sensitive data. If null, the application key will be used.
    |
    */
    'encryption_key' => env('GDPR_ENCRYPTION_KEY'),

    /*
    |--------------------------------------------------------------------------
    | Cipher
    |--------------------------------------------------------------------------
    |
    | This cipher will be used for encrypting and decrypting sensitive data.
    | This should be one of the ciphers supported by Laravel's encrypter.
    |
    */
    'cipher' => 'AES-256-CBC',
];
