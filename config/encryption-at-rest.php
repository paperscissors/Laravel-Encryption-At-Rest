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
    'encryption_key' => env('ENCRYPTION_AT_REST_KEY'),

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

    /*
    |--------------------------------------------------------------------------
    | Compact Mode for Emails
    |--------------------------------------------------------------------------
    |
    | When enabled, emails will be encrypted using a more compact representation
    | that produces shorter ciphertext. This is useful for databases with 
    | strict field length limits like PostgreSQL. The tradeoff is that
    | the encrypted value is marginally less secure but still adequate for
    | most use cases.
    |
    */
    'compact_email_encryption' => env('ENCRYPTION_AT_REST_COMPACT_EMAIL', false),
    
    /*
    |--------------------------------------------------------------------------
    | Compact Mode for Field Encryption
    |--------------------------------------------------------------------------
    |
    | When enabled, all fields (not just emails) will be encrypted using a more
    | compact representation that produces shorter ciphertext. This is useful for
    | databases with strict field length limits like PostgreSQL. The tradeoff is
    | that the encrypted value is marginally less secure but still adequate for
    | most use cases.
    |
    */
    'compact_field_encryption' => env('ENCRYPTION_AT_REST_COMPACT_FIELD', false),
];
