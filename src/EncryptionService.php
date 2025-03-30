<?php

namespace Paperscissorsandglue\EncryptionAtRest;

use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;

class EncryptionService
{
    /**
     * The encrypter instance.
     *
     * @var \Illuminate\Contracts\Encryption\Encrypter
     */
    protected $encrypter;

    /**
     * Flag for compact email encryption.
     *
     * @var bool
     */
    protected $compactEmailEncryption;

    /**
     * Create a new encryption service instance.
     *
     * @param  \Illuminate\Contracts\Encryption\Encrypter  $encrypter
     * @return void
     */
    public function __construct(Encrypter $encrypter)
    {
        $this->encrypter = $encrypter;
        $this->compactEmailEncryption = Config::get('encryption-at-rest.compact_email_encryption', false);
    }

    /**
     * Encrypt the given value.
     *
     * @param  mixed  $value
     * @param  bool|null  $forceCompact  Force compact mode regardless of config
     * @return string
     */
    public function encrypt($value, $forceCompact = null)
    {
        // For emails, use the compact encryption method if enabled
        $useCompact = $forceCompact ?? $this->compactEmailEncryption;
        
        if ($useCompact && is_string($value) && Str::contains($value, '@')) {
            return $this->compactEncrypt($value);
        }
        
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
        // Check if this looks like a compact encrypted email
        if (is_string($value) && Str::startsWith($value, 'c:')) {
            return $this->compactDecrypt($value);
        }
        
        return $this->encrypter->decrypt($value);
    }
    
    /**
     * Encrypt an email using a more compact representation.
     * This produces shorter output at a slight security tradeoff,
     * but is still adequately secure for most email use cases.
     *
     * @param  string  $email
     * @return string
     */
    protected function compactEncrypt($email)
    {
        // Get the encryption key
        $key = $this->encrypter->getKey();
        
        // Simple shortened encryption for emails
        // We'll use AES-128-CBC for shorter output
        $iv = random_bytes(openssl_cipher_iv_length('aes-128-cbc'));
        $encrypted = openssl_encrypt($email, 'aes-128-cbc', $key, 0, $iv);
        
        // Create a shortened MAC (16 bytes instead of 32)
        $mac = hash_hmac('sha256', $iv . $encrypted, $key, true);
        $mac = substr($mac, 0, 16);
        
        // Format: c:{base64(iv)}.{base64(encrypted)}.{base64(mac)}
        // The 'c:' prefix indicates this is a compact encrypted value
        return 'c:' . base64_encode($iv) . '.' . base64_encode($encrypted) . '.' . base64_encode($mac);
    }
    
    /**
     * Decrypt a compact encrypted email.
     *
     * @param  string  $payload
     * @return string
     * @throws \Exception If the MAC is invalid
     */
    protected function compactDecrypt($payload)
    {
        // Get the encryption key
        $key = $this->encrypter->getKey();
        
        // Remove the prefix and split the parts
        $payload = substr($payload, 2); // Remove 'c:' prefix
        $parts = explode('.', $payload);
        
        if (count($parts) !== 3) {
            throw new \Exception('Invalid compact payload format');
        }
        
        $iv = base64_decode($parts[0]);
        $encrypted = base64_decode($parts[1]);
        $sentMac = base64_decode($parts[2]);
        
        // Verify the MAC
        $calcMac = hash_hmac('sha256', $iv . $encrypted, $key, true);
        $calcMac = substr($calcMac, 0, 16);
        
        if (!hash_equals($sentMac, $calcMac)) {
            throw new \Exception('Invalid MAC');
        }
        
        // Decrypt
        $decrypted = openssl_decrypt($encrypted, 'aes-128-cbc', $key, 0, $iv);
        
        if ($decrypted === false) {
            throw new \Exception('Could not decrypt data');
        }
        
        return $decrypted;
    }
}
