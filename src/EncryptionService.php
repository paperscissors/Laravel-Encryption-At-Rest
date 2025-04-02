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
     * Flag for compact field encryption.
     *
     * @var bool
     */
    protected $compactFieldEncryption;

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
        $this->compactFieldEncryption = Config::get('encryption-at-rest.compact_field_encryption', false);
    }

    /**
     * Encrypt the given value.
     *
     * @param  mixed  $value
     * @param  bool|null  $forceCompact  Force compact mode regardless of config
     * @param  bool  $isFieldEncryption  Whether this is for a field or email encryption
     * @return string
     */
    public function encrypt($value, $forceCompact = null, $isFieldEncryption = false)
    {
        // Standard encryption result - to check size
        $standardEncrypted = $this->encrypter->encrypt($value);
        
        // For emails, use the compact encryption method if enabled
        $useCompactEmail = ($forceCompact ?? $this->compactEmailEncryption) && is_string($value) && Str::contains($value, '@');
        
        // For regular fields, use compact encryption if enabled or if standard result is too long
        $useCompactField = ($forceCompact ?? $this->compactFieldEncryption) && is_string($value) && strlen($standardEncrypted) > 255;
        
        if ($useCompactEmail || $useCompactField) {
            return $this->compactEncrypt($value);
        }
        
        return $standardEncrypted;
    }
    
    /**
     * Encrypt a value with length detection and fallback to compact encryption if needed
     * 
     * @param  mixed  $value
     * @param  bool  $databaseHasLimits  Whether database has strict column limits
     * @return string
     */
    public function encryptForStorage($value, $databaseHasLimits = false)
    {
        if (!is_string($value)) {
            return $this->encrypter->encrypt($value);
        }
        
        // Standard encryption first
        $standardEncrypted = $this->encrypter->encrypt($value);
        
        // Check if encrypted value would exceed database limit
        if ($databaseHasLimits && strlen($standardEncrypted) > 255) {
            // Try compact encryption
            $compactEncrypted = $this->compactEncrypt($value);
            
            if (strlen($compactEncrypted) <= 255) {
                return $compactEncrypted;
            }
            
            // If even compact encryption is too large, we'll need to truncate the value
            // This is a last resort, and should be handled carefully
            if (Str::contains($value, '@')) {
                // Special handling for emails - keep domain intact
                $parts = explode('@', $value);
                if (count($parts) === 2) {
                    $username = $parts[0];
                    $domain = $parts[1];
                    
                    // Keep shortening username until it fits
                    $maxTries = 10;
                    $tries = 0;
                    
                    while ($tries < $maxTries) {
                        $truncatedUsername = substr($username, 0, max(1, strlen($username) - $tries * 5));
                        $truncatedValue = $truncatedUsername . '@' . $domain;
                        $encryptedTruncated = $this->compactEncrypt($truncatedValue);
                        
                        if (strlen($encryptedTruncated) <= 255) {
                            return $encryptedTruncated;
                        }
                        
                        $tries++;
                    }
                }
            } else {
                // For non-email values, just truncate directly
                $maxTries = 10;
                $tries = 0;
                
                while ($tries < $maxTries) {
                    $truncatedValue = substr($value, 0, max(1, strlen($value) - $tries * 10));
                    $encryptedTruncated = $this->compactEncrypt($truncatedValue);
                    
                    if (strlen($encryptedTruncated) <= 255) {
                        return $encryptedTruncated;
                    }
                    
                    $tries++;
                }
            }
            
            // If we get here, we couldn't make it fit within 255 chars
            // Return as much as we can fit, which might be just a few characters
            return $this->compactEncrypt(substr($value, 0, 20) . '...');
        }
        
        return $standardEncrypted;
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
