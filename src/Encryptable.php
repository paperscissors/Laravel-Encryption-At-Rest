<?php

namespace Paperscissorsandglue\EncryptionAtRest;

use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\DB;

trait Encryptable
{
    /**
     * Get the attributes that should be encrypted.
     *
     * @return array
     */
    public function getEncryptableAttributes(): array
    {
        return $this->encryptable ?? [];
    }

    /**
     * The "booted" method of the model.
     *
     * @return void
     */
    protected static function bootEncryptable()
    {
        // Since we now encrypt immediately on set, we don't need saving event
        // Since we decrypt on access without modifying state, we don't need retrieved event
        
        // Keep this minimal - encryption happens on __set(), decryption on __get/getAttribute
    }

    /**
     * Encrypt attributes marked as encryptable.
     * DEPRECATED: This method is no longer used since encryption happens immediately in __set().
     *
     * @return void
     */
    protected function encryptAttributes()
    {
        // This method is deprecated and no longer used.
        // Encryption now happens immediately in __set() method, aligning with HasEncryptedEmail behavior.
    }

    /**
     * Decrypt attributes marked as encryptable.
     * DEPRECATED: This method is no longer used since we decrypt on access without modifying state.
     *
     * @return void
     */
    protected function decryptAttributes()
    {
        // This method is deprecated and no longer used.
        // Decryption now happens on-demand in __get() and getAttribute() without modifying $this->attributes
        // This prevents double encryption issues and aligns with HasEncryptedEmail behavior
    }

    /**
     * Get the encryption service.
     *
     * @return \Paperscissorsandglue\EncryptionAtRest\EncryptionService
     */
    protected function getEncryptionService()
    {
        return App::make(EncryptionService::class);
    }

    /**
     * Encrypt a value.
     *
     * @param  mixed  $value
     * @return string
     */
    protected function encryptValue($value)
    {
        return $this->getEncryptionService()->encrypt($value);
    }
    
    /**
     * Encrypt a value for storage with automatic size management.
     *
     * @param  mixed  $value
     * @param  bool  $databaseHasLimits
     * @return string
     */
    protected function encryptValueForStorage($value, $databaseHasLimits = false)
    {
        return $this->getEncryptionService()->encryptForStorage($value, $databaseHasLimits);
    }

    /**
     * Decrypt a value.
     *
     * @param  string  $value
     * @return mixed
     */
    protected function decryptValue($value)
    {
        $decrypted = $this->getEncryptionService()->decrypt($value);
        
        // Check if the decrypted value is still encrypted (double encryption scenario)
        if (is_string($decrypted) && $this->isValueEncrypted($decrypted)) {
            try {
                return $this->getEncryptionService()->decrypt($decrypted);
            } catch (\Exception $e) {
                // If second decryption fails, return the first decryption result
                return $decrypted;
            }
        }
        
        return $decrypted;
    }
    
    /**
     * Dynamically retrieve attributes.
     * Returns decrypted values without modifying internal state.
     *
     * @param  string  $key
     * @return mixed
     */
    public function __get($key)
    {
        // Handle "email" separately if HasEncryptedEmail trait is used
        if ($key === 'email' && method_exists($this, 'getEmailIndexHash')) {
            return parent::__get($key);
        }

        // If the attribute exists and is encrypted, return decrypted value
        $encryptableAttributes = $this->getEncryptableAttributes();
        
        if (in_array($key, $encryptableAttributes) && isset($this->attributes[$key])) {
            if (is_string($this->attributes[$key]) && !empty($this->attributes[$key])) {
                // Check if the value appears to be encrypted
                if ($this->isValueEncrypted($this->attributes[$key])) {
                    try {
                        // Return decrypted value directly - DO NOT modify $this->attributes
                        return $this->decryptValue($this->attributes[$key]);
                    } catch (\Exception $e) {
                        // If decryption fails, return the original value
                        return $this->attributes[$key];
                    }
                }
            }
            // If not encrypted, return as-is
            return $this->attributes[$key];
        }
        
        // Default behavior if not an encrypted field
        return parent::__get($key);
    }
    
    /**
     * Dynamically set attributes.
     * Encrypts immediately when set, like HasEncryptedEmail trait.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @return void
     */
    public function __set($key, $value)
    {
        // Handle "email" separately if HasEncryptedEmail trait is used
        if ($key === 'email' && method_exists($this, 'getEmailIndexHash')) {
            return parent::__set($key, $value);
        }
        
        $encryptableAttributes = $this->getEncryptableAttributes();
        
        if (in_array($key, $encryptableAttributes)) {
            if (!empty($value)) {
                // Check if value is already encrypted to avoid double-encryption
                if (!$this->isValueEncrypted($value)) {
                    // Encrypt the value immediately
                    $databaseHasLimits = DB::connection()->getDriverName() === 'pgsql';
                    $this->attributes[$key] = $this->encryptValueForStorage($value, $databaseHasLimits);
                } else {
                    // Already encrypted, use as is
                    $this->attributes[$key] = $value;
                }
            } else {
                $this->attributes[$key] = null;
            }
            return;
        }
        
        // For non-encryptable attributes, use default behavior
        parent::__set($key, $value);
    }
    
    /**
     * Convert the model's attributes to an array.
     * Ensures encrypted attributes are decrypted by going through getAttribute().
     *
     * @return array
     */
    public function attributesToArray()
    {
        $attributes = parent::attributesToArray();
        
        // For encryptable attributes, make sure we get the decrypted values
        foreach ($this->getEncryptableAttributes() as $key) {
            if (array_key_exists($key, $attributes)) {
                $attributes[$key] = $this->getAttribute($key);
            }
        }
        
        return $attributes;
    }
    
    /**
     * Get an attribute from the model.
     * Returns decrypted values without modifying internal state.
     *
     * @param  string  $key
     * @return mixed
     */
    public function getAttribute($key)
    {
        // Handle "email" separately if HasEncryptedEmail trait is used
        if ($key === 'email' && method_exists($this, 'getEmailIndexHash')) {
            return parent::getAttribute($key);
        }
        
        $encryptableAttributes = $this->getEncryptableAttributes();
        
        if (in_array($key, $encryptableAttributes) && isset($this->attributes[$key])) {
            // Check if the value appears to be encrypted
            if (is_string($this->attributes[$key]) && !empty($this->attributes[$key])) {
                if ($this->isValueEncrypted($this->attributes[$key])) {
                    try {
                        // Return decrypted value directly - DO NOT modify $this->attributes
                        return $this->decryptValue($this->attributes[$key]);
                    } catch (\Exception $e) {
                        // If decryption fails, return the attribute as-is
                        return $this->attributes[$key];
                    }
                }
            }
            
            // If not encrypted, return as-is
            return $this->attributes[$key];
        }
        
        return parent::getAttribute($key);
    }
    
    /**
     * Check if a value appears to be encrypted.
     * Detects both Laravel standard encryption (AES-256-CBC) and compact encryption formats.
     * Enhanced with bulletproof double encryption protection.
     *
     * @param  string  $value
     * @return bool
     */
    protected function isValueEncrypted($value)
    {
        if (!is_string($value) || empty($value)) {
            return false;
        }
        
        // Check for compact encryption format (starts with 'c:')
        if (strpos($value, 'c:') === 0) {
            // Validate compact format: c:base64.base64.base64
            $parts = explode('.', substr($value, 2));
            if (count($parts) === 3) {
                // All parts should be valid base64
                foreach ($parts as $part) {
                    if (base64_decode($part, true) === false) {
                        return false;
                    }
                }
                return true;
            }
            return false;
        }
        
        // Check for Laravel standard encryption format (base64 encoded JSON with iv, value, mac)
        // Must be long enough to contain encryption data
        if (strlen($value) < 100) {
            return false;
        }
        
        // Must be valid base64
        $decoded = base64_decode($value, true);
        if ($decoded === false) {
            return false;
        }
        
        // Must be valid JSON
        $json = json_decode($decoded, true);
        if (!is_array($json)) {
            return false;
        }
        
        // Must have required Laravel encryption keys
        if (!isset($json['iv'], $json['value'], $json['mac'])) {
            return false;
        }
        
        // All components should be base64 strings
        if (!is_string($json['iv']) || !is_string($json['value']) || !is_string($json['mac'])) {
            return false;
        }
        
        // Validate that components are valid base64
        if (base64_decode($json['iv'], true) === false || 
            base64_decode($json['value'], true) === false ||
            base64_decode($json['mac'], true) === false) {
            return false;
        }
        
        return true;
    }
}
