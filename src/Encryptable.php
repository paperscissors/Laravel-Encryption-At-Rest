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
        static::saving(function ($model) {
            $model->encryptAttributes();
        });

        static::retrieved(function ($model) {
            $model->decryptAttributes();
        });
    }

    /**
     * Encrypt attributes marked as encryptable.
     *
     * @return void
     */
    protected function encryptAttributes()
    {
        $databaseHasLimits = DB::connection()->getDriverName() === 'pgsql';
        
        foreach ($this->getEncryptableAttributes() as $attribute) {
            if (isset($this->attributes[$attribute]) && ! empty($this->attributes[$attribute])) {
                // Use the field-specific encryption that handles character limits
                $this->attributes[$attribute] = $this->encryptValueForStorage($this->attributes[$attribute], $databaseHasLimits);
            }
        }
    }

    /**
     * Decrypt attributes marked as encryptable.
     *
     * @return void
     */
    protected function decryptAttributes()
    {
        foreach ($this->getEncryptableAttributes() as $attribute) {
            if (isset($this->attributes[$attribute]) && ! empty($this->attributes[$attribute])) {
                try {
                    $this->attributes[$attribute] = $this->decryptValue($this->attributes[$attribute]);
                } catch (\Exception $e) {
                    // If the value can't be decrypted, leave it as is
                }
            }
        }
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
        return $this->getEncryptionService()->decrypt($value);
    }
    
    /**
     * Dynamically retrieve attributes.
     * This ensures attributes are decrypted when accessed via notifications
     * and other systems that might bypass the standard attribute getters.
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

        // If the attribute exists and is encrypted, ensure it's decrypted
        $encryptableAttributes = $this->getEncryptableAttributes();
        
        if (in_array($key, $encryptableAttributes) && isset($this->attributes[$key])) {
            if (is_string($this->attributes[$key]) && !empty($this->attributes[$key])) {
                // Check if the value appears to be encrypted
                if ($this->isValueEncrypted($this->attributes[$key])) {
                    try {
                        return $this->decryptValue($this->attributes[$key]);
                    } catch (\Exception $e) {
                        // If decryption fails, return the original value
                        return $this->attributes[$key];
                    }
                }
            }
        }
        
        // Default behavior if not an encrypted field
        return parent::__get($key);
    }
    
    /**
     * Dynamically set attributes.
     * Ensures attributes are correctly marked for encryption when set through
     * notification or other dynamic methods.
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
        
        // Set the attribute as normal
        parent::__set($key, $value);
        
        // If the attribute should be encrypted, make sure it's encrypted
        $encryptableAttributes = $this->getEncryptableAttributes();
        
        if (in_array($key, $encryptableAttributes) && isset($this->attributes[$key]) && !empty($value)) {
            // Don't double-encrypt - only encrypt if the value is not already encrypted
            if (!$this->isValueEncrypted($value)) {
                $this->attributes[$key] = $this->encryptValue($value);
            }
        }
    }
    
    /**
     * Convert the model's attributes to an array.
     * Ensures all attributes are properly decrypted.
     *
     * @return array
     */
    public function attributesToArray()
    {
        // Make sure all encryptable attributes are decrypted
        $this->decryptAttributes();
        
        return parent::attributesToArray();
    }
    
    /**
     * Get an attribute from the model.
     * Ensures encrypted attributes are properly decrypted.
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
            try {
                // Ensure the attribute is decrypted
                return $this->decryptValue($this->attributes[$key]);
            } catch (\Exception $e) {
                // If decryption fails, return the attribute as-is
                return $this->attributes[$key];
            }
        }
        
        return parent::getAttribute($key);
    }
    
    /**
     * Check if a value appears to be encrypted.
     * Detects both Laravel standard encryption (AES-256-CBC) and compact encryption formats.
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
            return true;
        }
        
        // Check for Laravel standard encryption format (base64 encoded JSON with iv, value, mac)
        // Laravel AES-256-CBC encryption produces base64 strings that decode to JSON
        if (strlen($value) > 50 && base64_decode($value, true) !== false) {
            $decoded = base64_decode($value, true);
            if ($decoded !== false) {
                $json = json_decode($decoded, true);
                // Laravel encryption has 'iv', 'value', and 'mac' keys
                // May also have additional keys like 'tag' in newer versions
                if (is_array($json) && 
                    isset($json['iv'], $json['value'], $json['mac'])) {
                    return true;
                }
            }
        }
        
        // Additional pattern check for Laravel encryption that starts with 'eyJ'
        // (base64 encoding of '{"' which is common for Laravel encryption JSON)
        if (preg_match('/^eyJ[A-Za-z0-9+\/]+=*$/', $value)) {
            $decoded = base64_decode($value, true);
            if ($decoded !== false) {
                $json = json_decode($decoded, true);
                if (is_array($json) && 
                    isset($json['iv'], $json['value'], $json['mac'])) {
                    return true;
                }
            }
        }
        
        return false;
    }
}
