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
            try {
                // If the attribute appears to be encrypted, decrypt it on-the-fly
                if (is_string($this->attributes[$key]) && !empty($this->attributes[$key])) {
                    // Attempt to detect if it's already decrypted to avoid double decryption
                    try {
                        // If this doesn't throw an exception, it's likely already encrypted
                        // and we should decrypt it before returning
                        $encrypted = $this->getEncryptionService()->encrypt('test_encryption');
                        $this->getEncryptionService()->decrypt($encrypted);
                        
                        // If it looks like a JSON payload, it's probably encrypted
                        if (preg_match('/^{.*}$/', $this->attributes[$key])) {
                            return $this->decryptValue($this->attributes[$key]);
                        }
                    } catch (\Exception $e) {
                        // If we catch an exception here, it's probably already decrypted
                    }
                }
            } catch (\Exception $e) {
                // If decryption fails, return the original value
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
            // Don't double-encrypt
            try {
                // Try to decrypt the value - if it fails, it needs to be encrypted
                $this->getEncryptionService()->decrypt($value);
            } catch (\Exception $e) {
                // If decryption failed, encrypt the value
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
}
