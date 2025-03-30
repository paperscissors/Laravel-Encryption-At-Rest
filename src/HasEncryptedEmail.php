<?php

namespace Paperscissorsandglue\EncryptionAtRest;

use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

trait HasEncryptedEmail
{
    /**
     * Boot the trait
     */
    public static function bootHasEncryptedEmail()
    {
        static::creating(function ($model) {
            $model->handleEmailEncryption();
        });

        static::updating(function ($model) {
            // Only rehash if the email is changed
            if ($model->isDirty('email')) {
                $model->handleEmailEncryption();
            }
        });
    }

    /**
     * Handle email encryption and hashing when setting the email
     */
    protected function handleEmailEncryption()
    {
        if (empty($this->email)) {
            return;
        }

        // Get original email before encryption
        $email = $this->email;

        // Create normalized version of email for searchable index
        $this->email_index = $this->getEmailIndexHash($email);
        
        // Email will be encrypted automatically by the setter
    }

    /**
     * Create a normalized hash of the email for indexing
     */
    public function getEmailIndexHash($email)
    {
        // Normalize email (lowercase)
        $email = Str::lower($email);
        
        // Create a deterministic hash that will be the same for identical emails
        // We use sha256 for deterministic behavior but secure enough for this purpose
        return hash('sha256', $email);
    }

    /**
     * Find a user by their email
     */
    public static function findByEmail($email)
    {
        $instance = new static;
        $emailHash = $instance->getEmailIndexHash($email);
        
        return static::where('email_index', $emailHash)->first();
    }

    /**
     * Create a scope to query by email
     */
    public function scopeWhereEmail($query, $email)
    {
        $emailHash = $this->getEmailIndexHash($email);
        
        return $query->where('email_index', $emailHash);
    }
    
    /**
     * Get the encryption service.
     */
    protected function getEmailEncryptionService()
    {
        return App::make(EncryptionService::class);
    }
    
    /**
     * Override __get magic method to ensure email is always decrypted when accessed
     */
    public function __get($key)
    {
        if ($key === 'email' && isset($this->attributes['email'])) {
            try {
                $encryptionService = $this->getEmailEncryptionService();
                
                // Check if the email looks encrypted
                if (is_string($this->attributes['email']) && !empty($this->attributes['email'])) {
                    try {
                        // If decryption works, return decrypted value
                        return $encryptionService->decrypt($this->attributes['email']);
                    } catch (\Exception $e) {
                        // If not, it may already be decrypted, so return as is
                        return $this->attributes['email'];
                    }
                }
            } catch (\Exception $e) {
                // If any error, return as is
                return $this->attributes['email'];
            }
        }
        
        // For all other attributes, use default behavior
        return parent::__get($key);
    }
    
    /**
     * Override getAttribute to ensure email is decrypted
     */
    public function getAttribute($key)
    {
        if ($key === 'email' && isset($this->attributes['email'])) {
            try {
                $encryptionService = $this->getEmailEncryptionService();
                try {
                    // Try to decrypt - if it works, the email was encrypted
                    return $encryptionService->decrypt($this->attributes['email']);
                } catch (\Exception $e) {
                    // If it fails, the email may already be decrypted
                    return $this->attributes['email'];
                }
            } catch (\Exception $e) {
                // If any error, return as is
                return $this->attributes['email'];
            }
        }
        
        return parent::getAttribute($key);
    }
    
    /**
     * Override setAttribute to ensure email is encrypted and indexed when set
     */
    public function setAttribute($key, $value)
    {
        if ($key === 'email') {
            if (!empty($value)) {
                try {
                    // Check if value is already encrypted to avoid double-encryption
                    $this->getEmailEncryptionService()->decrypt($value);
                    // If no exception, it's already encrypted, use as is
                    $this->attributes['email'] = $value;
                } catch (\Exception $e) {
                    // Not encrypted yet, encrypt it
                    $this->attributes['email'] = $this->getEmailEncryptionService()->encrypt($value);
                }
                
                // Always update the email_index for searching
                $this->attributes['email_index'] = $this->getEmailIndexHash($value);
            } else {
                $this->attributes['email'] = null;
                $this->attributes['email_index'] = null;
            }
            
            return $this;
        }
        
        return parent::setAttribute($key, $value);
    }
    
    /**
     * Make sure all attributes are properly handled when converting to array
     */
    public function attributesToArray()
    {
        // Email will be automatically decrypted by the getAttribute method
        return parent::attributesToArray();
    }
}