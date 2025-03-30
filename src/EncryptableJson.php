<?php

namespace Paperscissorsandglue\GdprLaravel;

use Illuminate\Support\Facades\App;

trait EncryptableJson
{
    /**
     * Get the attributes that should have encrypted JSON fields.
     *
     * @return array
     */
    public function getEncryptableJsonAttributes(): array
    {
        return $this->encryptableJson ?? [];
    }

    /**
     * The "booted" method of the model.
     *
     * @return void
     */
    protected static function bootEncryptableJson()
    {
        static::saving(function ($model) {
            $model->encryptJsonAttributes();
        });

        static::retrieved(function ($model) {
            $model->decryptJsonAttributes();
        });
    }

    /**
     * Encrypt JSON fields marked as encryptable.
     *
     * @return void
     */
    protected function encryptJsonAttributes()
    {
        foreach ($this->getEncryptableJsonAttributes() as $jsonAttribute => $fields) {
            if (isset($this->attributes[$jsonAttribute])) {
                $json = json_decode($this->attributes[$jsonAttribute], true) ?: [];
                
                foreach ($fields as $field) {
                    if (isset($json[$field]) && !empty($json[$field])) {
                        $json[$field] = $this->encryptJsonValue($json[$field]);
                    }
                }
                
                $this->attributes[$jsonAttribute] = json_encode($json);
            }
        }
    }

    /**
     * Decrypt JSON fields marked as encryptable.
     *
     * @return void
     */
    protected function decryptJsonAttributes()
    {
        foreach ($this->getEncryptableJsonAttributes() as $jsonAttribute => $fields) {
            if (isset($this->attributes[$jsonAttribute])) {
                $json = json_decode($this->attributes[$jsonAttribute], true) ?: [];
                
                foreach ($fields as $field) {
                    if (isset($json[$field]) && !empty($json[$field])) {
                        try {
                            $json[$field] = $this->decryptJsonValue($json[$field]);
                        } catch (\Exception $e) {
                            // If the value can't be decrypted, leave it as is
                        }
                    }
                }
                
                $this->attributes[$jsonAttribute] = json_encode($json);
            }
        }
    }

    /**
     * Get the encryption service.
     *
     * @return \Paperscissorsandglue\GdprLaravel\EncryptionService
     */
    protected function getJsonEncryptionService()
    {
        return App::make(EncryptionService::class);
    }

    /**
     * Encrypt a JSON value.
     *
     * @param  mixed  $value
     * @return string
     */
    protected function encryptJsonValue($value)
    {
        return $this->getJsonEncryptionService()->encrypt($value);
    }

    /**
     * Decrypt a JSON value.
     *
     * @param  string  $value
     * @return mixed
     */
    protected function decryptJsonValue($value)
    {
        return $this->getJsonEncryptionService()->decrypt($value);
    }
    
    /**
     * Override __get magic method to handle JSON attributes correctly
     */
    public function __get($key)
    {
        // If this is a JSON attribute with encrypted fields, make sure it's decrypted 
        $encryptableJsonAttributes = $this->getEncryptableJsonAttributes();
        
        if (array_key_exists($key, $encryptableJsonAttributes)) {
            // Make sure it's decrypted before returning
            if (isset($this->attributes[$key])) {
                $json = json_decode($this->attributes[$key], true) ?: [];
                $jsonFields = $encryptableJsonAttributes[$key];
                $modified = false;
                
                foreach ($jsonFields as $field) {
                    if (isset($json[$field]) && !empty($json[$field])) {
                        try {
                            // Try to decrypt to see if it's already decrypted
                            $decrypted = $this->decryptJsonValue($json[$field]);
                            // If no exception, it was encrypted, so update it
                            $json[$field] = $decrypted;
                            $modified = true;
                        } catch (\Exception $e) {
                            // Already decrypted or invalid, do nothing
                        }
                    }
                }
                
                if ($modified) {
                    // Re-encode with decrypted values
                    $this->attributes[$key] = json_encode($json);
                }
            }
        }
        
        // Use default behavior 
        return parent::__get($key);
    }
    
    /**
     * Override getAttribute to decrypt JSON fields
     */
    public function getAttribute($key)
    {
        // If this is a JSON attribute with encrypted fields
        $encryptableJsonAttributes = $this->getEncryptableJsonAttributes();
        
        if (array_key_exists($key, $encryptableJsonAttributes) && isset($this->attributes[$key])) {
            // Get the value using parent method first (handles casts etc.)
            $value = parent::getAttribute($key);
            
            // If it's already an array due to casting, we need to check individual fields
            if (is_array($value)) {
                $jsonFields = $encryptableJsonAttributes[$key];
                
                foreach ($jsonFields as $field) {
                    if (isset($value[$field]) && !empty($value[$field])) {
                        try {
                            // Try to decrypt
                            $value[$field] = $this->decryptJsonValue($value[$field]);
                        } catch (\Exception $e) {
                            // If it fails, it might already be decrypted
                        }
                    }
                }
                
                return $value;
            }
            
            // Otherwise, it's still a JSON string, so decode and process as before
            $json = json_decode($this->attributes[$key], true) ?: [];
            $jsonFields = $encryptableJsonAttributes[$key];
            $modified = false;
            
            foreach ($jsonFields as $field) {
                if (isset($json[$field]) && !empty($json[$field])) {
                    try {
                        $json[$field] = $this->decryptJsonValue($json[$field]);
                        $modified = true;
                    } catch (\Exception $e) {
                        // If can't decrypt, leave as is
                    }
                }
            }
            
            if ($modified) {
                // Re-encode with decrypted values if modified
                $this->attributes[$key] = json_encode($json);
            }
            
            // If the model has a cast for this attribute, apply it
            $cast = $this->getCasts()[$key] ?? null;
            if ($cast === 'array' || $cast === 'json') {
                return $json;
            }
            
            return $this->attributes[$key];
        }
        
        return parent::getAttribute($key);
    }
    
    /**
     * Override setAttribute to handle JSON encrypting when set
     */
    public function setAttribute($key, $value)
    {
        $encryptableJsonAttributes = $this->getEncryptableJsonAttributes();
        
        if (array_key_exists($key, $encryptableJsonAttributes)) {
            // Handle different input types
            if (is_array($value)) {
                $json = $value;
            } else if (is_string($value)) {
                $json = json_decode($value, true) ?: [];
            } else {
                $json = [];
            }
            
            $jsonFields = $encryptableJsonAttributes[$key];
            
            foreach ($jsonFields as $field) {
                if (isset($json[$field]) && !empty($json[$field])) {
                    // Check if the value is already encrypted to avoid double encryption
                    try {
                        // Try to decrypt, if it works, it's already encrypted
                        $this->decryptJsonValue($json[$field]);
                    } catch (\Exception $e) {
                        // If decryption fails, encrypt the value
                        $json[$field] = $this->encryptJsonValue($json[$field]);
                    }
                }
            }
            
            // If we have a cast, let parent handle the encoding
            $cast = $this->getCasts()[$key] ?? null;
            if ($cast === 'array' || $cast === 'json') {
                return parent::setAttribute($key, $json);
            }
            
            // Otherwise encode and store
            $this->attributes[$key] = json_encode($json);
            return $this;
        }
        
        return parent::setAttribute($key, $value);
    }
    
    /**
     * Ensure encrypted JSON fields are decrypted in notification payloads
     */
    public function toArray()
    {
        // Ensure all JSON fields are decrypted before converting to array
        $this->decryptJsonAttributes();
        
        return parent::toArray();
    }
}