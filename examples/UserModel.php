<?php

namespace YourApp\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Paperscissorsandglue\EncryptionAtRest\Encryptable;
use Paperscissorsandglue\EncryptionAtRest\EncryptableJson;
use Paperscissorsandglue\EncryptionAtRest\HasEncryptedEmail;

class User extends Authenticatable
{
    use Notifiable, Encryptable, EncryptableJson, HasEncryptedEmail;
    
    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'name',
        'email',
        'password',
        'phone',
        'address',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'password',
        'remember_token',
        'email_index',
    ];
    
    /**
     * The attributes that should be encrypted.
     * Note: 'email' is handled by HasEncryptedEmail trait
     * so it doesn't need to be included here.
     *
     * @var array
     */
    protected $encryptable = [
        'phone',
        'address',
        'ip_address',
        'social_security_number',
    ];
    
    /**
     * The attributes that should have encrypted JSON fields.
     *
     * @var array
     */
    protected $encryptableJson = [
        'metadata' => [
            'credit_card_number',
            'emergency_contact_phone',
            'personal_id_number'
        ],
        'preferences' => [
            'secondary_email',
            'recovery_phone'
        ]
    ];
    
    /**
     * The attributes that should be cast.
     *
     * @var array
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
        'password' => 'hashed',
        'metadata' => 'json',
        'preferences' => 'json',
    ];
}