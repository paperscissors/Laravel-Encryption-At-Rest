# Laravel Encryption at Rest

[![Latest Version on Packagist](https://img.shields.io/packagist/v/paperscissorsandglue/laravel-encryption-at-rest.svg?style=flat-square)](https://packagist.org/packages/paperscissorsandglue/laravel-encryption-at-rest)
[![GitHub Tests Action Status](https://img.shields.io/github/actions/workflow/status/paperscissorsandglue/laravel-encryption-at-rest/tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/paperscissorsandglue/laravel-encryption-at-rest/actions?query=workflow%3Atests+branch%3Amain)
[![Total Downloads](https://img.shields.io/packagist/dt/paperscissorsandglue/laravel-encryption-at-rest.svg?style=flat-square)](https://packagist.org/packages/paperscissorsandglue/laravel-encryption-at-rest)
[![License](https://img.shields.io/packagist/l/paperscissorsandglue/laravel-encryption-at-rest.svg?style=flat-square)](https://packagist.org/packages/paperscissorsandglue/laravel-encryption-at-rest)

A Laravel package for encrypting sensitive data at rest and automatically decrypting it when in use. Useful for regulatory compliance requirements like GDPR, HIPAA, and other data protection standards. Compatible with Laravel 10, 11, and 12.

## Features

- ✅ Encrypt user identifiable data at rest and decrypt while being used
- ✅ Encrypt specific fields within JSON columns
- ✅ Special handling for email addresses with searchable indexes
- ✅ Seamless integration with Laravel's authentication system
- ✅ Compatible with Laravel notifications and other subsystems
- ✅ Command-line tools for migrating existing data
- ✅ Simple trait-based implementation for models

## Requirements

- PHP 8.1 or higher
- Laravel 10.x, 11.x, or 12.x

## Installation

You can install the package via composer:

```bash
composer require paperscissorsandglue/laravel-encryption-at-rest
```

After installation, publish the configuration file:

```bash
php artisan vendor:publish --tag=encryption-at-rest-config
```

## Configuration

In your `.env` file, you can optionally set a custom encryption key:

```
ENCRYPTION_AT_REST_KEY=your-secure-key-here
```

If not set, the package will use your application key for encryption.

## Basic Usage

Add the `Encryptable` trait to your model and define which attributes should be encrypted:

```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Paperscissorsandglue\EncryptionAtRest\Encryptable;

class User extends Model
{
    use Encryptable;
    
    /**
     * The attributes that should be encrypted.
     *
     * @var array
     */
    protected $encryptable = [
        'email',
        'phone',
        'address',
    ];
}
```

That's it! The specified attributes will be automatically encrypted when saved to the database and decrypted when retrieved.

## Encrypting JSON Fields

For JSON columns where you only want to encrypt certain fields within the JSON structure, use the `EncryptableJson` trait:

```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Paperscissorsandglue\EncryptionAtRest\EncryptableJson;

class UserProfile extends Model
{
    use EncryptableJson;
    
    /**
     * The attributes that should have encrypted JSON fields.
     *
     * @var array
     */
    protected $encryptableJson = [
        'preferences' => ['notification_email', 'backup_phone'],
        'settings' => ['api_key', 'personal_token'],
    ];
    
    /**
     * The attributes that should be cast.
     *
     * @var array
     */
    protected $casts = [
        'preferences' => 'json',
        'settings' => 'json',
    ];
}
```

With this setup, only the specified fields within your JSON structure will be encrypted while the rest of the JSON remains searchable.

## Seamless Encryption/Decryption

This package uses smart dynamic getters and setters to handle all encryption and decryption transparently. All encrypted fields, including email, are automatically:

- Encrypted when saved to the database
- Decrypted when accessed through any means
- Properly handled in all Laravel subsystems

This universal approach means you don't need to write any special code to handle encryption - it just works:

```php
// Regular attribute access
$email = $user->email;   // Automatically decrypted

// Assignment 
$user->email = 'new@example.com';  // Will be encrypted on save

// Laravel notifications work seamlessly
$user->notify(new WelcomeNotification());

// Form requests and API responses work correctly 
return response()->json(['user' => $user]);

// Eloquent serialization works properly
$array = $user->toArray();
```

For JSON attributes with encrypted fields, the package also ensures seamless operation:

```php
// If 'api_key' is encrypted within the preferences JSON
$apiKey = $user->preferences['api_key'];  // Automatically decrypted

// Set values that will be encrypted automatically
$user->preferences = [
    'api_key' => 'new-secret-key',
    'public_setting' => 'not-encrypted'
];
```

## Encrypted Email Authentication

This package provides special support for encrypting the email field while maintaining the ability to authenticate users by email. This is achieved by adding a searchable hash of the email (`email_index`) that enables efficient lookup.

### Setup Encrypted Email Authentication

1. First, publish the migration to add the `email_index` column to your users table:

```bash
php artisan vendor:publish --tag=encryption-at-rest-migrations
php artisan migrate
```

2. Add the `HasEncryptedEmail` trait to your User model:

```php
<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;
use Paperscissorsandglue\EncryptionAtRest\HasEncryptedEmail;

class User extends Authenticatable
{
    use HasApiTokens, HasEncryptedEmail, Notifiable;
    
    // ... existing model code
}
```

3. Update your auth configuration in `config/auth.php` to use the encrypted email user provider:

```php
'providers' => [
    'users' => [
        'driver' => 'encrypted-email',
        'model' => App\Models\User::class,
    ],
],
```

4. For existing users, you'll need to regenerate the email index values and encrypt existing emails. Use the provided command:

```bash
# Run in dry-run mode first to see what would be changed
php artisan encryption:encrypt-emails "App\Models\User" --dry-run

# When ready, run the actual encryption (use --chunk=XX to set batch size)
php artisan encryption:encrypt-emails "App\Models\User"
```

Or if you prefer, create a migration:

```php
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use App\Models\User;

return new class extends Migration
{
    public function up(): void
    {
        // Rehash all existing user emails
        User::all()->each(function ($user) {
            $user->handleEmailEncryption();
            $user->save();
        });
    }
};
```

### Querying Users by Email

With the `HasEncryptedEmail` trait, you can still find users by their email:

```php
// Find a user by email
$user = User::findByEmail('user@example.com');

// Or use the scope
$user = User::whereEmail('user@example.com')->first();
```

### How It Works

1. When a user is created or updated, the email is:
   - Encrypted before storage in the `email` column
   - A deterministic hash is stored in the `email_index` column for searching

2. When a user is retrieved:
   - The email is automatically decrypted
   - Authentication systems use the `email_index` column for lookups

3. The authentication provider is modified to:
   - Look up users by the hashed email index
   - Enable all standard Laravel authentication features (login, registration, password reset, etc.)

## Manual Encryption/Decryption

You can also use the `EncryptionService` directly for custom encryption needs:

```php
use Paperscissorsandglue\EncryptionAtRest\EncryptionService;

public function __construct(EncryptionService $encryptionService)
{
    $this->encryptionService = $encryptionService;
}

public function storeData($data)
{
    $encryptedData = $this->encryptionService->encrypt($data);
    // Store $encryptedData...
}

public function retrieveData($encryptedData)
{
    $decryptedData = $this->encryptionService->decrypt($encryptedData);
    // Use $decryptedData...
}
```

## Using the Facade

You can use the provided facade for quick access to encryption functionality:

```php
use Paperscissorsandglue\EncryptionAtRest\Facades\EncryptionAtRest;

$encrypted = EncryptionAtRest::encrypt('sensitive data');
$decrypted = EncryptionAtRest::decrypt($encrypted);
```

## CLI Tools

This package includes several command-line tools to help you manage encrypted data.

### Encrypting Existing Data

To encrypt data in an existing database table for a model that uses our traits:

```bash
php artisan encryption:encrypt-model "App\Models\User"
```

Options:
- `--chunk=100` - Process records in chunks (default: 100)
- `--dry-run` - Test the process without making changes
- `--backup=true` - Create a database backup before processing (default: true)
- `--filter="id > 1000"` - Only process records matching SQL where clause

### Encrypting Emails Only

For models using the `HasEncryptedEmail` trait, you can use a dedicated command to process emails:

```bash
php artisan encryption:encrypt-emails "App\Models\User"
```

Options:
- `--chunk=100` - Process records in chunks
- `--dry-run` - Test the process without making changes

### Decrypting Data

If you need to decrypt data (for example, when migrating away from encryption):

```bash
php artisan encryption:decrypt-model "App\Models\User"
```

Options:
- `--chunk=100` - Process records in chunks (default: 100)
- `--dry-run` - Test the process without making changes
- `--backup=true` - Create a database backup before processing (default: true)
- `--filter="id > 1000"` - Only process records matching SQL where clause

⚠️ **Warning**: Decryption permanently removes the encryption protection from your data. Only use this command when absolutely necessary and after creating a backup.

## Security Considerations

- All encrypted data is stored using Laravel's built-in encryption features
- The encrypted data cannot be searched or indexed efficiently except for email (which uses a hash-based index)
- Consider using database indexes only on non-encrypted fields
- The email hash is not a security risk as it's a one-way hash, but it does allow deterministic lookup
- Users with the same email will have the same email_index hash, making the email effectively unique in the system
- Always create a database backup before running encryption/decryption commands on production data

## Testing

```bash
composer test
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security Vulnerabilities

Please review [our security policy](../../security/policy) on how to report security vulnerabilities.

## Credits

- [Paper Scissors and Glue](https://github.com/paperscissorsandglue)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.