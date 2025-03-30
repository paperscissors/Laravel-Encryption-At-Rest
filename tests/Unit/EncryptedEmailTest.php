<?php

namespace Paperscissorsandglue\EncryptionAtRest\Tests\Unit;

use Orchestra\Testbench\TestCase;
use Paperscissorsandglue\EncryptionAtRest\EncryptionAtRestServiceProvider;
use Paperscissorsandglue\EncryptionAtRest\HasEncryptedEmail;
use Paperscissorsandglue\EncryptionAtRest\Auth\EncryptedEmailUserProvider;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Auth\AuthManager;
use Illuminate\Support\Facades\Hash;

class EncryptedEmailTest extends TestCase
{
    protected function getPackageProviders($app)
    {
        return [EncryptionAtRestServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app)
    {
        // Setup default database
        $app['config']->set('database.default', 'testbench');
        $app['config']->set('database.connections.testbench', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);

        // Setup the encryption key
        $app['config']->set('encryption-at-rest.encryption_key', 'base64:'.base64_encode(random_bytes(32)));
        
        // Setup the auth configuration
        $app['config']->set('auth.providers.users', [
            'driver' => 'encrypted-email',
            'model' => TestUser::class,
        ]);
    }

    /**
     * Setup the test environment.
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Create the test users table
        $this->app['db']->connection()->getSchemaBuilder()->create('test_users', function ($table) {
            $table->increments('id');
            $table->string('name');
            $table->string('email');
            $table->string('email_index')->nullable()->index()->unique();
            $table->string('password');
            $table->rememberToken();
            $table->timestamps();
        });
    }

    public function testEmailEncryptionAndHashing()
    {
        // Create a user with email
        $user = new TestUser();
        $user->name = 'Test User';
        $user->email = 'test@example.com';
        $user->password = Hash::make('password');
        $user->save();

        // Check that email_index is set
        $this->assertNotNull($user->email_index);
        
        // Get the raw value from the database to check encryption
        $rawUser = $this->app['db']->connection()->table('test_users')->where('id', $user->id)->first();
        
        // The email in database should be encrypted
        $this->assertNotEquals('test@example.com', $rawUser->email);
        
        // But the email_index should be a deterministic hash
        $expectedHash = hash('sha256', 'test@example.com');
        $this->assertEquals($expectedHash, $rawUser->email_index);
        
        // When we retrieve the model, the email should be decrypted
        $retrievedUser = TestUser::find($user->id);
        $this->assertEquals('test@example.com', $retrievedUser->email);
    }

    public function testFindUserByEmail()
    {
        // Create a user with email
        $user = new TestUser();
        $user->name = 'Test User';
        $user->email = 'test@example.com';
        $user->password = Hash::make('password');
        $user->save();
        
        // Test the findByEmail method
        $foundUser = TestUser::findByEmail('test@example.com');
        $this->assertNotNull($foundUser);
        $this->assertEquals($user->id, $foundUser->id);
        
        // Test the whereEmail scope
        $scopedUser = TestUser::whereEmail('test@example.com')->first();
        $this->assertNotNull($scopedUser);
        $this->assertEquals($user->id, $scopedUser->id);
        
        // Test case-insensitive email
        $foundUser = TestUser::findByEmail('TEST@example.com');
        $this->assertNotNull($foundUser);
        $this->assertEquals($user->id, $foundUser->id);
    }

    public function testEncryptedEmailUserProvider()
    {
        // Create a user with email
        $user = new TestUser();
        $user->name = 'Test User';
        $user->email = 'auth@example.com';
        $user->password = Hash::make('password123');
        $user->save();
        
        // Create the user provider
        $provider = new EncryptedEmailUserProvider($this->app['hash'], TestUser::class);
        
        // Test retrieveByCredentials
        $retrievedUser = $provider->retrieveByCredentials([
            'email' => 'auth@example.com',
            'password' => 'password123'
        ]);
        
        $this->assertNotNull($retrievedUser);
        $this->assertEquals($user->id, $retrievedUser->id);
        $this->assertEquals('auth@example.com', $retrievedUser->email);
        
        // Test validateCredentials
        $isValid = $provider->validateCredentials($retrievedUser, [
            'password' => 'password123'
        ]);
        
        $this->assertTrue($isValid);
        
        // Test with wrong credentials
        $isValid = $provider->validateCredentials($retrievedUser, [
            'password' => 'wrong-password'
        ]);
        
        $this->assertFalse($isValid);
    }
}

class TestUser extends Authenticatable
{
    use HasEncryptedEmail;
    
    protected $table = 'test_users';
    protected $guarded = [];
}