<?php

namespace Paperscissorsandglue\EncryptionAtRest\Tests\Unit;

use Orchestra\Testbench\TestCase;
use Paperscissorsandglue\EncryptionAtRest\EncryptionAtRestServiceProvider;
use Paperscissorsandglue\EncryptionAtRest\HasEncryptedEmail;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

class NotificationTest extends TestCase
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
    }

    /**
     * Setup the test environment.
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Create the test users table
        $this->app['db']->connection()->getSchemaBuilder()->create('notification_test_users', function ($table) {
            $table->increments('id');
            $table->string('name');
            $table->string('email');
            $table->string('email_index')->nullable()->index();
            $table->timestamps();
        });
    }

    public function testEmailIsDecrypted()
    {
        // Create a user with email
        $user = new NotificationTestUser();
        $user->name = 'Test User';
        $user->email = 'notification@example.com';
        $user->save();

        // Check that email_index is set
        $this->assertNotNull($user->email_index);
        
        // Get the raw value from the database to check encryption
        $rawUser = $this->app['db']->connection()->table('notification_test_users')->where('id', $user->id)->first();
        
        // The email in database should be encrypted
        $this->assertNotEquals('notification@example.com', $rawUser->email);
        
        // When we retrieve the model, the email should be decrypted
        $retrievedUser = NotificationTestUser::find($user->id);
        $this->assertEquals('notification@example.com', $retrievedUser->email);
    }
}

class NotificationTestUser extends Authenticatable
{
    use Notifiable, HasEncryptedEmail;
    
    protected $table = 'notification_test_users';
    protected $guarded = [];
}