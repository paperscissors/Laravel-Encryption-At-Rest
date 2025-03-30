<?php

namespace Paperscissorsandglue\EncryptionAtRest\Tests\Unit;

use Orchestra\Testbench\TestCase;
use Paperscissorsandglue\EncryptionAtRest\EncryptionAtRestServiceProvider;
use Paperscissorsandglue\EncryptionAtRest\EncryptableJson;
use Paperscissorsandglue\EncryptionAtRest\EncryptionService;
use Illuminate\Database\Eloquent\Model;

class EncryptableJsonTest extends TestCase
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

    public function testEncryptAndDecryptJsonFields()
    {
        // Create a test table
        $this->app['db']->connection()->getSchemaBuilder()->create('json_test_models', function ($table) {
            $table->increments('id');
            $table->text('name')->nullable();
            $table->json('preferences')->nullable();
            $table->json('settings')->nullable();
            $table->timestamps();
        });

        // Create test data
        $preferences = [
            'theme' => 'dark',
            'notification_email' => 'alerts@example.com',
            'backup_phone' => '555-123-4567',
            'timezone' => 'UTC'
        ];

        $settings = [
            'language' => 'en',
            'api_key' => 'secret-api-key-12345',
            'personal_token' => 'personal-token-abcde',
            'notifications_enabled' => true
        ];

        // Create and save a model
        $model = new TestJsonModel();
        $model->name = 'Test User';
        $model->preferences = json_encode($preferences);
        $model->settings = json_encode($settings);
        $model->save();

        // Get a fresh instance from the database
        $retrievedModel = TestJsonModel::find($model->id);
        $retrievedPreferences = json_decode($retrievedModel->preferences, true);
        $retrievedSettings = json_decode($retrievedModel->settings, true);

        // Verify non-encrypted fields remain the same
        $this->assertEquals('dark', $retrievedPreferences['theme']);
        $this->assertEquals('UTC', $retrievedPreferences['timezone']);
        $this->assertEquals('en', $retrievedSettings['language']);
        $this->assertEquals(true, $retrievedSettings['notifications_enabled']);

        // Verify encrypted fields are decrypted correctly
        $this->assertEquals('alerts@example.com', $retrievedPreferences['notification_email']);
        $this->assertEquals('555-123-4567', $retrievedPreferences['backup_phone']);
        $this->assertEquals('secret-api-key-12345', $retrievedSettings['api_key']);
        $this->assertEquals('personal-token-abcde', $retrievedSettings['personal_token']);

        // Get raw data from database to verify encryption
        $rawData = $this->app['db']->connection()->table('json_test_models')->where('id', $model->id)->first();
        $rawPreferences = json_decode($rawData->preferences, true);
        $rawSettings = json_decode($rawData->settings, true);

        // Verify non-sensitive fields are not encrypted
        $this->assertEquals('dark', $rawPreferences['theme']);
        $this->assertEquals('UTC', $rawPreferences['timezone']);
        $this->assertEquals('en', $rawSettings['language']);
        $this->assertEquals(true, $rawSettings['notifications_enabled']);

        // Verify sensitive fields are encrypted
        $this->assertNotEquals('alerts@example.com', $rawPreferences['notification_email']);
        $this->assertNotEquals('555-123-4567', $rawPreferences['backup_phone']);
        $this->assertNotEquals('secret-api-key-12345', $rawSettings['api_key']);
        $this->assertNotEquals('personal-token-abcde', $rawSettings['personal_token']);
    }
}

class TestJsonModel extends Model
{
    use EncryptableJson;
    
    protected $table = 'json_test_models';
    protected $guarded = [];
    
    protected $encryptableJson = [
        'preferences' => ['notification_email', 'backup_phone'],
        'settings' => ['api_key', 'personal_token']
    ];
}