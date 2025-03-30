<?php

namespace Paperscissorsandglue\GdprLaravel\Tests\Unit;

use Orchestra\Testbench\TestCase;
use Paperscissorsandglue\GdprLaravel\EncryptionAtRestServiceProvider;
use Paperscissorsandglue\GdprLaravel\Encryptable;
use Paperscissorsandglue\GdprLaravel\EncryptionService;
use Illuminate\Database\Eloquent\Model;

class EncryptableTest extends TestCase
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

    public function testEncryptAndDecryptValue()
    {
        $encryptionService = $this->app->make(EncryptionService::class);
        
        $originalValue = 'test-value';
        $encryptedValue = $encryptionService->encrypt($originalValue);
        
        $this->assertNotEquals($originalValue, $encryptedValue);
        $this->assertEquals($originalValue, $encryptionService->decrypt($encryptedValue));
    }

    public function testEncryptableModelEncryptsAndDecryptsAttributes()
    {
        // Create a test table
        $this->app['db']->connection()->getSchemaBuilder()->create('test_models', function ($table) {
            $table->increments('id');
            $table->text('name')->nullable();
            $table->text('email')->nullable();
            $table->text('phone')->nullable();
            $table->timestamps();
        });

        // Create and save a model
        $model = new TestEncryptableModel();
        $model->name = 'Test User';
        $model->email = 'test@example.com';
        $model->phone = '123-456-7890';
        $model->save();

        // Get a fresh instance from the database
        $retrievedModel = TestEncryptableModel::find($model->id);

        // Check that the attributes are correctly decrypted
        $this->assertEquals('Test User', $retrievedModel->name);
        $this->assertEquals('test@example.com', $retrievedModel->email);
        $this->assertEquals('123-456-7890', $retrievedModel->phone);

        // Check the raw database values to make sure they're encrypted
        $rawData = $this->app['db']->connection()->table('test_models')->where('id', $model->id)->first();
        $this->assertNotEquals('test@example.com', $rawData->email);
        $this->assertNotEquals('123-456-7890', $rawData->phone);
    }
}

class TestEncryptableModel extends Model
{
    use Encryptable;
    
    protected $table = 'test_models';
    protected $guarded = [];
    
    protected $encryptable = ['email', 'phone'];
}