<?php

namespace Paperscissorsandglue\EncryptionAtRest\Tests\Unit;

use Orchestra\Testbench\TestCase;
use Paperscissorsandglue\EncryptionAtRest\EncryptionAtRestServiceProvider;
use Paperscissorsandglue\EncryptionAtRest\Encryptable;
use Paperscissorsandglue\EncryptionAtRest\EncryptionService;
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
            $table->text('address')->nullable();
            $table->text('company')->nullable();
            $table->timestamps();
        });

        // Create and save a model
        $model = new TestEncryptableModel();
        $model->name = 'Test User';
        $model->email = 'test@example.com';
        $model->phone = '123-456-7890';
        $model->address = '123 Main St, Anytown, USA';
        $model->company = 'Test Company Inc';
        $model->save();

        // Get a fresh instance from the database
        $retrievedModel = TestEncryptableModel::find($model->id);

        // Check that the attributes are correctly decrypted
        $this->assertEquals('Test User', $retrievedModel->name);
        $this->assertEquals('test@example.com', $retrievedModel->email);
        $this->assertEquals('123-456-7890', $retrievedModel->phone);
        $this->assertEquals('123 Main St, Anytown, USA', $retrievedModel->address);
        $this->assertEquals('Test Company Inc', $retrievedModel->company);

        // Check the raw database values to make sure they're encrypted
        $rawData = $this->app['db']->connection()->table('test_models')->where('id', $model->id)->first();
        $this->assertNotEquals('test@example.com', $rawData->email);
        $this->assertNotEquals('123-456-7890', $rawData->phone);
        $this->assertNotEquals('123 Main St, Anytown, USA', $rawData->address);
        $this->assertNotEquals('Test Company Inc', $rawData->company);
    }

    public function testIsValueEncryptedDetectsLaravelEncryption()
    {
        $encryptionService = $this->app->make(EncryptionService::class);
        $model = new TestEncryptableModel();
        
        // Test Laravel standard encryption detection
        $originalValue = 'test-value-for-encryption';
        $laravelEncrypted = $encryptionService->encrypt($originalValue);
        
        // Debug: Check what the encrypted value looks like
        $this->assertNotEquals($originalValue, $laravelEncrypted);
        $this->assertTrue(is_string($laravelEncrypted));
        $this->assertTrue(strlen($laravelEncrypted) > 50);
        
        // Verify it can be decrypted
        $decrypted = $encryptionService->decrypt($laravelEncrypted);
        $this->assertEquals($originalValue, $decrypted);
        
        // Use reflection to access the protected method
        $reflection = new \ReflectionClass($model);
        $method = $reflection->getMethod('isValueEncrypted');
        $method->setAccessible(true);
        
        // Debug: Check the base64 decoding
        $decoded = base64_decode($laravelEncrypted, true);
        $this->assertNotFalse($decoded, 'Encrypted value should be valid base64');
        
        $json = json_decode($decoded, true);
        $this->assertIsArray($json, 'Decoded base64 should be JSON array');
        $this->assertArrayHasKey('iv', $json, 'JSON should have iv key');
        $this->assertArrayHasKey('value', $json, 'JSON should have value key');
        $this->assertArrayHasKey('mac', $json, 'JSON should have mac key');
        
        // Test that Laravel encrypted values are detected
        $this->assertTrue($method->invokeArgs($model, [$laravelEncrypted]), 
            'isValueEncrypted should detect Laravel encrypted values');
        
        // Test that plain text is not detected as encrypted
        $this->assertFalse($method->invokeArgs($model, ['plain text value']));
        $this->assertFalse($method->invokeArgs($model, ['test@example.com']));
        $this->assertFalse($method->invokeArgs($model, ['']));
        $this->assertFalse($method->invokeArgs($model, [null]));
    }

    public function testIsValueEncryptedDetectsCompactEncryption()
    {
        $encryptionService = $this->app->make(EncryptionService::class);
        $model = new TestEncryptableModel();
        
        // Use reflection to access the protected compactEncrypt method
        $encryptionReflection = new \ReflectionClass($encryptionService);
        $compactEncryptMethod = $encryptionReflection->getMethod('compactEncrypt');
        $compactEncryptMethod->setAccessible(true);
        
        // Create a compact encrypted value
        $originalValue = 'test-compact-encryption';
        $compactEncrypted = $compactEncryptMethod->invokeArgs($encryptionService, [$originalValue]);
        
        // Use reflection to access the protected isValueEncrypted method
        $modelReflection = new \ReflectionClass($model);
        $isEncryptedMethod = $modelReflection->getMethod('isValueEncrypted');
        $isEncryptedMethod->setAccessible(true);
        
        // Test that compact encrypted values are detected
        $this->assertTrue($isEncryptedMethod->invokeArgs($model, [$compactEncrypted]));
        $this->assertTrue(strpos($compactEncrypted, 'c:') === 0, 'Compact encryption should start with c:');
    }

    public function testDoubleEncryptionPrevention()
    {
        // Create a test table
        $this->app['db']->connection()->getSchemaBuilder()->create('test_models', function ($table) {
            $table->increments('id');
            $table->text('name')->nullable();
            $table->text('email')->nullable();
            $table->text('phone')->nullable();
            $table->text('address')->nullable();
            $table->timestamps();
        });

        $encryptionService = $this->app->make(EncryptionService::class);
        
        // Create a model and save it
        $model = new TestEncryptableModel();
        $model->email = 'test@example.com';
        $model->phone = '123-456-7890';
        $model->save();

        // Retrieve the model from database (this triggers decryption)
        $retrievedModel = TestEncryptableModel::find($model->id);
        
        // Verify the decrypted values are correct
        $this->assertEquals('test@example.com', $retrievedModel->email);
        $this->assertEquals('123-456-7890', $retrievedModel->phone);

        // Get the raw encrypted values from database
        $rawData = $this->app['db']->connection()->table('test_models')->where('id', $model->id)->first();
        $originalEncryptedEmail = $rawData->email;
        $originalEncryptedPhone = $rawData->phone;

        // Now update the retrieved model (which has decrypted values)
        // This should NOT cause double encryption when we save
        $retrievedModel->email = 'test@example.com'; // Same value
        $retrievedModel->phone = '123-456-7890'; // Same value
        $retrievedModel->save();

        // Check that we can still decrypt to the original values
        $finalModel = TestEncryptableModel::find($retrievedModel->id);
        $this->assertEquals('test@example.com', $finalModel->email);
        $this->assertEquals('123-456-7890', $finalModel->phone);

        // Test that isValueEncrypted works correctly on the encrypted values
        $reflection = new \ReflectionClass($retrievedModel);
        $method = $reflection->getMethod('isValueEncrypted');
        $method->setAccessible(true);
        
        $this->assertTrue($method->invokeArgs($retrievedModel, [$originalEncryptedEmail]));
        $this->assertTrue($method->invokeArgs($retrievedModel, [$originalEncryptedPhone]));
        $this->assertFalse($method->invokeArgs($retrievedModel, ['test@example.com']));
        $this->assertFalse($method->invokeArgs($retrievedModel, ['123-456-7890']));
    }

    public function testMixedEncryptionFormats()
    {
        // Create a test table
        $this->app['db']->connection()->getSchemaBuilder()->create('test_models', function ($table) {
            $table->increments('id');
            $table->text('email')->nullable();
            $table->text('phone')->nullable();
            $table->text('address')->nullable();
            $table->timestamps();
        });

        $encryptionService = $this->app->make(EncryptionService::class);
        
        // Use reflection to access compact encryption
        $reflection = new \ReflectionClass($encryptionService);
        $compactEncryptMethod = $reflection->getMethod('compactEncrypt');
        $compactEncryptMethod->setAccessible(true);

        // Create a model with mixed encryption formats
        $model = new TestEncryptableModel();
        
        // Set values that will be encrypted with standard Laravel encryption
        $model->email = 'test@example.com';
        $model->phone = '123-456-7890';
        
        // Manually set a compact encrypted value in the database
        $compactEncryptedAddress = $compactEncryptMethod->invokeArgs($encryptionService, ['123 Main Street']);
        
        $model->save();
        
        // Manually update the address with compact encryption
        $this->app['db']->connection()->table('test_models')
            ->where('id', $model->id)
            ->update(['address' => $compactEncryptedAddress]);

        // Retrieve the model and check all values decrypt correctly
        $retrievedModel = TestEncryptableModel::find($model->id);
        
        $this->assertEquals('test@example.com', $retrievedModel->email);
        $this->assertEquals('123-456-7890', $retrievedModel->phone);
        $this->assertEquals('123 Main Street', $retrievedModel->address);

        // Verify the raw database values are different formats
        $rawData = $this->app['db']->connection()->table('test_models')->where('id', $model->id)->first();
        $this->assertTrue(strpos($rawData->address, 'c:') === 0, 'Address should use compact encryption');
        $this->assertFalse(strpos($rawData->email, 'c:') === 0, 'Email should use standard encryption');
        $this->assertFalse(strpos($rawData->phone, 'c:') === 0, 'Phone should use standard encryption');
    }

    public function testToArrayDecryptsAllAttributes()
    {
        // Create a test table
        $this->app['db']->connection()->getSchemaBuilder()->create('test_models', function ($table) {
            $table->increments('id');
            $table->text('name')->nullable();
            $table->text('email')->nullable();
            $table->text('phone')->nullable();
            $table->text('address')->nullable();
            $table->timestamps();
        });

        // Create and save a model
        $model = new TestEncryptableModel();
        $model->name = 'Test User';
        $model->email = 'test@example.com';
        $model->phone = '123-456-7890';
        $model->address = '123 Main St';
        $model->save();

        // Get a fresh instance from the database
        $retrievedModel = TestEncryptableModel::find($model->id);

        // Convert to array and check all encrypted fields are decrypted
        $array = $retrievedModel->toArray();
        
        $this->assertEquals('Test User', $array['name']);
        $this->assertEquals('test@example.com', $array['email']);
        $this->assertEquals('123-456-7890', $array['phone']);
        $this->assertEquals('123 Main St', $array['address']);
    }

    public function testCompactDecryptionFromRawDatabase()
    {
        // Create a test table
        $this->app['db']->connection()->getSchemaBuilder()->create('test_models', function ($table) {
            $table->increments('id');
            $table->text('address')->nullable();
            $table->timestamps();
        });

        $encryptionService = $this->app->make(EncryptionService::class);
        
        // Use reflection to access compact encryption
        $reflection = new \ReflectionClass($encryptionService);
        $compactEncryptMethod = $reflection->getMethod('compactEncrypt');
        $compactEncryptMethod->setAccessible(true);

        // Create a compact encrypted value similar to the user's issue
        $originalValue = '123 Main Street';
        $compactEncrypted = $compactEncryptMethod->invokeArgs($encryptionService, [$originalValue]);
        
        // Manually insert into database with compact encryption
        $id = $this->app['db']->connection()->table('test_models')->insertGetId([
            'address' => $compactEncrypted,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        // Retrieve using Eloquent - this should trigger decryption
        $model = TestEncryptableModel::find($id);
        
        // Check that the value is properly decrypted when accessed
        $this->assertEquals($originalValue, $model->address);
        
        // Check that accessing via __get also works
        $this->assertEquals($originalValue, $model->__get('address'));
        
        // Check that toArray() also works
        $array = $model->toArray();
        $this->assertEquals($originalValue, $array['address']);

        // Verify the raw database value is still compact encrypted
        $rawData = $this->app['db']->connection()->table('test_models')->where('id', $id)->first();
        $this->assertTrue(strpos($rawData->address, 'c:') === 0);
        $this->assertNotEquals($originalValue, $rawData->address);
    }

    public function testDecryptionWorksForRelationshipLoadedModels()
    {
        // Create tables for user and addresses
        $this->app['db']->connection()->getSchemaBuilder()->create('users', function ($table) {
            $table->increments('id');
            $table->string('name');
            $table->timestamps();
        });

        $this->app['db']->connection()->getSchemaBuilder()->create('user_addresses', function ($table) {
            $table->increments('id');
            $table->integer('user_id');
            $table->text('street_1')->nullable();
            $table->text('street_2')->nullable();
            $table->timestamps();
        });

        $encryptionService = $this->app->make(EncryptionService::class);
        $reflection = new \ReflectionClass($encryptionService);
        $compactEncryptMethod = $reflection->getMethod('compactEncrypt');
        $compactEncryptMethod->setAccessible(true);

        // Create test data
        $userId = $this->app['db']->connection()->table('users')->insertGetId([
            'name' => 'Test User',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        // Insert address with compact encrypted street_1 and street_2
        $street1Encrypted = $compactEncryptMethod->invokeArgs($encryptionService, ['123 Main Street']);
        $street2Encrypted = $encryptionService->encrypt('Apt 4B'); // Regular encryption

        $addressId = $this->app['db']->connection()->table('user_addresses')->insertGetId([
            'user_id' => $userId,
            'street_1' => $street1Encrypted,
            'street_2' => $street2Encrypted,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        // Now simulate loading through a collection/relationship query
        // (which doesn't trigger the retrieved event)
        $addresses = $this->app['db']->connection()->table('user_addresses')
            ->where('user_id', $userId)
            ->get();

        // Create model instances manually from the raw data (simulating relationship loading)
        $addressData = $addresses->first();
        $address = new TestAddressModel();
        $address->setRawAttributes((array) $addressData);
        $address->exists = true;

        // Test that decryption works even when retrieved event didn't fire
        $this->assertEquals('123 Main Street', $address->street_1);
        $this->assertEquals('Apt 4B', $address->street_2);

        // Test toArray() also works
        $array = $address->toArray();
        $this->assertEquals('123 Main Street', $array['street_1']);
        $this->assertEquals('Apt 4B', $array['street_2']);
    }
}

class TestEncryptableModel extends Model
{
    use Encryptable;
    
    protected $table = 'test_models';
    protected $guarded = [];
    
    protected $encryptable = ['email', 'phone', 'address', 'company'];
}

class TestAddressModel extends Model
{
    use Encryptable;
    
    protected $table = 'user_addresses';
    protected $guarded = [];
    
    protected $encryptable = ['street_1', 'street_2'];
}