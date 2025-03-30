<?php

namespace Paperscissorsandglue\EncryptionAtRest;

use Illuminate\Support\ServiceProvider;
use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;
use Paperscissorsandglue\EncryptionAtRest\Auth\EncryptedEmailAuthServiceProvider;

class EncryptionAtRestServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/encryption-at-rest.php', 'encryption-at-rest'
        );

        // Register the encryption service
        $this->app->singleton(EncryptionAtRestEncrypter::class, function ($app) {
            return new EncryptionAtRestEncrypter();
        });

        $this->app->singleton(EncryptionService::class, function ($app) {
            return new EncryptionService($app->make(EncryptionAtRestEncrypter::class));
        });

        // Alternative syntax for using the service via facade
        $this->app->bind('encryption-at-rest', function ($app) {
            return $app->make(EncryptionService::class);
        });

        // Register the encrypted email auth service provider
        $this->app->register(EncryptedEmailAuthServiceProvider::class);
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        if ($this->app->runningInConsole()) {
            // Publish configuration
            $this->publishes([
                __DIR__.'/../config/encryption-at-rest.php' => config_path('encryption-at-rest.php'),
            ], 'encryption-at-rest-config');

            // Publish migrations
            $this->publishes([
                __DIR__.'/../database/migrations/add_email_index_to_users_table.php.stub' => 
                    $this->getMigrationFileName('add_email_index_to_users_table.php'),
            ], 'encryption-at-rest-migrations');
            
            // Register the commands
            $this->commands([
                Console\EncryptEmails::class,
                Console\EncryptModelData::class,
                Console\DecryptModelData::class,
            ]);
        }
    }

    /**
     * Returns a migration file name with the current timestamp.
     *
     * @param string $migrationFileName
     * @return string
     */
    protected function getMigrationFileName($migrationFileName)
    {
        $timestamp = date('Y_m_d_His');
        
        return database_path('migrations/'.$timestamp.'_'.$migrationFileName);
    }
}
