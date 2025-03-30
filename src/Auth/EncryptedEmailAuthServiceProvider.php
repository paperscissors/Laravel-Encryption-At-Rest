<?php

namespace Paperscissorsandglue\EncryptionAtRest\Auth;

use Illuminate\Auth\AuthManager;
use Illuminate\Support\ServiceProvider;
use Paperscissorsandglue\EncryptionAtRest\Auth\EncryptedEmailUserProvider;

class EncryptedEmailAuthServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        //
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        // Add our custom user provider
        $this->app->make(AuthManager::class)->provider('encrypted-email', function ($app, array $config) {
            return new EncryptedEmailUserProvider($app['hash'], $config['model']);
        });
    }
}