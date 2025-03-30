<?php

namespace Paperscissorsandglue\GdprLaravel\Facades;

use Illuminate\Support\Facades\Facade;

class EncryptionAtRest extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'encryption-at-rest';
    }
}