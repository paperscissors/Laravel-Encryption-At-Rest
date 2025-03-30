<?php

namespace Paperscissorsandglue\GdprLaravel\Auth;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable as UserContract;
use Illuminate\Contracts\Hashing\Hasher as HasherContract;
use Illuminate\Support\Str;

class EncryptedEmailUserProvider extends EloquentUserProvider
{
    /**
     * Create a new database user provider.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @param  string  $model
     * @return void
     */
    public function __construct(HasherContract $hasher, $model)
    {
        parent::__construct($hasher, $model);
    }

    /**
     * Retrieve a user by the given credentials.
     *
     * @param  array  $credentials
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByCredentials(array $credentials)
    {
        if (empty($credentials) ||
           (count($credentials) === 1 &&
            Str::contains($this->firstCredentialKey($credentials), 'password'))) {
            return null;
        }

        // First we will build a query to find the user based on the given credentials
        $query = $this->newModelQuery();

        // Handle the email specially if it's in the credentials
        if (isset($credentials['email'])) {
            $model = $this->createModel();
            $emailHash = $model->getEmailIndexHash($credentials['email']);
            $query->where('email_index', $emailHash);
            
            // Remove email so we don't try to match on it again
            unset($credentials['email']);
        }

        // Now add any remaining credentials to the query
        foreach ($credentials as $key => $value) {
            if (Str::contains($key, 'password')) {
                continue;
            }

            if (is_array($value) || $value instanceof Arrayable) {
                $query->whereIn($key, $value);
            } else {
                $query->where($key, $value);
            }
        }

        return $query->first();
    }
}