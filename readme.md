# Laravel JWT Validate

This package is meant to be used in an architecture where you have multiple
Laravel applications working together, with one of them issuing JWTs with a
secret generated through an asymmetric encryption algorithm (RS256 for now).
This is mostly to aid with use Laravel Passport tokens in service-oriented
architectures where only the Auth service might be able to access all auth data.

JWT Validate will check the integrity of an incoming authentication token
using your primary installation's public key. It will also hydrate a user
model and make it available through the regular `Auth::user()` using data
encoded in your JWT.

Note that Passport Validate should **not** be used on a project that already
uses Laravel Passport. This is meant exclusively for applications that may
not have access to the OAuth private key, Passport database tables, or other
required elements of Laravel Passport.

## Installation

### Install through Composer
```bash
composer require jobilla/laravel-jwt-validate
```

### Add the auth config

To enable the guard, add the following to your `config/auth.php`

```php
<?php

return [
    // ...

    'guards' => [
        // ...
        
        'jwt' => [
            'driver' => 'jwt-validate',
            'public_key_path' => storage_path('oauth-public.key'),
            'hydrator' => function (array $claims, \Illuminate\Http\Request $request) {
                return new App\User(['id' => $claims['sub']]);
            },
        ]
    ]
];
```

You may choose to use this as your default guard, and likely replace the default
`api` guard with this one.