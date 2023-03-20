<?php

namespace Jobilla\JwtValidate;

use Illuminate\Auth\RequestGuard;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;

class JwtValidateServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->registerGuard();
    }

    protected function registerGuard()
    {
        Auth::extend('jwt-validate', function ($app, $name, array $config) {
            return tap($this->makeGuard($config), function ($guard) {
                $this->app->refresh('request', $guard, 'setRequest');
            });
        });
    }

    /**
     * Make an instance of the token guard.
     *
     * @param  array  $config
     * @return \Illuminate\Auth\RequestGuard
     */
    protected function makeGuard(array $config)
    {
        return new RequestGuard(function ($request) use ($config) {
            return (new TokenValidationGuard(
                $config['public_key_path'],
                $config['hydrator']
            ))->user($request);
        }, $this->app['request']);
    }
}
