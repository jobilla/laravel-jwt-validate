<?php

namespace Jobilla\JwtValidate;

use Lcobucci\JWT\Configuration;
use Illuminate\Http\Request;
use Illuminate\Auth\GuardHelpers;

class TokenValidationGuard
{
    use GuardHelpers;

    /**
     * @var Configuration
     */
    private $config;

    /**
     * @var callable
     */
    private $userHydrator;

    public function __construct(Configuration $config, callable $userHydrator)
    {
        $this->config        = $config;
        $this->userHydrator  = $userHydrator;
    }

    public function user(Request $request)
    {
        if (! $request->bearerToken()) {
            return null;
        }

        try {
            $token = $this->config->parser()->parse($request->bearerToken());

            if (!$this->config->validator()->validate($token, ...$this->config->validationConstraints())) {
                return null;
            }
        } catch (\Exception $e) {
            return null;
        }

        return call_user_func_array($this->userHydrator, [$token->claims()->all(), $request]);
    }
}
