<?php

namespace Jobilla\JwtValidate;

use Lcobucci\JWT\Parser;
use Illuminate\Http\Request;
use Illuminate\Auth\GuardHelpers;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Illuminate\Auth\AuthenticationException;

class TokenValidationGuard
{
    use GuardHelpers;

    /**
     * @var string
     */
    private $publicKeyPath;

    /**
     * @var callable
     */
    private $userHydrator;

    public function __construct(string $publicKeyPath, callable $userHydrator)
    {
        $this->publicKeyPath = $publicKeyPath;
        $this->userHydrator  = $userHydrator;
    }

    public function user(Request $request)
    {
        if (! $request->bearerToken()) {
            throw new AuthenticationException;
        }

        try {
            $token = (new Parser)->parse($request->bearerToken());

            if (! $token->verify(new Sha256(), 'file://'.$this->publicKeyPath)) {
                throw new AuthenticationException;
            }
        } catch (\Exception $e) {
            throw new AuthenticationException;
        }

        return call_user_func_array($this->userHydrator, [$token->getClaims(), $request]);
    }
}
