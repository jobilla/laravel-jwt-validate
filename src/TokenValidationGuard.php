<?php

namespace Jobilla\JwtValidate;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Http\Request;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;

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
        if (!$request->bearerToken()) {
            return null;
        }

        try {
            $token = app(Parser::class)->parse($request->bearerToken());

            if (!$token->verify(new Sha256(), 'file://' . $this->publicKeyPath)) {
                return null;
            }
        } catch (\Exception $e) {
            return null;
        }

        return call_user_func_array($this->userHydrator, [$token->getClaims(), $request]);
    }
}
