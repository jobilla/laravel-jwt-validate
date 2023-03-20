<?php

namespace Jobilla\JwtValidate\Tests;

use Illuminate\Http\Request;
use Jobilla\JwtValidate\TokenValidationGuard;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use PHPUnit\Framework\TestCase;

class GuardTest extends TestCase
{
    public function test_it_returns_null_user_if_there_is_no_bearer_token()
    {
        $guard = new TokenValidationGuard(__DIR__.'/fixtures/public.key', function () {});

        $this->assertNull($guard->user(new Request()));
    }

    public function test_it_returns_null_user_if_the_wrong_public_key_is_used()
    {
        $guard = new TokenValidationGuard(__DIR__.'/fixtures/invalid-public.key', function () {});

        $jwt = (new Builder())
            ->setIssuer('http://example.com')
            ->setAudience('http://example.org')
            ->setId('jobilla-test', true)
            ->setIssuedAt(time())
            ->setExpiration(time() + 3600)
            ->sign(new Sha256(), 'file://'.__DIR__.'/fixtures/private.key')
            ->getToken();
        $request = new Request([], [], [], [], [], ['HTTP_AUTHORIZATION' => 'Bearer '.$jwt]);

        $this->assertNull($guard->user($request));
    }

    public function test_it_hydrates_a_model_from_a_valid_jwt()
    {
        $guard = new TokenValidationGuard(__DIR__.'/fixtures/public.key', function ($claims) {
            $user = new \stdClass;
            $user->id = $claims['jti'];
            $user->name = $claims['name'];
            $user->company = $claims['company'];

            return $user;
        });

        $jwt = (new Builder())
            ->setIssuer('http://example.com')
            ->setAudience('http://example.org')
            ->setId('rob-stark', true)
            ->setIssuedAt(time())
            ->setExpiration(time() + 3600)
            ->set('company', 'The Seven Kingdoms Ltd.')
            ->set('name', 'Rob Stark')
            ->sign(new Sha256(), 'file://'.__DIR__.'/fixtures/private.key')
            ->getToken();
        $request = new Request([], [], [], [], [], ['HTTP_AUTHORIZATION' =>'Bearer '.$jwt]);

        $user = $guard->user($request);

        $this->assertEquals('rob-stark', $user->id);
        $this->assertEquals('Rob Stark', $user->name);
        $this->assertEquals('The Seven Kingdoms Ltd.', $user->company);
    }
}
