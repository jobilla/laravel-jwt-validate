<?php

namespace Jobilla\JwtValidate\Tests;

use DateTimeImmutable;
use Illuminate\Http\Request;
use Jobilla\JwtValidate\TokenValidationGuard;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use PHPUnit\Framework\TestCase;

class GuardTest extends TestCase
{
    public function test_it_returns_null_user_if_there_is_no_bearer_token()
    {
        $guard = new TokenValidationGuard(Configuration::forSymmetricSigner(new Sha256(), InMemory::file(__DIR__.'/fixtures/public.key')), function () {});

        $this->assertNull($guard->user(new Request()));
    }

    public function test_it_returns_null_user_if_the_wrong_public_key_is_used()
    {
        $now    = new DateTimeImmutable();
        $config = Configuration::forSymmetricSigner(new Sha256(), InMemory::file(__DIR__.'/fixtures/public.key'));
        $guard  = new TokenValidationGuard($config, function () {});

        $config->setValidationConstraints(
            new SignedWith($config->signer(), $config->signingKey()),
            new IssuedBy('http://example.com')
        );

        $jwt = $config->builder()
            ->issuedBy('http://example.com')
            ->permittedFor('http://example.org')
            ->identifiedBy('jobilla-test')
            ->issuedAt($now)
            ->expiresAt($now->modify('+1 hour'))
            ->getToken($config->signer(), $config->signingKey());

        $request = new Request([], [], [], [], [], ['HTTP_AUTHORIZATION' => 'Bearer '.$jwt->toString()]);

        $this->assertNull($guard->user($request));
    }

    public function test_it_hydrates_a_model_from_a_valid_jwt()
    {
        $now    = new DateTimeImmutable();
        $config = Configuration::forSymmetricSigner(new Sha256(), InMemory::file(__DIR__.'/fixtures/public.key'));
        $guard  = new TokenValidationGuard($config, function ($claims) {
            $user = new \stdClass();
            $user->id = $claims['jti'];
            $user->name = $claims['name'];
            $user->company = $claims['company'];

            return $user;
        });

        $config->setValidationConstraints(
            new SignedWith($config->signer(), $config->signingKey()),
            new IssuedBy('http://example.com')
        );

        $jwt = $config->builder()
            ->issuedBy('http://example.com')
            ->permittedFor('http://example.org')
            ->identifiedBy('rob-stark')
            ->issuedAt($now)
            ->expiresAt($now->modify('+1 hour'))
            ->withClaim('company', 'The Seven Kingdoms Ltd.')
            ->withClaim('name', 'Rob Stark')
            ->getToken($config->signer(), $config->signingKey());

        $request = new Request([], [], [], [], [], ['HTTP_AUTHORIZATION' =>'Bearer '.$jwt->toString()]);

        $user = $guard->user($request);

        $this->assertEquals('rob-stark', $user->id);
        $this->assertEquals('Rob Stark', $user->name);
        $this->assertEquals('The Seven Kingdoms Ltd.', $user->company);
    }
}
