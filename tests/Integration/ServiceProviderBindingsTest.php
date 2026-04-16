<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Illuminate\Routing\Router;
use SineMacula\Laravel\Mfa\Contracts\MfaPolicy;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\Contracts\SmsGateway;
use SineMacula\Laravel\Mfa\Gateways\NullSmsGateway;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Middleware\RequireMfa;
use SineMacula\Laravel\Mfa\Middleware\SkipMfa;
use SineMacula\Laravel\Mfa\Policies\NullMfaPolicy;
use SineMacula\Laravel\Mfa\Stores\SessionMfaVerificationStore;
use Tests\TestCase;

/**
 * Integration test for the service provider's container bindings.
 *
 * Asserts every contract the provider binds resolves to the
 * shipped default, and the middleware aliases are registered on
 * the router.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class ServiceProviderBindingsTest extends TestCase
{
    public function testMfaManagerIsSingleton(): void
    {
        $a = $this->app->make('mfa');
        $b = $this->app->make('mfa');

        self::assertInstanceOf(MfaManager::class, $a);
        self::assertSame($a, $b);
    }

    public function testDefaultMfaPolicyIsNull(): void
    {
        $policy = $this->app->make(MfaPolicy::class);

        self::assertInstanceOf(NullMfaPolicy::class, $policy);
    }

    public function testDefaultVerificationStoreIsSessionBacked(): void
    {
        $store = $this->app->make(MfaVerificationStore::class);

        self::assertInstanceOf(SessionMfaVerificationStore::class, $store);
    }

    public function testDefaultSmsGatewayIsNull(): void
    {
        $gateway = $this->app->make(SmsGateway::class);

        self::assertInstanceOf(NullSmsGateway::class, $gateway);
    }

    public function testMiddlewareAliasesAreRegistered(): void
    {
        $router  = $this->app->make(Router::class);
        $aliases = $router->getMiddleware();

        self::assertArrayHasKey('mfa', $aliases);
        self::assertArrayHasKey('mfa.skip', $aliases);

        self::assertSame(RequireMfa::class, $aliases['mfa']);
        self::assertSame(SkipMfa::class, $aliases['mfa.skip']);
    }
}
