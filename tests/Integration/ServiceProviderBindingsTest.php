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
 * Asserts every contract the provider binds resolves to the shipped default,
 * and the middleware aliases are registered on the router.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class ServiceProviderBindingsTest extends TestCase
{
    /**
     * The `'mfa'` alias must resolve to the same `MfaManager` instance every
     * time — the manager is registered as a singleton.
     *
     * @return void
     */
    public function testMfaManagerIsSingleton(): void
    {
        $first  = $this->container()->make('mfa');
        $second = $this->container()->make('mfa');

        self::assertInstanceOf(MfaManager::class, $first);
        self::assertSame($first, $second);
    }

    /**
     * Without a consumer override the `MfaPolicy` contract must resolve to the
     * shipped `NullMfaPolicy`.
     *
     * @return void
     */
    public function testDefaultMfaPolicyIsNull(): void
    {
        $policy = $this->container()->make(MfaPolicy::class);

        self::assertInstanceOf(NullMfaPolicy::class, $policy);
    }

    /**
     * Without a consumer override the `MfaVerificationStore` contract must
     * resolve to the session-backed default.
     *
     * @return void
     */
    public function testDefaultVerificationStoreIsSessionBacked(): void
    {
        $store = $this->container()->make(MfaVerificationStore::class);

        self::assertInstanceOf(SessionMfaVerificationStore::class, $store);
    }

    /**
     * Without a consumer override the `SmsGateway` contract must resolve to the
     * loud-failing `NullSmsGateway` default.
     *
     * @return void
     */
    public function testDefaultSmsGatewayIsNull(): void
    {
        $gateway = $this->container()->make(SmsGateway::class);

        self::assertInstanceOf(NullSmsGateway::class, $gateway);
    }

    /**
     * The provider must register the `'mfa'` and `'mfa.skip'` middleware
     * aliases against the router.
     *
     * @return void
     */
    public function testMiddlewareAliasesAreRegistered(): void
    {
        $router  = $this->container()->make(Router::class);
        $aliases = $router->getMiddleware();

        self::assertArrayHasKey('mfa', $aliases);
        self::assertArrayHasKey('mfa.skip', $aliases);

        self::assertSame(RequireMfa::class, $aliases['mfa']);
        self::assertSame(SkipMfa::class, $aliases['mfa.skip']);
    }
}
