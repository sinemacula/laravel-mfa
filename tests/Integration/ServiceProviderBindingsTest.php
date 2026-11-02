<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Illuminate\Routing\Router;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Codes\NullEmailSender;
use SineMacula\Laravel\Mfa\Codes\NullSmsSender;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\RequirementPolicy;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Http\Middleware\EnsureMfaRequirementIsMet;
use SineMacula\Laravel\Mfa\Http\Middleware\ExemptFromMfa;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredRequirementPolicy;
use Tests\TestCase;

/**
 * Integration test for the service provider's container bindings.
 *
 * Asserts every contract the provider binds resolves to the shipped default,
 * and the middleware aliases are registered on the router.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaServiceProvider::class)]
final class ServiceProviderBindingsTest extends TestCase
{
    /**
     * The `'mfa'` alias must resolve to the same `MfaManager` instance every
     * time — the manager is registered as a singleton.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testMfaManagerIsSingleton(): void
    {
        $first  = $this->container()->make('mfa');
        $second = $this->container()->make('mfa');

        self::assertInstanceOf(MfaManager::class, $first);
        self::assertSame($first, $second);
    }

    /**
     * Without a consumer override the `RequirementPolicy` contract must resolve
     * to the shipped `ConfiguredRequirementPolicy`, which reads the
     * application's configured mode.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testDefaultRequirementPolicyIsConfigured(): void
    {
        $policy = $this->container()->make(RequirementPolicy::class);

        self::assertInstanceOf(ConfiguredRequirementPolicy::class, $policy);
    }

    /**
     * Without a consumer override the `FreshnessGate` contract must resolve to
     * the shipped `ConfiguredFreshnessGate`, which reads the proof store.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testDefaultFreshnessGateIsConfigured(): void
    {
        $gate = $this->container()->make(FreshnessGate::class);

        self::assertInstanceOf(ConfiguredFreshnessGate::class, $gate);
    }

    /**
     * Without a consumer override the `ProofStore` contract must resolve to the
     * session-backed default.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testDefaultProofStoreIsSessionBacked(): void
    {
        $store = $this->container()->make(ProofStore::class);

        self::assertInstanceOf(SessionProofStore::class, $store);
    }

    /**
     * Without a consumer override the `SmsSender` and `EmailSender` contracts
     * must resolve to the loud-failing null defaults.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testDefaultSendersAreNull(): void
    {
        self::assertInstanceOf(NullSmsSender::class, $this->container()->make(SmsSender::class));
        self::assertInstanceOf(NullEmailSender::class, $this->container()->make(EmailSender::class));
    }

    /**
     * The provider must register the `'mfa'` and `'mfa.exempt'` middleware
     * aliases against the router.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testMiddlewareAliasesAreRegistered(): void
    {
        $router  = $this->container()->make(Router::class);
        $aliases = $router->getMiddleware();

        self::assertArrayHasKey('mfa', $aliases);
        self::assertArrayHasKey('mfa.exempt', $aliases);

        self::assertSame(EnsureMfaRequirementIsMet::class, $aliases['mfa']);
        self::assertSame(ExemptFromMfa::class, $aliases['mfa.exempt']);
    }
}
