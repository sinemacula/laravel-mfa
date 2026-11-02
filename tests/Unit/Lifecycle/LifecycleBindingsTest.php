<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\LastFactorPolicy;
use SineMacula\Laravel\Mfa\Contracts\SelfServiceRecovery;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleBindings;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleService;
use SineMacula\Laravel\Mfa\Lifecycle\NoSelfServiceRecovery;
use SineMacula\Laravel\Mfa\Lifecycle\RequiredFactorPolicy;
use Tests\TestCase;

/**
 * Tests for `LifecycleBindings`: the lifecycle service is shared, and the last
 * factor policy defaults to `RequiredFactorPolicy`, which an application may
 * rebind.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LifecycleBindings::class)]
final class LifecycleBindingsTest extends TestCase
{
    /**
     * The lifecycle service is a singleton.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRegistersTheServiceAsASingleton(): void
    {
        self::assertTrue($this->container()->isShared(LifecycleService::class));
        self::assertSame($this->container()->make(LifecycleService::class), $this->container()->make(LifecycleService::class));
    }

    /**
     * The last factor policy defaults to the required factor policy, shared,
     * and a binding of the application's own replaces it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsTheRequiredFactorPolicyByDefault(): void
    {
        self::assertInstanceOf(RequiredFactorPolicy::class, $this->container()->make(LastFactorPolicy::class));
        self::assertTrue($this->container()->isShared(LastFactorPolicy::class));

        $own = \Mockery::mock(LastFactorPolicy::class);

        $this->container()->instance(LastFactorPolicy::class, $own);

        self::assertSame($own, $this->container()->make(LastFactorPolicy::class));
    }

    /**
     * Self-service recovery defaults to none, shared.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsNoSelfServiceRecoveryByDefault(): void
    {
        self::assertInstanceOf(NoSelfServiceRecovery::class, $this->container()->make(SelfServiceRecovery::class));
        self::assertTrue($this->container()->isShared(SelfServiceRecovery::class));
    }
}
