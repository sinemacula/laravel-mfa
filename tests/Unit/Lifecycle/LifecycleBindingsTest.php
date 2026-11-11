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
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LifecycleBindings::class)]
final class LifecycleBindingsTest extends TestCase
{
    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBuildsTheServiceOnEveryResolution(): void
    {
        self::assertFalse($this->container()->isShared(LifecycleService::class));
        self::assertTrue($this->container()->bound(LifecycleService::class));
        self::assertNotSame($this->container()->make(LifecycleService::class), $this->container()->make(LifecycleService::class));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsTheRequiredFactorPolicyByDefault(): void
    {
        self::assertInstanceOf(RequiredFactorPolicy::class, $this->container()->make(LastFactorPolicy::class));
        self::assertFalse($this->container()->isShared(LastFactorPolicy::class));

        $own = \Mockery::mock(LastFactorPolicy::class);

        $this->container()->instance(LastFactorPolicy::class, $own);

        self::assertSame($own, $this->container()->make(LastFactorPolicy::class));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsNoSelfServiceRecoveryByDefault(): void
    {
        self::assertInstanceOf(NoSelfServiceRecovery::class, $this->container()->make(SelfServiceRecovery::class));
        self::assertFalse($this->container()->isShared(SelfServiceRecovery::class));
    }
}
