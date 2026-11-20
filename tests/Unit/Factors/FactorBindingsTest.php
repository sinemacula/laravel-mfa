<?php

declare(strict_types = 1);

namespace Tests\Unit\Factors;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Factors\FactorBindings;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\Support\FactorStateLocks;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorBindings::class)]
final class FactorBindingsTest extends TestCase
{
    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBuildsTheFactorServiceOnEveryResolution(): void
    {
        self::assertFalse($this->container()->isShared(FactorService::class));
        self::assertTrue($this->container()->bound(FactorService::class));
        self::assertNotSame($this->container()->make(FactorService::class), $this->container()->make(FactorService::class));
    }

    /**
     * One per request, shared by a factor state callback and its reads.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testSharesTheFactorStateLocks(): void
    {
        self::assertSame($this->container()->make(FactorStateLocks::class), $this->container()->make(FactorStateLocks::class));
    }
}
