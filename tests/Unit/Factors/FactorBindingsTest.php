<?php

declare(strict_types = 1);

namespace Tests\Unit\Factors;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Factors\FactorBindings;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\Factors\FactorStateCache;
use Tests\TestCase;

/**
 * Tests for `FactorBindings`: the factor services are shared, so every service
 * clears the one cache the reads are served from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorBindings::class)]
final class FactorBindingsTest extends TestCase
{
    /**
     * The factor service and the state cache are singletons.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRegistersTheFactorServicesAsSingletons(): void
    {
        foreach ([FactorService::class, FactorStateCache::class] as $service) {
            self::assertTrue($this->container()->isShared($service));
            self::assertSame($this->container()->make($service), $this->container()->make($service));
        }
    }
}
