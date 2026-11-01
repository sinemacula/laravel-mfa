<?php

declare(strict_types = 1);

namespace Tests\Unit\Factors;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Factors\FactorBindings;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use Tests\TestCase;

/**
 * Tests for `FactorBindings`: the factor service is shared.
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
     * The factor service is a singleton.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRegistersTheFactorServiceAsASingleton(): void
    {
        self::assertTrue($this->container()->isShared(FactorService::class));
        self::assertSame($this->container()->make(FactorService::class), $this->container()->make(FactorService::class));
    }
}
