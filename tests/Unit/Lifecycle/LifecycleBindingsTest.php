<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleBindings;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleService;
use Tests\TestCase;

/**
 * Tests for `LifecycleBindings`: the lifecycle service is shared.
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
}
