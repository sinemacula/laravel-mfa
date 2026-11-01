<?php

declare(strict_types = 1);

namespace Tests\Unit\Assurance;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Assurance\AssuranceBindings;
use SineMacula\Laravel\Mfa\Assurance\DefaultCombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use Tests\TestCase;

/**
 * Tests for `AssuranceBindings`: the default combination policy is bound and
 * shared.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AssuranceBindings::class)]
final class AssuranceBindingsTest extends TestCase
{
    /**
     * The default combination policy is bound, and is shared.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsTheDefaultPolicyAsASingleton(): void
    {
        self::assertTrue($this->container()->isShared(CombinationPolicy::class));
        self::assertInstanceOf(DefaultCombinationPolicy::class, $this->container()->make(CombinationPolicy::class));
        self::assertSame($this->container()->make(CombinationPolicy::class), $this->container()->make(CombinationPolicy::class));
    }
}
