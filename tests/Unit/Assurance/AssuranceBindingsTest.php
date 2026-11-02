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
 * built afresh.
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
     * The default combination policy is bound, and is built afresh.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsTheDefaultPolicyAfreshOnEveryResolution(): void
    {
        self::assertFalse($this->container()->isShared(CombinationPolicy::class));
        self::assertInstanceOf(DefaultCombinationPolicy::class, $this->container()->make(CombinationPolicy::class));
        self::assertNotSame($this->container()->make(CombinationPolicy::class), $this->container()->make(CombinationPolicy::class));
    }
}
