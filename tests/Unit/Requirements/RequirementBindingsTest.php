<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\MfaPolicy;
use SineMacula\Laravel\Mfa\Requirements\NullMfaPolicy;
use SineMacula\Laravel\Mfa\Requirements\RequirementBindings;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use Tests\TestCase;

/**
 * Tests for `RequirementBindings`: the requirement service is shared, and the
 * default policy enforces nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequirementBindings::class)]
final class RequirementBindingsTest extends TestCase
{
    /**
     * The requirement service is a singleton.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRegistersTheServiceAsASingleton(): void
    {
        self::assertTrue($this->container()->isShared(RequirementService::class));
        self::assertSame($this->container()->make(RequirementService::class), $this->container()->make(RequirementService::class));
    }

    /**
     * The default policy enforces nothing, and is shared.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsTheNullPolicyAsASingleton(): void
    {
        self::assertInstanceOf(NullMfaPolicy::class, $this->container()->make(MfaPolicy::class));
        self::assertSame($this->container()->make(MfaPolicy::class), $this->container()->make(MfaPolicy::class));
    }
}
