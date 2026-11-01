<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Contracts\RequirementPolicy;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredRequirementPolicy;
use SineMacula\Laravel\Mfa\Requirements\IdentityContractRequirement;
use SineMacula\Laravel\Mfa\Requirements\NoTenantRequirement;
use SineMacula\Laravel\Mfa\Requirements\ProofRequirementCheck;
use SineMacula\Laravel\Mfa\Requirements\RequirementBindings;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use Tests\TestCase;

/**
 * Tests for `RequirementBindings`: the requirement service is shared, and each
 * requirement seam is bound to its default, shared.
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
     * Rows of a requirement seam and its default.
     *
     * @return iterable<string, array{class-string, class-string}>
     */
    public static function seams(): iterable
    {
        yield 'the requirement policy' => [RequirementPolicy::class, ConfiguredRequirementPolicy::class];
        yield 'the identity requirement' => [IdentityRequirement::class, IdentityContractRequirement::class];
        yield 'the tenant requirement' => [TenantRequirement::class, NoTenantRequirement::class];
        yield 'the requirement check' => [RequirementCheck::class, ProofRequirementCheck::class];
        yield 'the freshness gate' => [FreshnessGate::class, ConfiguredFreshnessGate::class];
    }

    /**
     * Each seam is bound to its default, and shared.
     *
     * @param  class-string  $seam
     * @param  class-string  $default
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('seams')]
    public function testBindsEachSeamToItsDefaultAsASingleton(string $seam, string $default): void
    {
        self::assertInstanceOf($default, $this->container()->make($seam));
        self::assertSame($this->container()->make($seam), $this->container()->make($seam));
    }
}
