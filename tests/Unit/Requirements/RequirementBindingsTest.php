<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Applications\DeclaredFirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Contracts\RequirementPolicy;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFactorChangeGate;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredRequirementPolicy;
use SineMacula\Laravel\Mfa\Requirements\IdentityContractRequirement;
use SineMacula\Laravel\Mfa\Requirements\NoActiveTenant;
use SineMacula\Laravel\Mfa\Requirements\NoTenantRequirement;
use SineMacula\Laravel\Mfa\Requirements\ProofRequirementCheck;
use SineMacula\Laravel\Mfa\Requirements\RequirementBindings;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequirementBindings::class)]
final class RequirementBindingsTest extends TestCase
{
    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBuildsTheServiceOnEveryResolution(): void
    {
        self::assertFalse($this->container()->isShared(RequirementService::class));
        self::assertTrue($this->container()->bound(RequirementService::class));
        self::assertNotSame($this->container()->make(RequirementService::class), $this->container()->make(RequirementService::class));
    }

    /**
     * @return iterable<string, array{class-string, class-string}>
     */
    public static function seams(): iterable
    {
        yield 'the requirement policy' => [RequirementPolicy::class, ConfiguredRequirementPolicy::class];
        yield 'the identity requirement' => [IdentityRequirement::class, IdentityContractRequirement::class];
        yield 'the active tenant' => [ActiveTenantResolver::class, NoActiveTenant::class];
        yield 'the tenant requirement' => [TenantRequirement::class, NoTenantRequirement::class];
        yield 'the requirement check' => [RequirementCheck::class, ProofRequirementCheck::class];
        yield 'the freshness gate' => [FreshnessGate::class, ConfiguredFreshnessGate::class];
        yield 'the factor change gate' => [FactorChangeGate::class, ConfiguredFactorChangeGate::class];
        yield 'the first factor resolver' => [FirstFactorResolver::class, DeclaredFirstFactorResolver::class];
    }

    /**
     * @param  class-string  $seam
     * @param  class-string  $default
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('seams')]
    public function testBindsEachSeamToItsDefaultAfreshOnEveryResolution(string $seam, string $default): void
    {
        self::assertInstanceOf($default, $this->container()->make($seam));
        self::assertNotSame($this->container()->make($seam), $this->container()->make($seam));
    }
}
