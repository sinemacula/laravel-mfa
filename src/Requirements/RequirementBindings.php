<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Applications\DeclaredFirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Contracts\RequirementPolicy;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Support\PackageDefault;

/**
 * Registers the requirement service and the default requirement seams, each
 * stateless and resolved when asked for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RequirementBindings
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function register(Application $app): void
    {
        $app->bindIf(RequirementService::class);
        PackageDefault::bind($app, RequirementPolicy::class, ConfiguredRequirementPolicy::class);
        PackageDefault::bind($app, IdentityRequirement::class, IdentityContractRequirement::class);
        PackageDefault::bind($app, TenantRequirement::class, NoTenantRequirement::class);
        PackageDefault::bind($app, ActiveTenantResolver::class, NoActiveTenant::class);
        PackageDefault::bind($app, RequirementCheck::class, ProofRequirementCheck::class);
        PackageDefault::bind($app, FreshnessGate::class, ConfiguredFreshnessGate::class);
        PackageDefault::bind($app, FactorChangeGate::class, ConfiguredFactorChangeGate::class);
        PackageDefault::bind($app, FirstFactorResolver::class, DeclaredFirstFactorResolver::class);
    }
}
