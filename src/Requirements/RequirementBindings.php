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
        $app->bindIf(RequirementPolicy::class, ConfiguredRequirementPolicy::class);
        $app->bindIf(IdentityRequirement::class, IdentityContractRequirement::class);
        $app->bindIf(TenantRequirement::class, NoTenantRequirement::class);
        $app->bindIf(ActiveTenantResolver::class, NoActiveTenant::class);
        $app->bindIf(RequirementCheck::class, ProofRequirementCheck::class);
        $app->bindIf(FreshnessGate::class, ConfiguredFreshnessGate::class);
        $app->bindIf(FactorChangeGate::class, ConfiguredFactorChangeGate::class);
        $app->bindIf(FirstFactorResolver::class, DeclaredFirstFactorResolver::class);
    }
}
