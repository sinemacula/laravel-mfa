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
 * Registers the requirement service and the defaults of the requirement seams:
 * the sign-in requirement from the application's configured mode
 * (`ConfiguredRequirementPolicy`), the identity's own from its model
 * (`IdentityContractRequirement`), no active tenant (`NoActiveTenant`) and no
 * tenant requirement (`NoTenantRequirement`), the check of a session's proofs
 * through the combination policy (`ProofRequirementCheck`), the freshness of a
 * named operation from the proof store (`ConfiguredFreshnessGate`), the
 * authorisation of a factor change on that freshness and the bound
 * reauthenticator (`ConfiguredFactorChangeGate`), and the first factor the
 * application declares (`Applications\DeclaredFirstFactorResolver`), which the
 * freshness gate reads. An adapter, or the application, rebinds any of the
 * contracts in its own service provider.
 *
 * Every default keeps no state between calls and resolves what it reads on each
 * one, and is built when it is asked for, on the application serving at the
 * time.
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
     * Register the requirement service and the default requirement seams.
     *
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
