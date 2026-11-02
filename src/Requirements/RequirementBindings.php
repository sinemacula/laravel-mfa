<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Applications\DeclaredFirstFactorResolver;
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
 * (`IdentityContractRequirement`), no tenant requirement
 * (`NoTenantRequirement`), the check of a session's proofs through the
 * combination policy (`ProofRequirementCheck`), the freshness of a named
 * operation from the proof store (`ConfiguredFreshnessGate`), and the first
 * factor the application declares (`Applications\DeclaredFirstFactorResolver`),
 * which the freshness gate reads. An adapter, or the application, rebinds any
 * of the contracts in its own service provider.
 *
 * Every default keeps no state between calls and resolves what it reads on each
 * one, so each is shared.
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
        $app->singleton(RequirementService::class);
        $app->singleton(RequirementPolicy::class, ConfiguredRequirementPolicy::class);
        $app->singleton(IdentityRequirement::class, IdentityContractRequirement::class);
        $app->singleton(TenantRequirement::class, NoTenantRequirement::class);
        $app->singleton(RequirementCheck::class, ProofRequirementCheck::class);
        $app->singleton(FreshnessGate::class, ConfiguredFreshnessGate::class);
        $app->singleton(FirstFactorResolver::class, DeclaredFirstFactorResolver::class);
    }
}
