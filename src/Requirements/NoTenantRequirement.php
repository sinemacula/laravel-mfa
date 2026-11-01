<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;

/**
 * The default `TenantRequirement`: no tenant requires anything. The package
 * never sees a tenant tree, so which tenant requires what is the application's
 * policy, or an adapter's, bound in place of this one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class NoTenantRequirement implements TenantRequirement
{
    /**
     * The requirement of the identity's active tenant on the application:
     * none.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $tenant
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    #[\Override]
    public function requirementFor(MultiFactorAuthenticatable $identity, string $application, string $tenant): Requirement
    {
        return Requirement::none();
    }
}
