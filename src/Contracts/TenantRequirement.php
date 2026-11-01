<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Tenant requirement contract.
 *
 * What the active tenant's authentication policy requires of the session, as
 * this package's requirement. The tenant is an opaque id: which tenant requires
 * what is the application's policy, and this package never sees the tenant
 * tree. An empty requirement adds nothing to the others.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface TenantRequirement
{
    /**
     * The requirement of the identity's active tenant on the application.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $tenant
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    public function requirementFor(MultiFactorAuthenticatable $identity, string $application, string $tenant): Requirement;
}
