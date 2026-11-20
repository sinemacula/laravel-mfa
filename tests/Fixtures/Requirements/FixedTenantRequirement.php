<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Requirements;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * A tenant requirement that asks the same in every tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FixedTenantRequirement implements TenantRequirement
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     */
    public function __construct(

        /** What every tenant requires. */
        private Requirement $requirement,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $tenant
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    #[\Override]
    public function requirementFor(MultiFactorAuthenticatable $identity, string $application, string $tenant): Requirement
    {
        return $this->requirement;
    }
}
