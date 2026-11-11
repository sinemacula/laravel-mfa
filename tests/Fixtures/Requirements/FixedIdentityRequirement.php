<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Requirements;

use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * An identity requirement that always asks the same of every identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FixedIdentityRequirement implements IdentityRequirement
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     */
    public function __construct(

        /** What every identity must prove. */
        private Requirement $requirement,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    #[\Override]
    public function requirementFor(MultiFactorAuthenticatable $identity, string $application): Requirement
    {
        return $this->requirement;
    }
}
