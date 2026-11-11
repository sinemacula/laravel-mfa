<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * What a sign-in must prove after its first factor, judged before any tenant is
 * active; empty when nothing further is needed.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface RequirementPolicy
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    public function requirementFor(MultiFactorAuthenticatable $identity, string $application, Proof $firstFactor): Requirement;
}
