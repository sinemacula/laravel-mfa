<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Requirement policy contract.
 *
 * Asked after the first factor, at the identity level and before any principal
 * is chosen, what the sign-in must prove further: given the identity, the
 * application and the first factor's proof (its method, channel, observed
 * properties and time, not the method alone), it answers with a requirement,
 * empty when no further proof is needed. The answer is composed from every
 * source of a requirement (the application, the identity, a re-enrolment
 * obligation and the active tenant), the strictest applying.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface RequirementPolicy
{
    /**
     * The requirement the sign-in must meet after its first factor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    public function requirementFor(MultiFactorAuthenticatable $identity, string $application, Proof $firstFactor): Requirement;
}
