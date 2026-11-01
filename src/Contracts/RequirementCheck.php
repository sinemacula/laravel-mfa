<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Requirement check contract.
 *
 * Whether a session's proofs meet a requirement, the same answer wherever it is
 * asked: at sign-in, in a tenant's policy and on step-up. Each part is judged
 * on the newest proof that meets it within its maximum age, so a fresh weaker
 * proof never refreshes an old stronger one, and a fresh first factor never
 * stands in for an additional factor.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface RequirementCheck
{
    /**
     * Evaluate the session's proofs against the requirement.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  ...$proofs
     * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
     */
    public function check(Requirement $requirement, Proof ...$proofs): Evaluation;
}
