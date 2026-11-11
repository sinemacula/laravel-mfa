<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * What a combination of proofs establishes, derived only from what the proofs
 * observed; a rebinding may be stricter, never claim more.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface CombinationPolicy
{
    /**
     * Whether a factor on the channel is independent of the first factor; one
     * refused is neither offered nor verified.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $factor
     * @return bool
     */
    public function accepts(Proof $firstFactor, Channel $factor): bool;

    /**
     * What the session's proofs, the first factor's included, establish and
     * which parts of the requirement they meet.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  ...$proofs
     * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
     */
    public function evaluate(Requirement $requirement, Proof ...$proofs): Evaluation;
}
