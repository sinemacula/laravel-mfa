<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Combination policy contract.
 *
 * Decides whether a factor may serve as the further factor after a given first
 * factor, and what a combination of proofs establishes: whether it is accepted
 * as an additional verification, whether it is multifactor, the assurance level
 * it supports, whether it is phishing-resistant or restricted, and the `amr`
 * values it reports. Every answer is derived from what the proofs actually
 * observed, never from a factor's type or from configuration.
 *
 * A first factor whose method or channel is unknown, or not supplied by a
 * trusted source, accepts no factor and establishes no level. An application
 * may rebind the policy to be stricter than the package's, never to claim a
 * property no proof observed.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface CombinationPolicy
{
    /**
     * Whether a factor on the given channel may serve as the further factor
     * after the first factor. A factor that shares the first factor's channel
     * is not independent of it: one the policy refuses is neither offered on
     * the session nor verified on it.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $factor
     * @return bool
     */
    public function accepts(Proof $firstFactor, Channel $factor): bool;

    /**
     * Evaluate a combination of proofs against a requirement: what the
     * combination establishes, and which parts of the requirement it meets. The
     * proofs are the session's, the first factor's included.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  ...$proofs
     * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
     */
    public function evaluate(Requirement $requirement, Proof ...$proofs): Evaluation;
}
