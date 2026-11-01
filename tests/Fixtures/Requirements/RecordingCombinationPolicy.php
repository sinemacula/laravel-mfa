<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Requirements;

use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\DefaultCombinationPolicy;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * A combination policy that records the proofs each evaluation is given, then
 * answers as the package's default does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingCombinationPolicy implements CombinationPolicy
{
    /** @var list<list<\SineMacula\Laravel\Mfa\Proofs\Proof>> The proofs each evaluation was given, in order. */
    public array $handed = [];

    /**
     * Whether a factor may follow the first factor, as the default answers.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $factor
     * @return bool
     */
    #[\Override]
    public function accepts(Proof $firstFactor, Channel $factor): bool
    {
        return (new DefaultCombinationPolicy)->accepts($firstFactor, $factor);
    }

    /**
     * Record the proofs, then evaluate them as the default does.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  ...$proofs
     * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
     */
    #[\Override]
    public function evaluate(Requirement $requirement, Proof ...$proofs): Evaluation
    {
        $this->handed[] = array_values($proofs);

        return (new DefaultCombinationPolicy)->evaluate($requirement, ...$proofs);
    }
}
