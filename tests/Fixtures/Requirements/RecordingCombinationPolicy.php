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
 * Records the proofs each evaluation is given, then answers as the default
 * policy does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingCombinationPolicy implements CombinationPolicy
{
    /** @var list<list<\SineMacula\Laravel\Mfa\Proofs\Proof>> */
    public array $handed = [];

    /**
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
