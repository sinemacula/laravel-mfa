<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Enrollment;

use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\DefaultCombinationPolicy;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * A combination policy that answers as the default does, without saying when an
 * evaluation stops meeting its requirement, as one written before that was
 * asked would.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UndatedCombinationPolicy implements CombinationPolicy
{
    /**
     * As the default answers.
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
     * As the default answers, without the time.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  ...$proofs
     * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
     */
    #[\Override]
    public function evaluate(Requirement $requirement, Proof ...$proofs): Evaluation
    {
        $evaluation = (new DefaultCombinationPolicy)->evaluate($requirement, ...$proofs);

        return new Evaluation(
            $evaluation->accepted,
            $evaluation->multifactor,
            $evaluation->level,
            $evaluation->phishingResistant,
            $evaluation->restricted,
            $evaluation->amr,
            $evaluation->met,
            $evaluation->unmet,
        );
    }
}
