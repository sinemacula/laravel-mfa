<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Testing;

use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\DefaultCombinationPolicy;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\KeyProtection;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * A policy that answers as the default does, except that it rates a session
 * holding a hardware-bound, verified, phishing-resistant proof AAL3, as an
 * application whose authenticators it has vetted might.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LeveledCombinationPolicy implements CombinationPolicy
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
     * As the default answers, at AAL3 when a proof observed all it takes.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  ...$proofs
     * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
     */
    #[\Override]
    public function evaluate(Requirement $requirement, Proof ...$proofs): Evaluation
    {
        $evaluation = (new DefaultCombinationPolicy)->evaluate($requirement, ...$proofs);

        foreach ($proofs as $proof) {
            $properties = $proof->properties;

            if ($properties->userVerification === true && $properties->phishingResistance === true && $properties->keyProtection === KeyProtection::HARDWARE) {
                return new Evaluation(
                    accepted: true,
                    multifactor: true,
                    level: AssuranceLevel::AAL3,
                    phishingResistant: true,
                    restricted: false,
                    amr: $evaluation->amr,
                    met: [...$evaluation->met, ...$evaluation->unmet],
                    unmet: [],
                );
            }
        }

        return $evaluation;
    }
}
