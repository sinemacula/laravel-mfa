<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Assurance;

use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\DefaultCombinationPolicy;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * The assurance guide's stricter policy: no SMS factor after a phone code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class NoSmsAfterPhoneCode implements CombinationPolicy
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Assurance\DefaultCombinationPolicy  $default
     */
    public function __construct(

        /** Decides everything this policy does not refuse. */
        private DefaultCombinationPolicy $default,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $factor
     * @return bool
     */
    #[\Override]
    public function accepts(Proof $firstFactor, Channel $factor): bool
    {
        if ($firstFactor->channel?->kind === ChannelKind::SMS && $factor->kind === ChannelKind::SMS) {
            return false;
        }

        return $this->default->accepts($firstFactor, $factor);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  ...$proofs
     * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
     */
    #[\Override]
    public function evaluate(Requirement $requirement, Proof ...$proofs): Evaluation
    {
        $firstFactors = array_filter($proofs, static fn (Proof $proof): bool => $proof->kind === ProofKind::FIRST_FACTOR);
        $firstFactor  = count($firstFactors) === 1 ? reset($firstFactors) : null;

        $counted = array_filter($proofs, fn (Proof $proof): bool => $firstFactor === null
            || $proof->kind !== ProofKind::ADDITIONAL_FACTOR
            || $proof->channel === null
            || $this->accepts($firstFactor, $proof->channel));

        return $this->default->evaluate($requirement, ...$counted);
    }
}
