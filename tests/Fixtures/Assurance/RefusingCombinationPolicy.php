<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Assurance;

use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Answers as the policy it wraps until the numbered call, which it refuses with
 * its own exception. Call `0` refuses none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RefusingCombinationPolicy implements CombinationPolicy
{
    /** @var int */
    public int $calls = 0;

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\CombinationPolicy  $policy
     * @param  int  $refuseOnCall
     */
    public function __construct(

        /** Answers every call not refused. */
        private readonly CombinationPolicy $policy,

        /** The call refused, `0` for none. */
        private readonly int $refuseOnCall,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $factor
     * @return bool
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    #[\Override]
    public function accepts(Proof $firstFactor, Channel $factor): bool
    {
        $this->count();

        return $this->policy->accepts($firstFactor, $factor);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  ...$proofs
     * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    #[\Override]
    public function evaluate(Requirement $requirement, Proof ...$proofs): Evaluation
    {
        $this->count();

        return $this->policy->evaluate($requirement, ...$proofs);
    }

    /**
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function count(): void
    {
        if (++$this->calls === $this->refuseOnCall) {
            throw new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'The combination policy refused.');
        }
    }
}
