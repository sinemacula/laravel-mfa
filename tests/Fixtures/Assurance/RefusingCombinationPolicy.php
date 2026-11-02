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
 * A combination policy that answers as the policy it wraps, until the call
 * named, which it refuses with its own exception, as a policy of an
 * application's may. Call `0` refuses none, and counts them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RefusingCombinationPolicy implements CombinationPolicy
{
    /** @var int How many times the policy was asked. */
    public int $calls = 0;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\CombinationPolicy  $policy
     * @param  int  $refuseOnCall
     */
    public function __construct(

        /** The policy answered as. */
        private readonly CombinationPolicy $policy,

        /** The call refused, `0` for none. */
        private readonly int $refuseOnCall,
    ) {}

    /**
     * As the wrapped policy, unless this call is refused.
     *
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
     * As the wrapped policy, unless this call is refused.
     *
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
     * Count the call, and refuse it when it is the one named.
     *
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
