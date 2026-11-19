<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\RequirementPolicy;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Testing\Seams\RequirementSeamContract;

/**
 * The `RequirementPolicy` contract kit; each check delegates to
 * `RequirementSeamContract`.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait RequirementPolicyTests
{
    /**
     * Another identity is asked in between, and is not answered as the first.
     *
     * @return void
     */
    public function testRequirementPolicyKeepsNoStateBetweenCalls(): void
    {
        $policy      = $this->requirementPolicy();
        $identity    = $this->policyIdentity();
        $other       = $this->otherPolicyIdentity();
        $application = $this->policyApplication();
        $first       = $this->policyFirstFactor($identity);
        $otherFirst  = $this->policyFirstFactor($other);
        $ask         = static fn () => $policy->requirementFor($identity, $application, $first);
        $askAnother  = static fn () => $policy->requirementFor($other, $application, $otherFirst);

        RequirementSeamContract::assertAnswersAnotherQuestionItsOwnWay($ask, $askAnother);
        RequirementSeamContract::assertKeepsNoStateBetweenCalls($ask, $askAnother);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\RequirementPolicy
     */
    abstract protected function requirementPolicy(): RequirementPolicy;

    /**
     * An identity the policy asks something of.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function policyIdentity(): MultiFactorAuthenticatable;

    /**
     * An identity the policy asks something else of.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function otherPolicyIdentity(): MultiFactorAuthenticatable;

    /**
     * @return string
     */
    abstract protected function policyApplication(): string;

    /**
     * The first factor the identity signed in to `policyApplication()` with.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    abstract protected function policyFirstFactor(MultiFactorAuthenticatable $identity): Proof;
}
