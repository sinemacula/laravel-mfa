<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Enums\FactorChangeMade;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;

/**
 * Evaluates an active session's requirement again on the proofs it holds after
 * a change to the identity's factors, and hands the change, with any shortfall,
 * to the bound `SessionTransition`, as part of that change.
 *
 * Stateless: the seams are resolved on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SessionReevaluation
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the seams are resolved from on every call. */
        private Container $container,
    ) {}

    /**
     * After the change to the factor, evaluate the session's requirement again
     * on the proofs given and hand the change, with the requirement it does not
     * meet or `null`, to the bound session transition, whether the session
     * meets it or not.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChangeMade  $change
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return \SineMacula\Laravel\Mfa\Requirements\SessionJudgement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function judge(
        MultiFactorAuthenticatable $identity,
        string $application,
        string $session,
        FactorChangeMade $change,
        FactorSummary $factor,
        array $proofs,
    ): SessionJudgement {
        $outstanding = $this->outstanding($identity, $application, $proofs);
        $completion  = $this->container->make(SessionTransition::class)->factorChanged(new SessionChange($identity, $application, $session, $change, $factor, $outstanding));

        return new SessionJudgement($outstanding, $completion);
    }

    /**
     * The requirement the session does not meet on the proofs given, whole and
     * not what is left of it, or `null` when it meets it, changing nothing.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function outstanding(MultiFactorAuthenticatable $identity, string $application, array $proofs): ?Requirement
    {
        $requirement = $this->container->make(RequirementService::class)->requirementFor($identity, $application);

        return $this->container->make(RequirementCheck::class)->check($requirement, ...$proofs)->meetsRequirement() ? null : $requirement;
    }
}
