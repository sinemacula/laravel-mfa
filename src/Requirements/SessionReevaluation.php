<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;

/**
 * Evaluates an active session's requirement again on the proofs it holds after
 * a change to the identity's factors, and hands a shortfall to the bound
 * `SessionTransition`, as part of that change.
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
     * Evaluate the session's requirement again on the proofs given, and hand a
     * shortfall to the bound session transition. Returns the requirement the
     * session does not meet, whole and not what is left of it, or `null` when
     * it meets it.
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
    public function reevaluate(MultiFactorAuthenticatable $identity, string $application, array $proofs): ?Requirement
    {
        $requirement = $this->outstanding($identity, $application, $proofs);

        if ($requirement !== null) {
            $this->container->make(SessionTransition::class)->returnToPending($identity, $application, $requirement);
        }

        return $requirement;
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
