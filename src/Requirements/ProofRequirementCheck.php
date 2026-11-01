<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * The default `RequirementCheck`: the session's proofs judged by the bound
 * `CombinationPolicy`, so the answer is the same at sign-in, in a tenant's
 * policy and on step-up.
 *
 * Only the proofs of one sign-in count: those bound to the same session as the
 * session's one first factor. With no first factor, or more than one, none
 * counts, so nothing but an empty requirement is met. The combination policy
 * judges each part on a combination that provides it on evidence within the
 * part's maximum age, which for a boolean answer is the newest proof meeting
 * the part: a fresh weaker proof never refreshes an old stronger one, and a
 * fresh first factor, or a reauthentication with it, never stands in for an
 * additional factor unless it is a multi-factor authenticator itself.
 *
 * The policy is resolved on every call, so one bound after this check was
 * resolved is the one used.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ProofRequirementCheck implements RequirementCheck
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the combination policy is resolved from. */
        private Container $container,
    ) {}

    /**
     * Evaluate the session's proofs against the requirement.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  ...$proofs
     * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    public function check(Requirement $requirement, Proof ...$proofs): Evaluation
    {
        return $this->container->make(CombinationPolicy::class)->evaluate($requirement, ...self::ofOneSignIn($proofs));
    }

    /**
     * The proofs of the sign-in the session's one first factor began: those
     * bound to the same session as it, none when there is no first factor or
     * more than one.
     *
     * @param  array<array-key, \SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    private static function ofOneSignIn(array $proofs): array
    {
        $firstFactors = array_values(array_filter($proofs, static fn (Proof $proof): bool => $proof->kind === ProofKind::FIRST_FACTOR));

        if (count($firstFactors) !== 1) {
            return [];
        }

        $sessionId = $firstFactors[0]->binding->sessionId;

        return array_values(array_filter($proofs, static fn (Proof $proof): bool => $proof->binding->sessionId === $sessionId));
    }
}
