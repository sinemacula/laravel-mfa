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
 * The default `RequirementCheck`, judged by the bound `CombinationPolicy` on
 * the proofs of one sign-in only.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ProofRequirementCheck implements RequirementCheck
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Resolves the policy on every call, so a later binding applies. */
        private Container $container,
    ) {}

    /**
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
     * Proofs bound to the session of the one first factor, or none when there
     * is not exactly one.
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
