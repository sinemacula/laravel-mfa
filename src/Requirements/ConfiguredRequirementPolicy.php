<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Contracts\RequirementPolicy;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * The default `RequirementPolicy`: the sign-in requirement composed from the
 * application's configured mode, the identity's own requirement and its
 * re-enrolment obligation (see `RequirementService::requirementFor()`), or none
 * when the first factor meets all of it on its own, as a passkey whose
 * assertion observed user verification meets an additional verification.
 *
 * The first factor is judged by the bound `RequirementCheck`, like any proof,
 * so an old one or one below a minimum level leaves the whole requirement
 * standing. A proof that is not a first factor of the identity on the
 * application suppresses nothing. The collaborators are resolved on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConfiguredRequirementPolicy implements RequirementPolicy
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the requirement service and the check are resolved from. */
        private Container $container,
    ) {}

    /**
     * The requirement the sign-in must meet after its first factor: none when
     * the first factor meets the whole composed requirement, the whole of it
     * otherwise.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function requirementFor(MultiFactorAuthenticatable $identity, string $application, Proof $firstFactor): Requirement
    {
        $requirement = $this->container->make(RequirementService::class)->requirementFor($identity, $application);

        if (!self::isFirstFactorOf($firstFactor, $identity, $application)) {
            return $requirement;
        }

        $evaluation = $this->container->make(RequirementCheck::class)->check($requirement, $firstFactor);

        return $evaluation->meetsRequirement() ? Requirement::none() : $requirement;
    }

    /**
     * Whether the proof is a first factor at sign-in, of the identity, on the
     * application.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return bool
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private static function isFirstFactorOf(Proof $proof, MultiFactorAuthenticatable $identity, string $application): bool
    {
        return $proof->kind                 === ProofKind::FIRST_FACTOR
            && $proof->binding->application === $application
            && ProofOwner::of($identity)->owns($proof->binding);
    }
}
