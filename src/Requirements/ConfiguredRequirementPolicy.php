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
 * The default `RequirementPolicy`: the composed sign-in requirement, or none
 * when the first factor meets all of it, as a user-verified passkey does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConfiguredRequirementPolicy implements RequirementPolicy
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Collaborators are resolved on every call. */
        private Container $container,
    ) {}

    /**
     * A proof that is not the identity's first factor on the application
     * suppresses nothing.
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
