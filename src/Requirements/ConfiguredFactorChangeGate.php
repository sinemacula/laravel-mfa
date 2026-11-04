<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Enums\FactorChange;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;

/**
 * The package's own judgement of a factor change, on the session's recorded
 * proofs, through the bound `FreshnessGate` and `Reauthenticator`:
 *
 * - a first additional factor needs the first factor proved again through the
 *   bound `Reauthenticator`, which the default refuses: a first factor
 *   reauthentication of the identity on the application, bound to the sign-in
 *   the change is made from, under its current verification generation, made
 *   within the last five minutes, which the grant lasts until the end of;
 * - a further factor needs the session fresh for `mfa.add_factor`, which the
 *   grant lasts as long as;
 * - removing a factor needs the session fresh for `mfa.remove_factor`, and,
 *   while the identity has another confirmed factor, whatever the freshness
 *   gate holds the session to met by proofs made without this one, so a
 *   step-up with the factor never authorises its own removal;
 * - generating recovery codes needs the session fresh for
 *   `mfa.generate_recovery_codes`.
 *
 * Each step-up is judged with the requirement the application configures for
 * the change's operation. A refusal is the package's own
 * `OperationRefusedException` carrying `not_fresh`; one a seam it asks throws
 * propagates as that seam's.
 *
 * Stateless: the seams are resolved on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConfiguredFactorChangeGate implements FactorChangeGate
{
    /** @var int How old, in seconds, a reauthentication may be and still authorise a first additional factor. */
    public const int REAUTHENTICATION_MAX_AGE = 300;

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
     * Authorise the change on the session's proofs, and say until when.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $request
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function authorize(FactorChangeRequest $request): ?CarbonImmutable
    {
        return match ($request->change) {
            FactorChange::ADD_FIRST_ADDITIONAL_FACTOR => $this->reauthenticated($request),
            FactorChange::ADD_FACTOR                  => $this->freshUntil($request, 'Adding a factor needs a fresh step-up.'),
            FactorChange::REMOVE_FACTOR               => $this->freshForRemoval($request),
            FactorChange::GENERATE_RECOVERY_CODES     => $this->fresh($request, 'The session is not fresh enough to issue recovery codes.'),
        };
    }

    /**
     * Refuse unless the bound reauthenticator proves the first factor again,
     * now, on the sign-in the change is made from; the grant lasts until that
     * proof is too old to authorise one.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $request
     * @return \Carbon\CarbonImmutable
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function reauthenticated(FactorChangeRequest $request): CarbonImmutable
    {
        $proof = $this->container->make(Reauthenticator::class)->reauthenticate($request->identity, $request->application);

        OperationRefusedException::byPackageUnless(
            $proof !== null && self::isFreshReauthentication($proof, $request->identity, $request->application, $request->session),
            FailureReason::NOT_FRESH,
            'Adding a first additional factor needs the first factor proved again.',
        );

        return $proof->provedAt->addSeconds(self::REAUTHENTICATION_MAX_AGE);
    }

    /**
     * Refuse unless the session is fresh for the change's operation, and say
     * until when it is.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $request
     * @param  string  $detail
     * @return \Carbon\CarbonImmutable
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function freshUntil(FactorChangeRequest $request, string $detail): CarbonImmutable
    {
        $until = $this->requirements()->freshUntil($request->change->value, $request->requirement);

        OperationRefusedException::byPackageUnless($until !== null, FailureReason::NOT_FRESH, $detail);

        return $until;
    }

    /**
     * Refuse unless the session is fresh for the change's operation.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $request
     * @param  string  $detail
     * @return null
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function fresh(FactorChangeRequest $request, string $detail): null
    {
        OperationRefusedException::byPackageUnless($this->requirements()->isFresh($request->change->value, $request->requirement), FailureReason::NOT_FRESH, $detail);

        return null;
    }

    /**
     * Refuse removing the factor unless the session is fresh for it, and, while
     * the identity has another confirmed factor, fresh on proofs made without
     * this one.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $request
     * @return null
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function freshForRemoval(FactorChangeRequest $request): null
    {
        $this->fresh($request, 'Removing a factor needs a fresh step-up.');

        $id = $request->factorId;

        if (!$request->factors->contains(static fn (EloquentFactor&Model $other): bool => LockedFactors::idOf($other) !== $id && $other->isConfirmed())) {
            return null;
        }

        $requirement = $this->requirements()->freshnessRequirement($request->change->value, $request->requirement);

        OperationRefusedException::byPackageUnless($requirement !== null, FailureReason::NOT_FRESH, 'Removing a factor has no freshness to judge it by.');

        $proofs = array_filter(
            $this->container->make(SessionFirstFactor::class)->proofs($request->identity, $request->application),
            static fn (Proof $proof): bool => $proof->reference !== $id,
        );

        OperationRefusedException::byPackageUnless(
            $this->container->make(RequirementCheck::class)->check($requirement, ...$proofs)->meetsRequirement(),
            FailureReason::NOT_FRESH,
            'Removing a factor needs a fresh step-up made with another factor.',
        );

        return null;
    }

    /**
     * The requirement service the freshness gate is asked through.
     *
     * @return \SineMacula\Laravel\Mfa\Requirements\RequirementService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function requirements(): RequirementService
    {
        return $this->container->make(RequirementService::class);
    }

    /**
     * Whether the proof is a reauthentication with the identity's first factor
     * on the sign-in, under its current verification generation, made within
     * the last five minutes and not after now.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @return bool
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private static function isFreshReauthentication(Proof $proof, MultiFactorAuthenticatable $identity, string $application, string $session): bool
    {
        if ($proof->kind !== ProofKind::FIRST_FACTOR_REAUTHENTICATION || !ProofOwner::of($identity)->ownsSignIn($proof->binding, $application, $session)) {
            return false;
        }

        if ($proof->generation !== VerificationGeneration::current($identity)) {
            return false;
        }

        $now = CarbonImmutable::now();

        return $proof->provedAt->lessThanOrEqualTo($now)
            && $proof->provedAt->greaterThanOrEqualTo($now->subSeconds(self::REAUTHENTICATION_MAX_AGE));
    }
}
