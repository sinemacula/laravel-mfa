<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Context\CallerContext;
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
 * The package's own judgement of a factor change on the session's recorded
 * proofs; a seam's refusal propagates as that seam's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConfiguredFactorChangeGate implements FactorChangeGate
{
    /** @var int Oldest reauthentication that authorises a first additional factor, in seconds. */
    public const int REAUTHENTICATION_MAX_AGE = 300;

    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Seams are resolved on every call. */
        private Container $container,
    ) {}

    /**
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
     * Require the first factor proved again on this sign-in; the grant lasts
     * until that proof is too old.
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
     * Require the session fresh for the operation; the grant lasts as long as
     * it stays fresh.
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
        $until = $this->requirements()->freshUntil(self::caller($request), $request->change->value, $request->requirement);

        OperationRefusedException::byPackageUnless($until !== null, FailureReason::NOT_FRESH, $detail);

        return $until;
    }

    /**
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
        $fresh = $this->requirements()->isFresh(self::caller($request), $request->change->value, $request->requirement);

        OperationRefusedException::byPackageUnless($fresh, FailureReason::NOT_FRESH, $detail);

        return null;
    }

    /**
     * While another factor is confirmed, the freshness requirement must also be
     * met without this factor's proofs, so it never authorises its own removal.
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

        $requirement = $this->requirements()->freshnessRequirement(self::caller($request), $request->change->value, $request->requirement);

        OperationRefusedException::byPackageUnless($requirement !== null, FailureReason::NOT_FRESH, 'Removing a factor has no freshness to judge it by.');

        $proofs = array_filter(
            $this->container->make(SessionFirstFactor::class)->proofsOf($request->identity, $request->application, $request->session),
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
     * @return \SineMacula\Laravel\Mfa\Requirements\RequirementService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function requirements(): RequirementService
    {
        return $this->container->make(RequirementService::class);
    }

    /**
     * A first-factor reauthentication of this sign-in and generation, made
     * within the last five minutes and not after now.
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

    /**
     * The gate is asked only for an active session of the request's identity.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $request
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     *
     * @throws \InvalidArgumentException
     */
    private static function caller(FactorChangeRequest $request): CallerContext
    {
        return CallerContext::forIdentity($request->identity, $request->application);
    }
}
