<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Database\OpenTransaction;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Enrollment\PendingEnrollments;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Factors\FactorChannel;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;

/**
 * Factor and identity counters for a challenge owner. Call both methods inside
 * the owner's storage transaction so the factor lock is held until it commits;
 * lock order is identity state, factors, then the owner's challenge. An
 * `enrollment` binding admits only a pending factor and counts nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class ChallengeCounters
{
    /** @var string */
    private const string NO_TRANSACTION = 'A challenge is admitted and its outcome reported only inside the caller\'s transaction on the storage connection.';

    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptService  $attempts
     * @param  \SineMacula\Laravel\Mfa\Context\SessionFirstFactor  $firstFactors
     */
    public function __construct(

        /** Resolves seams and drivers. */
        private Container $container,

        /** Configuration. */
        private Repository $config,

        /** Records outcomes. */
        private AttemptService $attempts,

        /** First factor reader. */
        private SessionFirstFactor $firstFactors,
    ) {}

    /**
     * Ask before sending or checking a code; deliveries are never reported.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission
     *
     * @throws \LogicException
     * @throws \Throwable
     */
    public function isUsable(CallerContext $caller, Factor $factor, ProofBinding $binding): ChallengeAdmission
    {
        OpenTransaction::assertOpen(self::NO_TRANSACTION);

        $identity = self::identityOf($caller);
        $pending  = $caller->pending;

        $refusal = $this->identityRefusal($identity, $binding);

        if ($refusal !== null) {
            return $refusal;
        }

        $model = $this->factorModel($factor);

        return FactorStateTransaction::forIdentity($identity, $model, function (Collection $factors) use ($identity, $pending, $factor, $binding): ChallengeAdmission {

            $stored = LockedFactors::find($factor, $factors);

            return $stored === null
                ? ChallengeAdmission::refuse(FailureReason::NOT_FOUND, 'The factor is not among the identity\'s factors.')
                : $this->factorAdmission($identity, $pending, $stored, $binding);
        });
    }

    /**
     * For a caller already holding the identity's factor state lock.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     *
     * @internal
     */
    public function underLock(CallerContext $caller, EloquentFactor&Model $factor, ProofBinding $binding): ChallengeAdmission
    {
        $identity = self::identityOf($caller);

        return $this->identityRefusal($identity, $binding) ?? $this->factorAdmission($identity, $caller->pending, $factor, $binding);
    }

    /**
     * Count a checked challenge's outcome, without an IP address; events fire
     * once the owner's transaction commits.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  bool  $passed
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptOutcome
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    public function report(CallerContext $caller, Factor $factor, ProofBinding $binding, bool $passed): AttemptOutcome
    {
        OpenTransaction::assertOpen(self::NO_TRANSACTION);

        $identity = self::identityOf($caller);

        OperationRefusedException::unless(ProofOwner::of($identity)->owns($binding), FailureReason::NOT_FOUND, 'The challenge\'s binding names another identity.');

        if ($binding->purpose === Purpose::ENROLLMENT) {
            return $passed ? AttemptOutcome::pass() : AttemptOutcome::fail();
        }

        return $this->attempts->attempt(
            new Attempt($identity, $factor, $binding->purpose, $binding->application, $caller->client),
            static fn (): bool => $passed,
        );
    }

    /**
     * Checked before any lock is taken.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return ?\SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function identityRefusal(MultiFactorAuthenticatable $identity, ProofBinding $binding): ?ChallengeAdmission
    {
        $people = $this->container->make(SubjectTypeResolver::class);
        $active = $this->container->make(ActiveStateResolver::class);

        return match (true) {
            !ProofOwner::of($identity)->owns($binding) => ChallengeAdmission::refuse(FailureReason::NOT_FOUND, 'The challenge\'s binding names another identity.'),
            !$people->isPerson($identity)              => ChallengeAdmission::refuse(FailureReason::MACHINE_IDENTITY, 'The identity is not a person.'),
            !$active->isActive($identity)              => ChallengeAdmission::refuse(FailureReason::IDENTITY_INACTIVE, 'The identity is inactive.'),
            default                                    => null,
        };
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function factorAdmission(MultiFactorAuthenticatable $identity, ?PendingContext $pending, EloquentFactor&Model $factor, ProofBinding $binding): ChallengeAdmission
    {
        $enrolling = $binding->purpose === Purpose::ENROLLMENT;
        $refusal   = $enrolling ? $this->enrollingRefusal($identity, $pending, $factor, $binding) : $this->factorRefusal($identity, $pending, $factor, $binding);

        if ($refusal !== null) {
            return $refusal;
        }

        $lockout = $this->attempts->lockedOut($identity, $enrolling ? null : $factor);

        return $lockout === null ? ChallengeAdmission::admit() : ChallengeAdmission::locked($lockout);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return ?\SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function enrollingRefusal(MultiFactorAuthenticatable $identity, ?PendingContext $pending, EloquentFactor&Model $factor, ProofBinding $binding): ?ChallengeAdmission
    {
        if (!(new ApplicationSettings($this->config, $binding->application))->enables($factor->getType())) {
            return ChallengeAdmission::refuse(FailureReason::TYPE_NOT_ENABLED, sprintf('The application does not enable the factor\'s type [%s].', $factor->getType()));
        }

        $enrollments = $this->container->make(PendingEnrollments::class);
        $enrollment  = $factor->isConfirmed() ? null : $enrollments->forFactor((string) LockedFactors::idOf($factor));

        if ($enrollment === null || !$enrollments->isBound($enrollment, $binding, $pending !== null)) {
            return ChallengeAdmission::refuse(FailureReason::NOT_FOUND, 'The factor holds no enrolment bound to the challenge.');
        }

        return $enrollments->isLive($enrollment, $identity) ? null : ChallengeAdmission::refuse(FailureReason::EXPIRED, 'The factor\'s enrolment has expired.');
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return ?\SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function factorRefusal(MultiFactorAuthenticatable $identity, ?PendingContext $pending, EloquentFactor&Model $factor, ProofBinding $binding): ?ChallengeAdmission
    {
        if (!$factor->isConfirmed()) {
            return ChallengeAdmission::refuse(FailureReason::NOT_CONFIRMED, 'The factor is pending.');
        }

        if (!(new ApplicationSettings($this->config, $binding->application))->enables($factor->getType())) {
            return ChallengeAdmission::refuse(FailureReason::TYPE_NOT_ENABLED, sprintf('The application does not enable the factor\'s type [%s].', $factor->getType()));
        }

        return $this->isAccepted($identity, $pending, $factor, $binding)
            ? null
            : ChallengeAdmission::refuse(FailureReason::NOT_ACCEPTED, 'The combination policy does not accept the factor after the session\'s first factor.');
    }

    /**
     * Never accepted when the session's first factor is unknown.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function isAccepted(MultiFactorAuthenticatable $identity, ?PendingContext $pending, EloquentFactor&Model $factor, ProofBinding $binding): bool
    {
        $firstFactor = $this->firstFactors->forBinding($identity, $binding, $pending);
        $driver      = $this->container->make(DriverResolver::class)->fromContainer($this->container, $factor->getType());
        $channel     = FactorChannel::of($factor, $driver->channelKind());

        return $firstFactor !== null && $channel !== null && $this->container->make(CombinationPolicy::class)->accepts($firstFactor, $channel);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    private function factorModel(Factor $factor): EloquentFactor&Model
    {
        if (LockedFactors::keepsState($factor)) {
            return $factor;
        }

        $model = ConfiguredModels::factor($this->config);

        return new $model;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     *
     * @throws \InvalidArgumentException
     */
    private static function identityOf(CallerContext $caller): MultiFactorAuthenticatable
    {
        return $caller->identity ?? throw new \InvalidArgumentException('Challenge counters are kept for an identity, and the caller is nobody.');
    }
}
