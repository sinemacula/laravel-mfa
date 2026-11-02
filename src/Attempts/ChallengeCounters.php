<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Database\OpenTransaction;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Factors\FactorChannel;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;

/**
 * The calls a challenge owner makes into this package's counts: whoever sends
 * and consumes a delivered factor's challenges (the authentication layer, or
 * the package's own `ChallengeGateway`) asks whether the factor may be
 * challenged before it sends or checks a code, and reports every outcome. The
 * per-challenge attempt and delivery counts are the owner's; the per-factor and
 * per-identity counts and lockouts are this package's.
 *
 * Both calls run inside the owner's own transaction on the storage connection,
 * and refuse with a `LogicException` without one: the identity's factor state
 * lock they take (see `Support\FactorStateTransaction`) is then held until the
 * owner commits, so parallel guesses for one identity are counted one after the
 * other and cannot overrun a cap, and an owner that rolls back counts nothing.
 * The lock order is the identity's state, then its factors, then the owner's
 * challenge: the owner opens its transaction, asks `isUsable()`, then locks and
 * consumes its challenge, then calls `report()`.
 *
 * `isUsable()` answers under the lock: the binding must name the identity,
 * which must be an active person, and the factor must be one of its stored
 * factors, confirmed, of a type the binding's application enables, accepted by
 * the combination policy after the session's first factor, and neither locked
 * nor disabled. A delivery is asked about but never reported, so sending a code
 * never resets or adds to a failure count. `report()` counts the outcome as a
 * verification of the package's own would, without an IP address (an owner's
 * per-address limits are its own), and dispatches the lockout and failure
 * ceiling events once the owner's transaction commits.
 *
 * Stateless: the configuration and the seams are read on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class ChallengeCounters
{
    /** @var string Why a call made outside a transaction is refused. */
    private const string NO_TRANSACTION = 'A challenge is admitted and its outcome reported only inside the caller\'s transaction on the storage connection.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptService  $attempts
     * @param  \SineMacula\Laravel\Mfa\Context\SessionFirstFactor  $firstFactors
     */
    public function __construct(

        /** The container the seams and the drivers are resolved from. */
        private Container $container,

        /** The configuration the factor model and settings are read from. */
        private Repository $config,

        /** The counts and lockouts the outcome is recorded in. */
        private AttemptService $attempts,

        /** The reader of the session's first factor. */
        private SessionFirstFactor $firstFactors,
    ) {}

    /**
     * Whether the factor may be challenged now under the binding, read under
     * the identity's factor state lock, which is held until the caller's
     * transaction ends.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission
     *
     * @throws \LogicException
     * @throws \Throwable
     */
    public function isUsable(MultiFactorAuthenticatable $identity, Factor $factor, ProofBinding $binding): ChallengeAdmission
    {
        OpenTransaction::assertOpen(self::NO_TRANSACTION);

        $refusal = $this->identityRefusal($identity, $binding);

        if ($refusal !== null) {
            return $refusal;
        }

        return FactorStateTransaction::forIdentity($identity, $this->factorModel($factor), function (Collection $factors) use ($identity, $factor, $binding): ChallengeAdmission {

            $stored = LockedFactors::find($factor, $factors);

            if ($stored === null) {
                return ChallengeAdmission::refuse(FailureReason::NOT_FOUND, 'The factor is not among the identity\'s factors.');
            }

            $refusal = $this->factorRefusal($identity, $stored, $binding);

            if ($refusal !== null) {
                return $refusal;
            }

            $lockout = $this->attempts->lockedOut($identity, $stored);

            return $lockout === null ? ChallengeAdmission::admit() : ChallengeAdmission::locked($lockout);
        });
    }

    /**
     * Count the outcome of a challenge the caller has just checked and
     * consumed, inside the same transaction: a success resets the factor's and
     * the identity's failures in a row, a failure counts against both and may
     * lock or disable. An outcome is refused, and counted nowhere, while a
     * lockout applies, and answered as not found for a factor no longer among
     * the identity's.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  bool  $passed
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptOutcome
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    public function report(MultiFactorAuthenticatable $identity, Factor $factor, ProofBinding $binding, bool $passed): AttemptOutcome
    {
        OpenTransaction::assertOpen(self::NO_TRANSACTION);

        OperationRefusedException::unless(ProofOwner::of($identity)->owns($binding), FailureReason::NOT_FOUND, 'The challenge\'s binding names another identity.');

        return $this->attempts->attempt(
            new Attempt($identity, $factor, $binding->purpose, null, $binding->application),
            static fn (): bool => $passed,
        );
    }

    /**
     * Refuse a binding that names another identity, a machine and an inactive
     * identity, before any lock is taken.
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

        return match (true) {
            !ProofOwner::of($identity)->owns($binding) => ChallengeAdmission::refuse(FailureReason::NOT_FOUND, 'The challenge\'s binding names another identity.'),
            !$people->isPerson($identity)              => ChallengeAdmission::refuse(FailureReason::MACHINE_IDENTITY, 'The identity is not a person.'),
            !$identity->isMfaActive()                  => ChallengeAdmission::refuse(FailureReason::IDENTITY_INACTIVE, 'The identity is inactive.'),
            default                                    => null,
        };
    }

    /**
     * Refuse a stored factor that is pending, of a type the binding's
     * application does not enable, or not accepted after the session's first
     * factor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return ?\SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function factorRefusal(MultiFactorAuthenticatable $identity, EloquentFactor&Model $factor, ProofBinding $binding): ?ChallengeAdmission
    {
        if (!$factor->isConfirmed()) {
            return ChallengeAdmission::refuse(FailureReason::NOT_CONFIRMED, 'The factor is pending.');
        }

        if (!(new ApplicationSettings($this->config, $binding->application))->enables($factor->getType())) {
            return ChallengeAdmission::refuse(FailureReason::TYPE_NOT_ENABLED, sprintf('The application does not enable the factor\'s type [%s].', $factor->getType()));
        }

        return $this->isAccepted($identity, $factor, $binding)
            ? null
            : ChallengeAdmission::refuse(FailureReason::NOT_ACCEPTED, 'The combination policy does not accept the factor after the session\'s first factor.');
    }

    /**
     * Whether the combination policy accepts the factor's channel after the
     * first factor of the session the binding names; never when that first
     * factor is not known.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function isAccepted(MultiFactorAuthenticatable $identity, EloquentFactor&Model $factor, ProofBinding $binding): bool
    {
        $firstFactor = $this->firstFactors->forBinding($identity, $binding);
        $driver      = $this->container->make(DriverResolver::class)->fromContainer($this->container, $factor->getType());
        $channel     = FactorChannel::of($factor, $driver->channelKind());

        return $firstFactor !== null && $channel !== null && $this->container->make(CombinationPolicy::class)->accepts($firstFactor, $channel);
    }

    /**
     * The factor model the identity's factors are locked through: the factor's
     * own when it keeps state, otherwise the configured one.
     *
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
}
