<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Lifecycle;

use Carbon\Exceptions\InvalidFormatException;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Context\ClientContext;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Enrollment\PendingEnrollments;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Events\EnrollmentAbandoned;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Events\FactorRemoved;
use SineMacula\Laravel\Mfa\Events\FactorsReset;
use SineMacula\Laravel\Mfa\Exceptions\InvalidModelException;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Requirements\ReenrollmentObligation;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;

/**
 * Resets an identity that has lost its factors, for someone else acting with a
 * reason. Bypasses the last factor policy and needs no session.
 *
 * The verification generation advances whatever the bound `SessionRevoker`
 * does, so every earlier proof stops counting. Delivered code rows stay for the
 * send caps. A factor whose stored state cannot be read is still removed, with
 * no event of its own; `FactorsReset` counts it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IdentityReset
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptService  $attempts
     * @param  \SineMacula\Laravel\Mfa\Lifecycle\FactorRemoval  $removal
     * @param  \SineMacula\Laravel\Mfa\Enrollment\PendingEnrollments  $enrollments
     * @param  \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService  $recoveryCodes
     * @param  \SineMacula\Laravel\Mfa\Events\EventDispatcher  $events
     */
    public function __construct(

        /** Seams are resolved on every call. */
        private Container $container,

        /** Names the configured factor model. */
        private Repository $config,

        /** Lockouts and failure counts. */
        private AttemptService $attempts,

        /** Erases each factor's own records. */
        private FactorRemoval $removal,

        /** Enrolments in progress. */
        private PendingEnrollments $enrollments,

        /** The recovery code set. */
        private RecoveryCodeService $recoveryCodes,

        /** Dispatches the reset's events. */
        private EventDispatcher $events,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Events\Actor  $actor
     * @param  string  $reason
     * @param  bool  $requireReenrollment
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function reset(MultiFactorAuthenticatable $identity, Actor $actor, string $reason, bool $requireReenrollment, ?ClientContext $client = null): void
    {
        if (trim($reason) === '') {
            throw new \InvalidArgumentException('A reset needs a reason.');
        }

        OperationRefusedException::unless(
            $this->container->make(SubjectTypeResolver::class)->isPerson($identity),
            FailureReason::MACHINE_IDENTITY,
            'The identity is not a person, so it holds no factors to reset.',
        );

        $model = ConfiguredModels::factor($this->config);

        FactorStateTransaction::forIdentity($identity, new $model, function (Collection $stored) use ($identity, $actor, $reason, $requireReenrollment, $client): void {

            $factors    = $stored->sortBy(static fn (EloquentFactor&Model $factor): ?string => LockedFactors::idOf($factor))->values();
            $readable   = $factors->filter(static fn (EloquentFactor&Model $factor): bool => self::isReadable($factor))->values();
            $unreadable = $factors->count() - $readable->count();
            $context    = $this->events->context($identity, null, $client);

            $this->liftLockouts($identity, $readable, $actor, $client);
            $this->removeFactors($identity, $factors, $readable, $actor, $context);

            $this->recoveryCodes->removeSet($identity, $actor, $client);

            ReenrollmentObligation::record($identity, $requireReenrollment);
            VerificationGeneration::advance($identity);

            $this->container->make(SessionRevoker::class)->revokeAll($identity);

            $this->events->dispatch(new FactorsReset($context, $actor, $reason, $requireReenrollment, $unreadable));
        });
    }

    /**
     * Whether the factor's summary, status and deadline can be read.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return bool
     */
    private static function isReadable(EloquentFactor&Model $factor): bool
    {
        // PHPStan cannot trace these through the model's casts.
        try {
            FactorSummary::fromFactor($factor);
            $factor->getLockedUntil();
            // @phpstan-ignore catch.neverThrown
        } catch (InvalidFormatException|InvalidModelException) {
            return false;
        } catch (\ValueError) { // @phpstan-ignore catch.neverThrown
            return false;
        }

        return true;
    }

    /**
     * Only readable factors are lifted; an unreadable one's deadline goes with
     * its row.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @param  \SineMacula\Laravel\Mfa\Events\Actor  $actor
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return void
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private function liftLockouts(MultiFactorAuthenticatable $identity, Collection $factors, Actor $actor, ?ClientContext $client): void
    {
        foreach ($factors as $factor) {
            $this->attempts->liftLockout($identity, $factor, $actor, null, $client);
        }

        $this->attempts->liftLockout($identity, null, $actor, null, $client);
        $this->attempts->resetIdentityFailures($identity);
    }

    /**
     * Only readable factors are reported.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $readable
     * @param  \SineMacula\Laravel\Mfa\Events\Actor  $actor
     * @param  array<string, int|string|null>  $context
     * @return void
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     */
    private function removeFactors(MultiFactorAuthenticatable $identity, Collection $factors, Collection $readable, Actor $actor, array $context): void
    {
        foreach ($this->enrollments->ofOwner(ProofOwner::of($identity)) as $enrollment) {
            $this->enrollments->forget($enrollment);
        }

        foreach ($factors as $factor) {

            if (!$readable->contains($factor)) {

                $this->removal->erase($identity, $factor);

                continue;
            }

            $summary   = FactorSummary::fromFactor($factor);
            $confirmed = $factor->isConfirmed();

            $this->removal->erase($identity, $factor);

            $this->events->dispatch($confirmed ? new FactorRemoved($context, $summary, $actor) : new EnrollmentAbandoned($context, $summary));
        }
    }
}
