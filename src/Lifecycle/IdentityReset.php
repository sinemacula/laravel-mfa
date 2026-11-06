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
 * reason, as one change in its factor state transaction: every lockout lifted,
 * every factor, enrolment and recovery code removed, the re-enrolment
 * obligation recorded as stated, every proof invalidated and every session
 * revoked. Who may reset whom is the application's authorisation, and needs no
 * session, so it serves a console command or a queued job as well as a request;
 * an inactive identity can be reset, and a machine, which holds no factors,
 * cannot. It bypasses the last factor policy.
 *
 * The verification generation is advanced whatever the bound `SessionRevoker`
 * does, so every proof of an earlier one stops counting, the caller's own when
 * it resets itself; it only ever goes up, by however many steps. Without an
 * authentication layer the Laravel login itself goes on, and the identity's
 * next protected request finds no proof. Delivered code rows stay, since the
 * send caps read them; with the factor gone they verify nothing.
 *
 * A reset is the remedy for a factor whose stored state cannot be read: a
 * status the package does not know, or a deadline or disabled time that is not
 * a time. Every factor of the identity is removed under the lock, whatever its
 * state. Such a factor is never read for a lift, so its deadline goes with its
 * row, and no status or confirmation is invented for it: it is reported by no
 * event of its own, and `FactorsReset` counts it.
 *
 * A verification holding the lock first commits, and its proof is then
 * invalidated here; one that waits for the lock finds its factor gone. The
 * events come once the change commits: `LockoutLifted` for each live lockout,
 * then, in id order, `FactorRemoved` for a confirmed factor and
 * `EnrollmentAbandoned` for a pending one, `RecoveryCodesRemoved` when there
 * was a set, and `FactorsReset` last, with the count of factors removed whose
 * state could not be read.
 *
 * Stateless: the seams are resolved on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IdentityReset
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptService  $attempts
     * @param  \SineMacula\Laravel\Mfa\Lifecycle\FactorRemoval  $removal
     * @param  \SineMacula\Laravel\Mfa\Enrollment\PendingEnrollments  $enrollments
     * @param  \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService  $recoveryCodes
     * @param  \SineMacula\Laravel\Mfa\Events\EventDispatcher  $events
     */
    public function __construct(

        /** The container the seams are resolved from on every call. */
        private Container $container,

        /** The configuration the factor model is read from. */
        private Repository $config,

        /** The lockouts and failure counts. */
        private AttemptService $attempts,

        /** The removal of each factor's own records. */
        private FactorRemoval $removal,

        /** The enrolments in progress. */
        private PendingEnrollments $enrollments,

        /** The recovery code set. */
        private RecoveryCodeService $recoveryCodes,

        /** The dispatcher of the reset's events. */
        private EventDispatcher $events,
    ) {}

    /**
     * Reset the identity.
     *
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
     * Determine whether the factor's stored state can be read: the summary its
     * events carry, its status and its deadline. A factor that cannot is still
     * removed, but never read again.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return bool
     */
    private static function isReadable(EloquentFactor&Model $factor): bool
    {
        // A value that cannot be read throws the trait's InvalidModelException,
        // a datetime cast's InvalidFormatException or an enum cast's
        // ValueError; static analysis traces neither of the last two through
        // the model, nor the first through the summary, so the catches are
        // marked.
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
     * Lift every lockout of the factors whose state can be read, then the
     * identity's, and clear its run of failures. A factor whose state cannot be
     * read is not read for a lift: its deadline goes with its row.
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
     * Remove every factor and enrolment of the identity's, reporting each
     * factor whose state can be read by how far it got, and nothing for the
     * others.
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
