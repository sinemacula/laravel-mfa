<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enrollment;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Attempts\AttemptOutcome;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Attempts\RequestIp;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\CodeDeliveryDriver;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization;
use SineMacula\Laravel\Mfa\Enums\FactorChangeMade;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\BootstrapEnrollmentCompleted;
use SineMacula\Laravel\Mfa\Events\EnrollmentAbandoned;
use SineMacula\Laravel\Mfa\Events\EnrollmentExpired;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Events\FactorConfirmed;
use SineMacula\Laravel\Mfa\Events\VerificationFailed;
use SineMacula\Laravel\Mfa\Events\VerificationPassed;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\RefusedUnderLockException;
use SineMacula\Laravel\Mfa\Exceptions\SignInChangedException;
use SineMacula\Laravel\Mfa\Factors\FactorChannel;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Factors\OperationGuard;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeIssuance;
use SineMacula\Laravel\Mfa\Requirements\ReenrollmentObligation;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\SessionReevaluation;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;
use SineMacula\Laravel\Mfa\Verification\CheckOutcome;
use SineMacula\Laravel\Mfa\Verification\ProofAcceptance;

/**
 * Confirms an enrolment: the first valid code, under a live grant, in the
 * session that started it, makes the pending factor confirmed.
 *
 * The caller and its binding are captured and an IP address slot is taken.
 * Under the identity's factor state lock the caller is resolved again, so a
 * sign-in that changed counts nothing, then the row is read and compared, in
 * this order: the grant is bound to the caller (`not_found` otherwise), it is
 * live (an expired one discards the factor and commits), the identity is active
 * and not locked out, the type is still enabled, and the limits and what
 * authorised the grant still hold (see `EnrollmentAuthority::reconfirm()`).
 * Freshness is not judged again: the grant's stored expiry already ends with
 * the proof that authorised it, and a later proof must not revive it.
 *
 * A wrong or replayed code counts against the enrolment's own cap, which at its
 * limit abandons the pending factor; both commit, as they return. The
 * identity's and the factor's failure counts are never charged. A valid code
 * followed by a refusal throws, so the code's use, the TOTP step, the
 * confirmation, the end of a re-enrolment obligation and the recovery codes all
 * roll back.
 *
 * On a pending session the proof goes through `Verification\ProofAcceptance`,
 * so the whole requirement is evaluated again; the session may stay pending. On
 * an active session no proof is recorded and `StepUp` is not called, since this
 * code was bound to the enrolment: the requirement is evaluated again on the
 * proofs the session holds, and the confirmation goes to `SessionTransition`
 * with any shortfall, whose answer the confirmation returns.
 *
 * Stateless: the seams and the configuration are read on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EnrollmentConfirmer
{
    /** @var list<\SineMacula\Laravel\Mfa\Enums\FailureReason> The failures that count against the enrolment's own cap. */
    private const array COUNTED = [FailureReason::INVALID_CODE, FailureReason::REPLAYED];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContextResolver  $callers
     * @param  \SineMacula\Laravel\Mfa\Factors\OperationGuard  $guard
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptService  $attempts
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentAuthority  $authority
     * @param  \SineMacula\Laravel\Mfa\Enrollment\PendingEnrollments  $enrollments
     * @param  \SineMacula\Laravel\Mfa\Events\EventDispatcher  $events
     */
    public function __construct(

        /** The container the seams are resolved from. */
        private Container $container,

        /** The configuration the applications and models are read from. */
        private Repository $config,

        /** The resolver of who the request serves. */
        private CallerContextResolver $callers,

        /** The guard every operation on a factor starts with. */
        private OperationGuard $guard,

        /** The throttle on the address and the identity's lockout. */
        private AttemptService $attempts,

        /** Whether what authorised the grant still holds. */
        private EnrollmentAuthority $authority,

        /** The enrolments in progress. */
        private PendingEnrollments $enrollments,

        /** The dispatcher of the confirmation's events. */
        private EventDispatcher $events,
    ) {}

    /**
     * Confirm the enrolment the grant holds with the code.
     *
     * @param  \SineMacula\Laravel\Mfa\Secrets\RevealedSecret|string  $grant
     * @param  string  $code
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation
     *
     * @throws \Throwable
     */
    public function confirm(#[\SensitiveParameter] RevealedSecret|string $grant, #[\SensitiveParameter] string $code): EnrollmentConfirmation
    {
        $caller  = $this->callers->resolve(PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT);
        $binding = $caller === null ? null : $this->callers->binding($caller, Purpose::ENROLLMENT);

        if ($caller === null || $binding === null) {
            return EnrollmentConfirmation::failed(FailureReason::NOT_FOUND);
        }

        return $this->attempt($caller, $binding, EnrollmentGrant::hash($grant), $code);
    }

    /**
     * Make the attempt holding a slot of the IP address's window and the
     * identity's lock, and report a refusal made there, which rolled back all
     * it did, or by the address's throttle, which ran nothing.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $grantHash
     * @param  string  $code
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation
     *
     * @throws \Throwable
     */
    private function attempt(Caller $caller, ProofBinding $binding, string $grantHash, #[\SensitiveParameter] string $code): EnrollmentConfirmation
    {
        $settled = EnrollmentConfirmation::failed(FailureReason::NOT_FOUND);
        $summary = null;

        try {
            $outcome = $this->attempts->throttled(
                RequestIp::resolve($this->container),
                function () use ($caller, $binding, $grantHash, $code, &$settled, &$summary): AttemptOutcome {

                    $settled = FactorStateTransaction::forIdentity(
                        $caller->identity,
                        new (ConfiguredModels::factor($this->config)),
                        function (Collection $factors) use ($binding, $grantHash, $code, &$summary): EnrollmentConfirmation {

                            $current = $this->callers->still(PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT, $binding)
                                ?? throw new SignInChangedException('The sign-in changed before the identity\'s lock was held.');

                            return $this->underLock($current, $binding, $grantHash, $code, $factors, $summary);
                        },
                    );

                    return self::attemptOutcome($settled);
                },
            );
        } catch (SignInChangedException) {
            return EnrollmentConfirmation::failed(FailureReason::NOT_FOUND);
        } catch (RefusedUnderLockException $exception) {
            return $this->failed($caller, $binding, $summary, $exception->refusal->reason, $exception->challengeId);
        }

        return $outcome->lockout === null ? $settled : $this->failed($caller, $binding, $summary, FailureReason::LOCKED, null, $outcome->lockout->until);
    }

    /**
     * Under the lock, for the caller as it stands now: find the enrolment the
     * grant holds, answering one not bound to the caller as `not_found`, and
     * settle it, leaving the factor as it was found for what a refusal reports:
     * the instance goes on to change with a confirmation the refusal rolls
     * back.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $grantHash
     * @param  string  $code
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @param  ?\SineMacula\Laravel\Mfa\Factors\FactorSummary  $summary
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private function underLock(
        Caller $caller,
        ProofBinding $binding,
        string $grantHash,
        #[\SensitiveParameter] string $code,
        Collection $factors,
        ?FactorSummary &$summary,
    ): EnrollmentConfirmation {
        return RefusedUnderLockException::carrying(function () use ($caller, $binding, $grantHash, $code, $factors, &$summary): EnrollmentConfirmation {

            $granted = $this->enrollments->granted($grantHash, $binding, $caller, $factors);

            if ($granted === null) {
                return $this->failed($caller, $binding, null, FailureReason::NOT_FOUND);
            }

            [$enrollment, $factor] = $granted;

            $summary = FactorSummary::fromFactor($factor);

            return $this->settle($caller, $binding, $enrollment, $factor, $factors, $code);
        });
    }

    /**
     * Under the lock, with a grant bound to the caller: discard one no longer
     * live, refuse what no longer holds, check the code, and confirm or count.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Mfa\Models\Enrollment  $enrollment
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @param  string  $code
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private function settle(
        Caller $caller,
        ProofBinding $binding,
        Enrollment $enrollment,
        EloquentFactor&Model $factor,
        Collection $factors,
        #[\SensitiveParameter] string $code,
    ): EnrollmentConfirmation {
        $identity = $caller->identity;

        if (!$this->enrollments->isLive($enrollment, $identity)) {
            return $this->expire($caller, $binding, $enrollment, $factor);
        }

        $this->guard->identity($identity);

        $lockout = $this->attempts->lockedOut($identity, null);

        if ($lockout !== null) {
            return $this->failed($caller, $binding, FactorSummary::fromFactor($factor), FailureReason::LOCKED, null, $lockout->until);
        }

        $type = $factor->getType();

        OperationRefusedException::unless(
            (new ApplicationSettings($this->config, $binding->application))->enables($type),
            FailureReason::TYPE_NOT_ENABLED,
            sprintf('The application no longer enables the type [%s].', $type),
        );

        $this->authority->reconfirm($enrollment->authority, $binding->application, $type, $factors);

        $driver = $this->container->make(DriverResolver::class)->fromContainer($this->container, $type);
        $check  = $this->check($driver, $factor, $enrollment, $binding, $code);

        return $check->hasPassed()
            ? RefusedUnderLockException::carrying(
                fn (): EnrollmentConfirmation => $this->complete($caller, $binding, $enrollment, $factor, $factors, $driver, $check),
                $check->challengeId,
            )
            : $this->count($caller, $binding, $enrollment, $factor, $check);
    }

    /**
     * Check the code along the factor's route: a delivered type's through the
     * bound gateway, against the challenge the enrolment recorded, any other's
     * through its driver.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Models\Enrollment  $enrollment
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $code
     * @return \SineMacula\Laravel\Mfa\Verification\CheckOutcome
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function check(FactorDriver $driver, EloquentFactor&Model $factor, Enrollment $enrollment, ProofBinding $binding, #[\SensitiveParameter] string $code): CheckOutcome
    {
        if (!$driver instanceof CodeDeliveryDriver) {
            $check   = $driver->confirm($factor, $code, $binding);
            $failure = $check->failure();

            return $failure === null ? CheckOutcome::passed(ObservedProperties::none()) : CheckOutcome::failed($failure, $check->detail());
        }

        $challengeId = (string) $enrollment->challenge_id;
        $outcome     = $this->container->make(ChallengeGateway::class)->verify($factor, $binding, $challengeId, $code);

        return $outcome->reason === null
            ? CheckOutcome::passed(ObservedProperties::none(), $challengeId)
            : CheckOutcome::refused($outcome->reason, $outcome->detail, $outcome->lockedUntil);
    }

    /**
     * Under the lock, with a valid code: confirm the factor, end any
     * re-enrolment obligation, issue recovery codes with the identity's first
     * factor, and settle the session. A refusal throws, so all of it rolls
     * back.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Mfa\Models\Enrollment  $enrollment
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @param  \SineMacula\Laravel\Mfa\Verification\CheckOutcome  $check
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private function complete(
        Caller $caller,
        ProofBinding $binding,
        Enrollment $enrollment,
        EloquentFactor&Model $factor,
        Collection $factors,
        FactorDriver $driver,
        CheckOutcome $check,
    ): EnrollmentConfirmation {
        $identity    = $caller->identity;
        $application = $binding->application;
        $type        = $factor->getType();
        $first       = !$factors->contains(static fn (EloquentFactor&Model $other): bool => $other->isConfirmed());
        $now         = CarbonImmutable::now();

        $factor->confirm($now);
        $factor->persist();

        $this->enrollments->forget($enrollment);

        $proof = new Proof(
            kind      : ProofKind::ADDITIONAL_FACTOR,
            method    : $type,
            channel   : FactorChannel::of($factor, $driver->channelKind()),
            reference : $enrollment->factor_id,
            properties: ObservedProperties::none(),
            provedAt  : $now,
            binding   : $binding,
            generation: VerificationGeneration::current($identity),
            challengeId: $check->challengeId,
        );

        if ($caller->pending === null && $first) {
            $this->assertAcceptedAfterFirstFactor($caller, $binding, $proof);
        }

        $acceptance = $this->container->make(ProofAcceptance::class);
        $result     = $caller->pending === null ? null : $acceptance->evaluate($caller, $proof, $driver->amr(), $type);
        $summary    = FactorSummary::fromFactor($factor);
        $context    = $this->events->context($identity, $application);

        $this->events->dispatch(new VerificationPassed($context, $summary, $type, Purpose::ENROLLMENT, $check->challengeId));
        $this->events->dispatch(new FactorConfirmed($context, $summary));

        if ($enrollment->authority === EnrollmentAuthorization::BOOTSTRAP) {
            $this->events->dispatch(new BootstrapEnrollmentCompleted($context, $summary));
        }

        ReenrollmentObligation::end($identity);

        $codes = $first ? $this->container->make(RecoveryCodeIssuance::class)->withFirstFactor($identity, $application, $proof) : [];

        if ($result !== null) {
            return EnrollmentConfirmation::confirmed($summary, $codes, $result->withCompletion($acceptance->handOver($caller, $result)));
        }

        $proofs    = $this->container->make(SessionFirstFactor::class)->proofs($identity, $application);
        $judgement = $this->container->make(SessionReevaluation::class)->judge($identity, $application, $binding->sessionId, FactorChangeMade::CONFIRMED, $summary, $proofs);

        return EnrollmentConfirmation::confirmed($summary, $codes, completion: $judgement->completion());
    }

    /**
     * Refuse an active session's first additional factor that its known first
     * factor does not accept: the session could not use it to verify.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function assertAcceptedAfterFirstFactor(Caller $caller, ProofBinding $binding, Proof $proof): void
    {
        $firstFactor = $this->container->make(SessionFirstFactor::class)->forBinding($caller->identity, $binding);

        OperationRefusedException::unless(
            $firstFactor === null || $this->container->make(RequirementCheck::class)->check(Requirement::none(), $firstFactor, $proof)->accepted,
            FailureReason::NOT_ACCEPTED,
            'The combination policy does not accept the factor after the session\'s first factor.',
        );
    }

    /**
     * Discard a grant no longer live, with its pending factor, and report it.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Mfa\Models\Enrollment  $enrollment
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     */
    private function expire(Caller $caller, ProofBinding $binding, Enrollment $enrollment, EloquentFactor&Model $factor): EnrollmentConfirmation
    {
        $this->enrollments->discard($enrollment, $factor);

        $summary = FactorSummary::fromFactor($factor);

        $this->events->dispatch(new EnrollmentExpired($this->events->context($caller->identity, $binding->application), $summary));

        return $this->failed($caller, $binding, $summary, FailureReason::EXPIRED);
    }

    /**
     * Report a code that failed, count it when it was wrong or replayed, and at
     * the cap abandon the enrolment; both commit. A check with nothing to
     * compare against counts nothing.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Mfa\Models\Enrollment  $enrollment
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Verification\CheckOutcome  $check
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     */
    private function count(Caller $caller, ProofBinding $binding, Enrollment $enrollment, EloquentFactor&Model $factor, CheckOutcome $check): EnrollmentConfirmation
    {
        $reason  = $check->reason ?? FailureReason::INVALID_CODE;
        $summary = FactorSummary::fromFactor($factor);
        $failed  = $this->failed($caller, $binding, $summary, $reason, $enrollment->challenge_id, $check->lockedUntil);

        if (!in_array($reason, self::COUNTED, true)) {
            return $failed;
        }

        if ($this->enrollments->countAttempt($enrollment) < (new EnrollmentSettings($this->config))->maxAttempts()) {
            return $failed;
        }

        $this->enrollments->discard($enrollment, $factor);

        $this->events->dispatch(new EnrollmentAbandoned($this->events->context($caller->identity, $binding->application), $summary));

        return EnrollmentConfirmation::failed($reason, abandoned: true);
    }

    /**
     * Report one failed attempt, naming the factor as it was found only when
     * the grant was bound to the caller, and answer it.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  ?\SineMacula\Laravel\Mfa\Factors\FactorSummary  $summary
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  ?string  $challengeId
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function failed(
        Caller $caller,
        ProofBinding $binding,
        ?FactorSummary $summary,
        FailureReason $reason,
        ?string $challengeId = null,
        ?CarbonImmutable $lockedUntil = null,
    ): EnrollmentConfirmation {
        $this->events->dispatch(new VerificationFailed(
            $this->events->context($caller->identity, $binding->application),
            $summary,
            $summary?->type,
            Purpose::ENROLLMENT,
            $reason,
            $challengeId,
        ));

        return EnrollmentConfirmation::failed($reason, $lockedUntil);
    }

    /**
     * What the address's throttle makes of how the attempt settled: only a
     * failure the enrolment counted keeps its slot.
     *
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation  $settled
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptOutcome
     */
    private static function attemptOutcome(EnrollmentConfirmation $settled): AttemptOutcome
    {
        return in_array($settled->reason, self::COUNTED, true) ? AttemptOutcome::fail() : AttemptOutcome::uncounted();
    }
}
