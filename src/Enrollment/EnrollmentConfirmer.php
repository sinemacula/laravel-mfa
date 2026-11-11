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
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\CallerContext;
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
 * Confirms a pending factor with its first valid code, under the identity's
 * factor lock. Wrong codes count only against the enrolment's own cap, never
 * the identity's or factor's. A refusal after a valid code throws so every
 * write rolls back. On an active session no proof is recorded, since the code
 * was bound to the enrolment.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EnrollmentConfirmer
{
    /** @var list<\SineMacula\Laravel\Mfa\Enums\FailureReason> Failures that count against the enrolment's cap. */
    private const array COUNTED = [FailureReason::INVALID_CODE, FailureReason::REPLAYED];

    /**
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

        /** Resolves seams. */
        private Container $container,

        /** Configuration. */
        private Repository $config,

        /** Caller resolver. */
        private CallerContextResolver $callers,

        /** Factor operation guard. */
        private OperationGuard $guard,

        /** IP throttle and identity lockout. */
        private AttemptService $attempts,

        /** Enrolment authorisation. */
        private EnrollmentAuthority $authority,

        /** Enrolments in progress. */
        private PendingEnrollments $enrollments,

        /** Event dispatcher. */
        private EventDispatcher $events,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @param  \SineMacula\Laravel\Mfa\Secrets\RevealedSecret|string  $grant
     * @param  string  $code
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation
     *
     * @throws \Throwable
     */
    public function confirm(CallerContext $context, #[\SensitiveParameter] RevealedSecret|string $grant, #[\SensitiveParameter] string $code): EnrollmentConfirmation
    {
        $caller  = $this->callers->resolve($context, PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT);
        $binding = $caller === null ? null : $this->callers->binding($caller, Purpose::ENROLLMENT);

        if ($caller === null || $binding === null) {
            return EnrollmentConfirmation::failed(FailureReason::NOT_FOUND);
        }

        return $this->attempt($caller, $binding, EnrollmentGrant::hash($grant), $code);
    }

    /**
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
                $caller->client->ip,
                function () use ($caller, $binding, $grantHash, $code, &$settled, &$summary): AttemptOutcome {

                    $settled = FactorStateTransaction::forIdentity(
                        $caller->identity,
                        new (ConfiguredModels::factor($this->config)),
                        function (Collection $factors) use ($caller, $binding, $grantHash, $code, &$summary): EnrollmentConfirmation {

                            $current = $this->callers->still($caller, PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT, $binding)
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
     * The summary is taken before settling, since a rolled-back confirmation
     * still changes the instance.
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
        $check  = $this->check($caller, $driver, $factor, $enrollment, $binding, $code);

        return $check->hasPassed()
            ? RefusedUnderLockException::carrying(
                fn (): EnrollmentConfirmation => $this->complete($caller, $binding, $enrollment, $factor, $factors, $driver, $check),
                $check->challengeId,
            )
            : $this->count($caller, $binding, $enrollment, $factor, $check);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Models\Enrollment  $enrollment
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $code
     * @return \SineMacula\Laravel\Mfa\Verification\CheckOutcome
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function check(
        Caller $caller,
        FactorDriver $driver,
        EloquentFactor&Model $factor,
        Enrollment $enrollment,
        ProofBinding $binding,
        #[\SensitiveParameter] string $code,
    ): CheckOutcome {
        if (!$driver instanceof CodeDeliveryDriver) {
            $check   = $driver->confirm($factor, $code, $binding);
            $failure = $check->failure();

            return $failure === null ? CheckOutcome::passed(ObservedProperties::none()) : CheckOutcome::failed($failure, $check->detail());
        }

        $challengeId = (string) $enrollment->challenge_id;
        $outcome     = $this->container->make(ChallengeGateway::class)->verify($caller->context(), $factor, $binding, $challengeId, $code);

        return $outcome->reason === null
            ? CheckOutcome::passed(ObservedProperties::none(), $challengeId)
            : CheckOutcome::refused($outcome->reason, $outcome->detail, $outcome->lockedUntil);
    }

    /**
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
        $context    = $this->events->context($identity, $application, $caller->client, $binding->sessionId);

        $this->events->dispatch(new VerificationPassed($context, $summary, $type, Purpose::ENROLLMENT, $check->challengeId));
        $this->events->dispatch(new FactorConfirmed($context, $summary));

        if ($enrollment->authority === EnrollmentAuthorization::BOOTSTRAP) {
            $this->events->dispatch(new BootstrapEnrollmentCompleted($context, $summary));
        }

        ReenrollmentObligation::end($identity);

        $codes = $first ? $this->container->make(RecoveryCodeIssuance::class)->withFirstFactor($identity, $application, $proof, $caller->pending, $caller->client) : [];

        if ($result !== null) {
            return EnrollmentConfirmation::confirmed($summary, $codes, $result->withCompletion($acceptance->handOver($caller, $result)));
        }

        $proofs    = $this->container->make(SessionFirstFactor::class)->proofsOf($identity, $application, $binding->sessionId);
        $judgement = $this->container->make(SessionReevaluation::class)->judge($identity, $application, $binding->sessionId, FactorChangeMade::CONFIRMED, $summary, $proofs);

        return EnrollmentConfirmation::confirmed($summary, $codes, completion: $judgement->completion());
    }

    /**
     * The session could not verify with a factor its first factor rejects.
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
        $firstFactor = $this->container->make(SessionFirstFactor::class)->forBinding($caller->identity, $binding, $caller->pending);

        OperationRefusedException::unless(
            $firstFactor === null || $this->container->make(RequirementCheck::class)->check(Requirement::none(), $firstFactor, $proof)->accepted,
            FailureReason::NOT_ACCEPTED,
            'The combination policy does not accept the factor after the session\'s first factor.',
        );
    }

    /**
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

        $this->events->dispatch(new EnrollmentExpired($this->events->context($caller->identity, $binding->application, $caller->client, $binding->sessionId), $summary));

        return $this->failed($caller, $binding, $summary, FailureReason::EXPIRED);
    }

    /**
     * At the cap the enrolment is abandoned; both outcomes commit.
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

        $this->events->dispatch(new EnrollmentAbandoned($this->events->context($caller->identity, $binding->application, $caller->client, $binding->sessionId), $summary));

        return EnrollmentConfirmation::failed($reason, abandoned: true);
    }

    /**
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
            $this->events->context($caller->identity, $binding->application, $caller->client, $binding->sessionId),
            $summary,
            $summary?->type,
            Purpose::ENROLLMENT,
            $reason,
            $challengeId,
        ));

        return EnrollmentConfirmation::failed($reason, $lockedUntil);
    }

    /**
     * Only a counted failure keeps its IP slot.
     *
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation  $settled
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptOutcome
     */
    private static function attemptOutcome(EnrollmentConfirmation $settled): AttemptOutcome
    {
        return in_array($settled->reason, self::COUNTED, true) ? AttemptOutcome::fail() : AttemptOutcome::uncounted();
    }
}
