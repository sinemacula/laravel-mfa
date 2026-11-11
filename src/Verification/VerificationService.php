<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Verification;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Attempts\AttemptOutcome;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Enums\SubmissionKind;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Events\VerificationFailed;
use SineMacula\Laravel\Mfa\Events\VerificationPassed;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\RefusedUnderLockException;
use SineMacula\Laravel\Mfa\Exceptions\SignInChangedException;
use SineMacula\Laravel\Mfa\Factors\FactorChannel;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Factors\OperationGuard;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;

/**
 * The one way a person verifies. The caller and binding are resolved again
 * under the identity's lock, so a sign-in that changed meanwhile counts and
 * reports nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class VerificationService
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContextResolver  $callers
     * @param  \SineMacula\Laravel\Mfa\Factors\OperationGuard  $guard
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptService  $attempts
     * @param  \SineMacula\Laravel\Mfa\Verification\SubmissionRoutes  $routes
     * @param  \SineMacula\Laravel\Mfa\Events\EventDispatcher  $events
     */
    public function __construct(

        /** Seams and configuration are resolved on every call. */
        private Container $container,

        /** Resolves who the request serves. */
        private CallerContextResolver $callers,

        /** Starts every operation on a factor. */
        private OperationGuard $guard,

        /** Throttles the request's IP address. */
        private AttemptService $attempts,

        /** Checks a submission along its route. */
        private SubmissionRoutes $routes,

        /** Dispatches the verification events. */
        private EventDispatcher $events,
    ) {}

    /**
     * A failure is a result with one `VerificationFailed`; anything thrown
     * after commit propagates, never reported as failed.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @param  \SineMacula\Laravel\Mfa\Verification\Submission  $submission
     * @param  ?\SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     *
     * @throws \Throwable
     */
    public function verify(CallerContext $context, #[\SensitiveParameter] Submission $submission, ?Purpose $purpose = null): VerificationResult
    {
        $caller = $this->callers->resolve($context, PendingAction::VERIFY);

        if ($caller === null) {
            return VerificationResult::failed(FailureReason::NOT_FOUND, 'The caller is nobody this verifies for.');
        }

        $allowed = PurposeRule::resolve($caller, $purpose);

        if ($allowed === null) {
            $application = $this->callers->application($caller);

            return $this->refused($caller, $application, $purpose ?? Purpose::SIGN_IN, FailureReason::NOT_ACCEPTED, 'A verification is not made for that purpose.');
        }

        $binding = $this->callers->binding($caller, $allowed);

        if ($binding === null) {
            return VerificationResult::failed(FailureReason::NOT_FOUND, 'The identity has no sign-in to bind the verification to.');
        }

        return $submission->kind === SubmissionKind::RECOVERY_CODE
            ? $this->attempt($submission, $caller, $binding, null, null)
            : $this->attemptFactor($submission, $caller, $binding);
    }

    /**
     * Refuse a factor that may not be used or takes another kind of submission.
     *
     * @param  \SineMacula\Laravel\Mfa\Verification\Submission  $submission
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     *
     * @throws \Throwable
     */
    private function attemptFactor(#[\SensitiveParameter] Submission $submission, Caller $caller, ProofBinding $binding): VerificationResult
    {
        try {
            $factor = $this->guard->factor($caller->identity, $submission->factorId, $binding->application);
        } catch (OperationRefusedException $exception) {
            return $this->refused($caller, $binding->application, $binding->purpose, $exception->reason, $exception->getMessage(), $binding->sessionId);
        }

        $driver = $this->container->make(DriverResolver::class)->fromContainer($this->container, $factor->getType());

        if (!SubmissionRoutes::fits($submission, $driver, $factor->getType())) {
            $check = CheckOutcome::refused(FailureReason::NOT_FOUND, 'The factor does not take that kind of submission.');

            return $this->report($caller, $binding, FactorSummary::fromFactor($factor), $factor->getType(), $submission, $check);
        }

        return $this->attempt($submission, $caller, $binding, $factor, $driver);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Verification\Submission  $submission
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor)|null  $factor
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     *
     * @throws \Throwable
     */
    private function attempt(
        #[\SensitiveParameter] Submission $submission,
        Caller $caller,
        ProofBinding $binding,
        (EloquentFactor&Model)|null $factor,
        ?FactorDriver $driver,
    ): VerificationResult {
        $settled = $this->settled($submission, $caller, $binding, $factor, $driver);

        if ($settled instanceof VerificationResult) {
            return $settled;
        }

        $vanished = $settled->reason     === FailureReason::NOT_FOUND && !$settled->counted;
        $summary  = $vanished || $factor === null ? null : FactorSummary::fromFactor($factor);
        $type     = $factor              === null ? RecoveryCodeService::TYPE : $factor->getType();

        return $this->report($caller, $binding, $summary, $vanished ? null : $type, $submission, $settled);
    }

    /**
     * A refusal carried out of the transaction has rolled back what the attempt
     * did; anything thrown after commit propagates.
     *
     * @param  \SineMacula\Laravel\Mfa\Verification\Submission  $submission
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor)|null  $factor
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @return \SineMacula\Laravel\Mfa\Verification\CheckOutcome|\SineMacula\Laravel\Mfa\Verification\VerificationResult
     *
     * @throws \Throwable
     */
    private function settled(
        #[\SensitiveParameter]
        Submission $submission,
        Caller $caller,
        ProofBinding $binding,
        (EloquentFactor&Model)|null $factor,
        ?FactorDriver $driver,
    ): CheckOutcome|VerificationResult {
        $settled = CheckOutcome::refused(FailureReason::NOT_FOUND, 'The verification did not run.');

        try {
            $outcome = $this->attempts->throttled(
                $caller->client->ip,
                function () use ($submission, $caller, $binding, $factor, $driver, &$settled): AttemptOutcome {

                    $settled = $this->transaction($submission, $caller, $binding, $factor, $driver);

                    return self::attemptOutcome($settled);
                },
            );
        } catch (SignInChangedException) {
            return VerificationResult::failed(FailureReason::NOT_FOUND, 'The sign-in the verification was made for is no longer the caller\'s.');
        } catch (RefusedUnderLockException $exception) {
            return CheckOutcome::refused($exception->refusal->reason, $exception->refusal->getMessage(), challengeId: $exception->challengeId);
        }

        return $outcome->lockout === null ? $settled : CheckOutcome::refused(FailureReason::LOCKED, $outcome->lockout->detail(), $outcome->lockout->until);
    }

    /**
     * A counted failure returns and so commits; a refusal thrown inside rolls
     * back and is carried out.
     *
     * @param  \SineMacula\Laravel\Mfa\Verification\Submission  $submission
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $served
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor)|null  $factor
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @return \SineMacula\Laravel\Mfa\Verification\CheckOutcome|\SineMacula\Laravel\Mfa\Verification\VerificationResult
     *
     * @throws \Throwable
     */
    private function transaction(
        #[\SensitiveParameter] Submission $submission,
        Caller $served,
        ProofBinding $binding,
        (EloquentFactor&Model)|null $factor,
        ?FactorDriver $driver,
    ): CheckOutcome|VerificationResult {
        $model = $factor ?? new (ConfiguredModels::factor($this->container->make(Repository::class)));

        $settle = function (Collection $factors) use ($submission, $served, $binding, $factor, $driver): CheckOutcome|VerificationResult {

            $caller = $this->callers->still($served, PendingAction::VERIFY, $binding)
                ?? throw new SignInChangedException('The sign-in changed before the identity\'s lock was held.');

            return RefusedUnderLockException::carrying(function () use ($submission, $caller, $binding, $factor, $driver, $factors): CheckOutcome|VerificationResult {

                if ($factor === null || $driver === null) {
                    return $this->settleRecoveryCode($submission, $caller, $binding);
                }

                $stored = LockedFactors::find($factor, $factors);

                return $stored === null
                    ? CheckOutcome::refused(FailureReason::NOT_FOUND, 'The factor is no longer among the identity\'s factors.')
                    : $this->settleFactor($submission, $caller, $binding, $stored, $driver);
            });
        };

        return FactorStateTransaction::forIdentity($served->identity, $model, $settle);
    }

    /**
     * Under the lock: admit, check and count, then on a pass stamp the factor's
     * last use and complete.
     *
     * @param  \SineMacula\Laravel\Mfa\Verification\Submission  $submission
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @return \SineMacula\Laravel\Mfa\Verification\CheckOutcome|\SineMacula\Laravel\Mfa\Verification\VerificationResult
     *
     * @throws \Throwable
     */
    private function settleFactor(
        #[\SensitiveParameter] Submission $submission,
        Caller $caller,
        ProofBinding $binding,
        EloquentFactor&Model $factor,
        FactorDriver $driver,
    ): CheckOutcome|VerificationResult {
        $admission = $this->container->make(ChallengeCounters::class)->underLock($caller->context(), $factor, $binding);

        if (!$admission->isAdmitted()) {
            return CheckOutcome::refusedBy($admission);
        }

        $check = $this->routes->factor($caller, $submission, $factor, $driver, $binding);

        if (!$check->hasPassed()) {
            return $check;
        }

        $factor->recordVerification();
        $factor->persist();

        $reference = (string) LockedFactors::idOf($factor);
        $channel   = FactorChannel::of($factor, $driver->channelKind());

        $generation = VerificationGeneration::current($caller->identity);
        $properties = self::observed($check);
        $now        = CarbonImmutable::now();
        $proof      = new Proof(ProofKind::ADDITIONAL_FACTOR, $factor->getType(), $channel, $reference, $properties, $now, $binding, $generation, $check->challengeId);

        return $this->complete($caller, $proof, $check, $driver->amr(), FactorSummary::fromFactor($factor), $factor->getType());
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Verification\Submission  $submission
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Verification\CheckOutcome|\SineMacula\Laravel\Mfa\Verification\VerificationResult
     *
     * @throws \Throwable
     */
    private function settleRecoveryCode(#[\SensitiveParameter] Submission $submission, Caller $caller, ProofBinding $binding): CheckOutcome|VerificationResult
    {
        $admission = $this->container->make(RecoveryCodeService::class)->admission($caller->identity, $binding, $caller->pending);

        if (!$admission->isAdmitted()) {
            return CheckOutcome::refusedBy($admission);
        }

        $check = $this->routes->recoveryCode($caller, $submission, $binding);

        if (!$check->hasPassed()) {
            return $check;
        }

        $generation = VerificationGeneration::current($caller->identity);
        $proof      = new Proof(ProofKind::RECOVERY_CODE, RecoveryCodeService::TYPE, null, null, self::observed($check), CarbonImmutable::now(), $binding, $generation);

        return $this->complete($caller, $proof, $check, [], null, RecoveryCodeService::TYPE);
    }

    /**
     * Events are queued under the lock, so a rollback discards them.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @param  \SineMacula\Laravel\Mfa\Verification\CheckOutcome  $check
     * @param  list<string>  $driverAmr
     * @param  ?\SineMacula\Laravel\Mfa\Factors\FactorSummary  $summary
     * @param  string  $type
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\RefusedUnderLockException
     */
    private function complete(Caller $caller, Proof $proof, CheckOutcome $check, array $driverAmr, ?FactorSummary $summary, string $type): VerificationResult
    {
        return RefusedUnderLockException::carrying(
            fn (): VerificationResult => $this->accept($caller, $proof, $check, $driverAmr, $summary, $type),
            $proof->challengeId,
        );
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @param  \SineMacula\Laravel\Mfa\Verification\CheckOutcome  $check
     * @param  list<string>  $driverAmr
     * @param  ?\SineMacula\Laravel\Mfa\Factors\FactorSummary  $summary
     * @param  string  $type
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function accept(Caller $caller, Proof $proof, CheckOutcome $check, array $driverAmr, ?FactorSummary $summary, string $type): VerificationResult
    {
        $acceptance = $this->container->make(ProofAcceptance::class);
        $binding    = $proof->binding;
        $result     = $acceptance->evaluate($caller, $proof, $driverAmr, $type);
        $completion = $acceptance->handOver($caller, $result);
        $context    = $this->events->context($caller->identity, $binding->application, $caller->client, $binding->sessionId);

        $this->events->dispatch(new VerificationPassed($context, $summary, $type, $binding->purpose, $proof->challengeId));

        if ($check->remaining !== null) {
            $this->container->make(RecoveryCodeService::class)->reportRedeemed($caller->identity, $binding, $check->remaining, $caller->client);
        }

        return $result->withCompletion($completion);
    }

    /**
     * Report a refusal made before any factor or attempt.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @param  ?string  $signInId
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function refused(Caller $caller, string $application, Purpose $purpose, FailureReason $reason, string $detail, ?string $signInId = null): VerificationResult
    {
        $context = $this->events->context($caller->identity, $application, $caller->client, $signInId ?? $caller->pending?->sessionId);

        $this->events->dispatch(new VerificationFailed($context, null, null, $purpose, $reason));

        return VerificationResult::failed($reason, $detail);
    }

    /**
     * Name a challenge only with the factor it was named for.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  ?\SineMacula\Laravel\Mfa\Factors\FactorSummary  $summary
     * @param  ?string  $type
     * @param  \SineMacula\Laravel\Mfa\Verification\Submission  $submission
     * @param  \SineMacula\Laravel\Mfa\Verification\CheckOutcome  $check
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function report(
        Caller $caller,
        ProofBinding $binding,
        ?FactorSummary $summary,
        ?string $type,
        #[\SensitiveParameter] Submission $submission,
        CheckOutcome $check,
    ): VerificationResult {
        $reason = $check->reason ?? FailureReason::INVALID_CODE;

        $this->events->dispatch(new VerificationFailed(
            $this->events->context($caller->identity, $binding->application, $caller->client, $binding->sessionId),
            $summary,
            $type,
            $binding->purpose,
            $reason,
            $summary === null ? null : ($check->challengeId ?? $submission->challengeId),
        ));

        return VerificationResult::failed($reason, $check->detail, $check->lockedUntil);
    }

    /**
     * Only a counted failure keeps its throttle slot.
     *
     * @param  \SineMacula\Laravel\Mfa\Verification\CheckOutcome|\SineMacula\Laravel\Mfa\Verification\VerificationResult  $settled
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptOutcome
     */
    private static function attemptOutcome(CheckOutcome|VerificationResult $settled): AttemptOutcome
    {
        return match (true) {
            $settled instanceof VerificationResult => AttemptOutcome::pass(),
            $settled->counted                      => AttemptOutcome::fail(),
            default                                => AttemptOutcome::uncounted(),
        };
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Verification\CheckOutcome  $check
     * @return \SineMacula\Laravel\Mfa\Assurance\ObservedProperties
     *
     * @throws \LogicException
     */
    private static function observed(CheckOutcome $check): ObservedProperties
    {
        return $check->properties ?? throw new \LogicException('A check that passed says what it observed.');
    }
}
