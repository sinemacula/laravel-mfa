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
 * The one way a person verifies: a code for one of their factors, a code
 * answering a challenge, a recovery code or a passkey's assertion, with one
 * result and one reason for every failure.
 *
 * The caller and what it is bound to (the owner, the application, the sign-in
 * and the purpose) are captured once and threaded through the check and the
 * proof. An IP address slot is taken, then the identity's factor state lock.
 * Under the lock the caller and the binding are resolved again and compared, so
 * a sign-in that ended or changed in the meantime is refused, counting and
 * reporting nothing; the submission is admitted, then checked and counted along
 * its one route (see `SubmissionRoutes`). A failure ends there, so its count
 * commits. A success makes the proof, stamped with the verification generation
 * read under the lock, which must itself be accepted after the session's first
 * factor; the whole requirement is evaluated again with it; the result goes to
 * `PendingCompletion` or `StepUp` as the last write of the transaction, so
 * their refusal rolls back the code's use and the count (see
 * `ProofAcceptance`).
 *
 * A failure is a result, carrying a reason a caller may be told, with one
 * `VerificationFailed` once the transaction has ended, except where the request
 * serves nobody at all. A success dispatches `VerificationPassed`, and for a
 * recovery code `RecoveryCodeUsed` and `RecoveryCodesLow`, once it commits,
 * after the default seams' proof reaches the store. Any exception but a refusal
 * made inside the transaction propagates, one a listener throws after the
 * commit included: what committed is never reported as failed.
 *
 * Stateless: the seams are resolved on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class VerificationService
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContextResolver  $callers
     * @param  \SineMacula\Laravel\Mfa\Factors\OperationGuard  $guard
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptService  $attempts
     * @param  \SineMacula\Laravel\Mfa\Verification\SubmissionRoutes  $routes
     * @param  \SineMacula\Laravel\Mfa\Events\EventDispatcher  $events
     */
    public function __construct(

        /** The container the seams and the configuration are resolved from. */
        private Container $container,

        /** The resolver of who the request serves. */
        private CallerContextResolver $callers,

        /** The guard every operation on a factor starts with. */
        private OperationGuard $guard,

        /** The throttle on the request's IP address. */
        private AttemptService $attempts,

        /** The routes a submission is checked along. */
        private SubmissionRoutes $routes,

        /** The dispatcher of the verification events. */
        private EventDispatcher $events,
    ) {}

    /**
     * Verify the submission for the purpose given: for a pending session,
     * completing its sign-in; for an active one, stepping up unless `sign_in`
     * is asked for. See `PurposeRule`.
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
     * Find the submission's factor and its driver, refuse one that may not be
     * used or that takes another kind of submission, and make the attempt.
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
            return $this->refused($caller, $binding->application, $binding->purpose, $exception->reason, $exception->getMessage());
        }

        $driver = $this->container->make(DriverResolver::class)->fromContainer($this->container, $factor->getType());

        if (!SubmissionRoutes::fits($submission, $driver, $factor->getType())) {
            $check = CheckOutcome::refused(FailureReason::NOT_FOUND, 'The factor does not take that kind of submission.');

            return $this->report($caller, $binding, FactorSummary::fromFactor($factor), $factor->getType(), $submission, $check);
        }

        return $this->attempt($submission, $caller, $binding, $factor, $driver);
    }

    /**
     * Make the attempt holding a slot of the IP address's window and the
     * identity's lock, and report how it failed if it did.
     *
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
     * How the attempt settled, holding a slot of the IP address's window and,
     * once it has one, the identity's lock. A refusal carried out of the
     * transaction has rolled back what the attempt did; one the address's
     * throttle made ran nothing. Anything thrown once the transaction committed
     * propagates.
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
     * Open the identity's factor state transaction and settle the attempt in
     * it. What a success returns commits with it, and what a failure counted
     * commits too, since it returns; a refusal thrown inside it rolls
     * everything back and is carried out, marked as made before the commit.
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
     * Under the lock: admit the factor as stored, check and count the
     * submission, and on a pass stamp the factor's last use and complete.
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
     * Under the lock: admit the recovery code, redeem it, and on a pass
     * complete.
     *
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
     * Under the lock: refuse a proof that is not itself accepted after the
     * session's first factor, whatever an older proof shows; evaluate the whole
     * requirement again with it; hand the result to the seam; and queue the
     * events, so a rollback discards them.
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
     * Evaluate and hand over a proof the route made, refusing one the
     * combination policy does not accept; see `complete()`.
     *
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
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function refused(Caller $caller, string $application, Purpose $purpose, FailureReason $reason, string $detail): VerificationResult
    {
        $context = $this->events->context($caller->identity, $application, $caller->client, $caller->pending?->sessionId);

        $this->events->dispatch(new VerificationFailed($context, null, null, $purpose, $reason));

        return VerificationResult::failed($reason, $detail);
    }

    /**
     * Report a failed attempt, once, and answer it: with the challenge a check
     * reported before a seam refused, or the one the submission named, and only
     * with the factor it was named for.
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
     * What the address's throttle makes of how the attempt settled: only a
     * failure that was counted keeps its slot.
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
     * What a check that passed observed.
     *
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
