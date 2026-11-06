<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Verification;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Attempts\AttemptOutcome;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\CodeDeliveryDriver;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\CodeSent;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\RefusedUnderLockException;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Factors\OperationGuard;
use SineMacula\Laravel\Mfa\Passkeys\AssertionRequest;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertions;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;

/**
 * What comes before a verification of a factor that needs a challenge: sending
 * a delivered factor's code, and asking for a passkey's assertion, each bound
 * to the caller's identity, application, sign-in and purpose as the
 * verification that follows will be.
 *
 * Sending takes the shape a verification does: the caller and the binding are
 * captured, an IP address slot is taken, and under the identity's factor state
 * lock they are resolved again, so a sign-in that changed sends nothing. The
 * factor as stored there is admitted, and the bound `ChallengeGateway` sends
 * the code; `CodeSent` is dispatched once it commits, whichever gateway sent
 * it. A refusal is the result's reason: nothing is reported, since no attempt
 * was made, and sending resets no count and lifts no lockout.
 *
 * Stateless: the seams are resolved on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ChallengeRequests
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContextResolver  $callers
     * @param  \SineMacula\Laravel\Mfa\Factors\OperationGuard  $guard
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptService  $attempts
     * @param  \SineMacula\Laravel\Mfa\Events\EventDispatcher  $events
     */
    public function __construct(

        /** The container the seams are resolved from. */
        private Container $container,

        /** The resolver of who the request serves. */
        private CallerContextResolver $callers,

        /** The guard every operation on a factor starts with. */
        private OperationGuard $guard,

        /** The throttle on the request's IP address. */
        private AttemptService $attempts,

        /** The dispatcher of `CodeSent`. */
        private EventDispatcher $events,
    ) {}

    /**
     * Send a code for the caller's delivered factor. Refused as `not_found`
     * when the request serves nobody or the identity has no sign-in, and when
     * the factor is missing, another's, or delivers no codes.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @param  mixed  $factorId
     * @param  ?\SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     *
     * @throws \Throwable
     */
    public function sendCode(CallerContext $context, mixed $factorId, ?Purpose $purpose = null): SendResult
    {
        $caller = $this->callers->resolve($context, PendingAction::SEND_CODE);

        if ($caller === null) {
            return SendResult::refused(FailureReason::NOT_FOUND);
        }

        $allowed = PurposeRule::resolve($caller, $purpose);

        if ($allowed === null) {
            return SendResult::refused(FailureReason::NOT_ACCEPTED);
        }

        $binding = $this->callers->binding($caller, $allowed);

        if ($binding === null) {
            return SendResult::refused(FailureReason::NOT_FOUND);
        }

        try {
            $factor = $this->guard->factor($caller->identity, $factorId, $binding->application);
        } catch (OperationRefusedException $exception) {
            return SendResult::refused($exception->reason);
        }

        try {
            return $this->send($caller, $binding, $factor);
        } catch (RefusedUnderLockException $exception) {
            return SendResult::refused($exception->refusal->reason);
        }
    }

    /**
     * The options of an assertion request for the caller's passkey factor, or
     * the reason there are none: `not_found` when the request serves nobody for
     * verifying. Only the package's own refusals are answered as a reason: a
     * seam's exception propagates.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @param  mixed  $factorId
     * @param  ?\SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Passkeys\AssertionRequest
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    public function requestAssertion(CallerContext $context, mixed $factorId, ?Purpose $purpose = null): AssertionRequest
    {
        $caller = $this->callers->resolve($context, PendingAction::VERIFY);

        if ($caller === null) {
            return AssertionRequest::refused(FailureReason::NOT_FOUND);
        }

        try {
            return AssertionRequest::started($this->assertionOptions($caller, $factorId, $purpose));
        } catch (OperationRefusedException $exception) {
            return $exception->byPackage ? AssertionRequest::refused($exception->reason) : throw $exception;
        }
    }

    /**
     * The options of the assertion request, refusing a purpose a ceremony is
     * not made for, a caller with no sign-in to bind it to and a factor the
     * caller may not use.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  mixed  $factorId
     * @param  ?\SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return array<string, mixed>
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    private function assertionOptions(Caller $caller, mixed $factorId, ?Purpose $purpose): array
    {
        $allowed = PurposeRule::resolve($caller, $purpose);

        OperationRefusedException::byPackageUnless($allowed !== null, FailureReason::NOT_ACCEPTED, 'An assertion is not requested for that purpose.');

        $binding = $this->callers->binding($caller, $allowed);

        OperationRefusedException::byPackageUnless($binding !== null, FailureReason::NOT_FOUND, 'The identity has no sign-in to bind the ceremony to.');

        $factor = $this->guard->factor($caller->identity, $factorId, $binding->application);

        return $this->container->make(PasskeyAssertions::class)->options($caller->identity, $factor, $binding, $caller->pending);
    }

    /**
     * Send the code holding a slot of the IP address's window and the
     * identity's lock.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     *
     * @throws \Throwable
     */
    private function send(Caller $caller, ProofBinding $binding, EloquentFactor&Model $factor): SendResult
    {
        $driver = $this->container->make(DriverResolver::class)->fromContainer($this->container, $factor->getType());

        if (!$driver instanceof CodeDeliveryDriver) {
            return SendResult::refused(FailureReason::NOT_FOUND);
        }

        $result = SendResult::refused(FailureReason::NOT_FOUND);

        $outcome = $this->attempts->throttled(
            $caller->client->ip,
            function () use ($caller, $binding, $factor, &$result): AttemptOutcome {

                $result = FactorStateTransaction::forIdentity(
                    $caller->identity,
                    $factor,
                    fn (Collection $factors): SendResult => RefusedUnderLockException::carrying(
                        fn (): SendResult => $this->sendUnderLock($caller, $binding, LockedFactors::find($factor, $factors)),
                    ),
                );

                return AttemptOutcome::uncounted();
            },
        );

        return $outcome->lockout === null ? $result : SendResult::refusedBy(ChallengeAdmission::locked($outcome->lockout));
    }

    /**
     * Under the lock: refuse a sign-in that changed and a factor no longer
     * stored, admit the factor, send the code and queue `CodeSent`.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $served
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor)|null  $factor
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     *
     * @throws \Throwable
     */
    private function sendUnderLock(Caller $served, ProofBinding $binding, (EloquentFactor&Model)|null $factor): SendResult
    {
        $caller = $this->callers->still($served, PendingAction::SEND_CODE, $binding);

        if ($caller === null || $factor === null) {
            return SendResult::refused(FailureReason::NOT_FOUND);
        }

        $admission = $this->container->make(ChallengeCounters::class)->underLock($caller->context(), $factor, $binding);

        if (!$admission->isAdmitted()) {
            return SendResult::refusedBy($admission);
        }

        $result      = $this->container->make(ChallengeGateway::class)->send($caller->context(), $factor, $binding);
        $challengeId = $result->challengeId;

        if ($challengeId !== null) {
            $context = $this->events->context($caller->identity, $binding->application, $caller->client);

            $this->events->dispatch(new CodeSent($context, FactorSummary::fromFactor($factor), $binding->purpose, $challengeId));
        }

        return $result;
    }
}
