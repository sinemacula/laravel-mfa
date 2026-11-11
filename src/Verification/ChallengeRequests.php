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
 * Sends a delivered factor's code or asks for a passkey assertion, bound as the
 * verification that follows; sending resets no count.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ChallengeRequests
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContextResolver  $callers
     * @param  \SineMacula\Laravel\Mfa\Factors\OperationGuard  $guard
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptService  $attempts
     * @param  \SineMacula\Laravel\Mfa\Events\EventDispatcher  $events
     */
    public function __construct(

        /** Seams are resolved on every call. */
        private Container $container,

        /** Resolves who the request serves. */
        private CallerContextResolver $callers,

        /** Starts every operation on a factor. */
        private OperationGuard $guard,

        /** Throttles the request's IP address. */
        private AttemptService $attempts,

        /** Dispatches `CodeSent`. */
        private EventDispatcher $events,
    ) {}

    /**
     * A refusal is the result's reason; nothing is reported, since no attempt
     * was made.
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
     * Only the package's own refusals become a reason; a seam's exception
     * propagates.
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
     * Hold a slot of the IP address's window and the identity's lock.
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
     * Resolve the caller again so a changed sign-in sends nothing; `CodeSent`
     * dispatches on commit, whichever gateway sent.
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
            $context = $this->events->context($caller->identity, $binding->application, $caller->client, $binding->sessionId);

            $this->events->dispatch(new CodeSent($context, FactorSummary::fromFactor($factor), $binding->purpose, $challengeId));
        }

        return $result;
    }
}
