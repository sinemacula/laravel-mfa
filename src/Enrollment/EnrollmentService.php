<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enrollment;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Attempts\AttemptOutcome;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\CodeDeliveryDriver;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\CodeSent;
use SineMacula\Laravel\Mfa\Events\EnrollmentAbandoned;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;

/**
 * Enrols every factor type except passkeys, which the passkey change gate
 * associates. Refusals are results, since `not_fresh` is an ordinary path.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EnrollmentService
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContextResolver  $callers
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptService  $attempts
     * @param  \SineMacula\Laravel\Mfa\Enrollment\PendingEnrollments  $enrollments
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStarter  $starter
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmer  $confirmer
     * @param  \SineMacula\Laravel\Mfa\Events\EventDispatcher  $events
     */
    public function __construct(

        /** Resolves seams. */
        private Container $container,

        /** Configuration. */
        private Repository $config,

        /** Caller resolver. */
        private CallerContextResolver $callers,

        /** IP throttle. */
        private AttemptService $attempts,

        /** Enrolments in progress. */
        private PendingEnrollments $enrollments,

        /** Starts enrolments. */
        private EnrollmentStarter $starter,

        /** Confirms enrolments. */
        private EnrollmentConfirmer $confirmer,

        /** Event dispatcher. */
        private EventDispatcher $events,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest  $request
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart
     *
     * @throws \Throwable
     */
    public function start(CallerContext $context, #[\SensitiveParameter] EnrollmentRequest $request): EnrollmentStart
    {
        return $this->starter->start($context, $request);
    }

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
        return $this->confirmer->confirm($context, $grant, $code);
    }

    /**
     * Subject to the send cooldown and caps; renews neither the grant's expiry
     * nor its attempts.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @param  \SineMacula\Laravel\Mfa\Secrets\RevealedSecret|string  $grant
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     *
     * @throws \Throwable
     */
    public function resend(CallerContext $context, #[\SensitiveParameter] RevealedSecret|string $grant): SendResult
    {
        $caller  = $this->callers->resolve($context, PendingAction::START_BOOTSTRAP_ENROLLMENT);
        $binding = $caller === null ? null : $this->callers->binding($caller, Purpose::ENROLLMENT);

        if ($caller === null || $binding === null) {
            return SendResult::refused(FailureReason::NOT_FOUND);
        }

        $result  = SendResult::refused(FailureReason::NOT_FOUND);
        $hash    = EnrollmentGrant::hash($grant);
        $outcome = $this->attempts->throttled(
            $caller->client->ip,
            function () use ($caller, $binding, $hash, &$result): AttemptOutcome {

                $result = FactorStateTransaction::forIdentity(
                    $caller->identity,
                    new (ConfiguredModels::factor($this->config)),
                    fn (Collection $factors): SendResult => $this->resendUnderLock($caller, $binding, $hash, $factors),
                );

                return AttemptOutcome::uncounted();
            },
        );

        return $outcome->lockout === null ? $result : SendResult::refusedBy(ChallengeAdmission::locked($outcome->lockout));
    }

    /**
     * Delete the pending factor. Needs no step-up and works during a lockout,
     * since it only gives something up.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @param  \SineMacula\Laravel\Mfa\Secrets\RevealedSecret|string  $grant
     * @return bool
     *
     * @throws \Throwable
     *
     * @imperative
     */
    public function cancel(CallerContext $context, #[\SensitiveParameter] RevealedSecret|string $grant): bool
    {
        $caller  = $this->callers->resolve($context, PendingAction::START_BOOTSTRAP_ENROLLMENT);
        $binding = $caller === null ? null : $this->callers->binding($caller, Purpose::ENROLLMENT);

        if ($caller === null || $binding === null) {
            return false;
        }

        $hash = EnrollmentGrant::hash($grant);

        return FactorStateTransaction::forIdentity(
            $caller->identity,
            new (ConfiguredModels::factor($this->config)),
            function (Collection $factors) use ($caller, $binding, $hash): bool {

                $still   = $this->callers->still($caller, PendingAction::START_BOOTSTRAP_ENROLLMENT, $binding);
                $granted = $still === null ? null : $this->enrollments->granted($hash, $binding, $still, $factors);

                if ($still === null || $granted === null) {
                    return false;
                }

                [$enrollment, $factor] = $granted;

                $this->enrollments->discard($enrollment, $factor);

                $context = $this->events->context($still->identity, $binding->application, $still->client, $binding->sessionId);

                $this->events->dispatch(new EnrollmentAbandoned($context, FactorSummary::fromFactor($factor)));

                return true;
            },
        );
    }

    /**
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $served
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $hash
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private function resendUnderLock(Caller $served, ProofBinding $binding, string $hash, Collection $factors): SendResult
    {
        $caller  = $this->callers->still($served, PendingAction::START_BOOTSTRAP_ENROLLMENT, $binding);
        $granted = $caller === null ? null : $this->enrollments->granted($hash, $binding, $caller, $factors);

        return $caller === null || $granted === null
            ? SendResult::refused(FailureReason::NOT_FOUND)
            : $this->sendAgain($caller, $binding, $granted[0], $granted[1]);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Mfa\Models\Enrollment  $enrollment
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     *
     * @throws \Throwable
     */
    private function sendAgain(Caller $caller, ProofBinding $binding, Enrollment $enrollment, EloquentFactor&Model $factor): SendResult
    {
        if (!$this->container->make(DriverResolver::class)->fromContainer($this->container, $factor->getType()) instanceof CodeDeliveryDriver) {
            return SendResult::refused(FailureReason::NOT_FOUND);
        }

        $admission = $this->container->make(ChallengeCounters::class)->underLock($caller->context(), $factor, $binding);

        if (!$admission->isAdmitted()) {
            return SendResult::refusedBy($admission);
        }

        $result      = $this->container->make(ChallengeGateway::class)->send($caller->context(), $factor, $binding);
        $challengeId = $result->challengeId;

        if ($challengeId !== null) {
            $this->enrollments->recordChallenge($enrollment, $challengeId);

            $context = $this->events->context($caller->identity, $binding->application, $caller->client, $binding->sessionId);

            $this->events->dispatch(new CodeSent($context, FactorSummary::fromFactor($factor), Purpose::ENROLLMENT, $challengeId));
        }

        return $result;
    }
}
