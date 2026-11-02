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
use SineMacula\Laravel\Mfa\Attempts\RequestIp;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Context\Caller;
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
 * The one way a factor is enrolled: started, then confirmed with a first valid
 * code (see `EnrollmentStarter` and `EnrollmentConfirmer`); its code sent again
 * meanwhile, or the enrolment cancelled. A passkey is the exception: it becomes
 * a factor through its association, which the passkey change gate makes from
 * its registration.
 *
 * Refusals are results with a reason, since `not_fresh` is an ordinary path; a
 * request serving nobody answers `not_found`. Storage failures and delivery
 * exceptions propagate, with their rollback, and a pending credential that does
 * not validate still throws through the bound resolver.
 *
 * Stateless: the seams and the configuration are read on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EnrollmentService
{
    /**
     * Constructor.
     *
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

        /** The container the seams are resolved from. */
        private Container $container,

        /** The configuration the factor model is read from. */
        private Repository $config,

        /** The resolver of who the request serves. */
        private CallerContextResolver $callers,

        /** The throttle on the address. */
        private AttemptService $attempts,

        /** The enrolments in progress. */
        private PendingEnrollments $enrollments,

        /** The start of an enrolment. */
        private EnrollmentStarter $starter,

        /** The confirmation of an enrolment. */
        private EnrollmentConfirmer $confirmer,

        /** The dispatcher of the events. */
        private EventDispatcher $events,
    ) {}

    /**
     * Start an enrolment for the person the request serves.
     *
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest  $request
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart
     *
     * @throws \Throwable
     */
    public function start(#[\SensitiveParameter] EnrollmentRequest $request): EnrollmentStart
    {
        return $this->starter->start($request);
    }

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
        return $this->confirmer->confirm($grant, $code);
    }

    /**
     * Send the enrolment's code again, through the delivered-code cooldown and
     * caps. Nothing is renewed: not the grant's expiry and not its attempts.
     *
     * @param  \SineMacula\Laravel\Mfa\Secrets\RevealedSecret|string  $grant
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     *
     * @throws \Throwable
     */
    public function resend(#[\SensitiveParameter] RevealedSecret|string $grant): SendResult
    {
        $caller  = $this->callers->resolve(PendingAction::START_BOOTSTRAP_ENROLLMENT);
        $binding = $caller === null ? null : $this->callers->binding($caller, Purpose::ENROLLMENT);

        if ($caller === null || $binding === null) {
            return SendResult::refused(FailureReason::NOT_FOUND);
        }

        $result  = SendResult::refused(FailureReason::NOT_FOUND);
        $hash    = EnrollmentGrant::hash($grant);
        $outcome = $this->attempts->throttled(
            RequestIp::resolve($this->container),
            function () use ($caller, $binding, $hash, &$result): AttemptOutcome {

                $result = FactorStateTransaction::forIdentity(
                    $caller->identity,
                    new (ConfiguredModels::factor($this->config)),
                    fn (Collection $factors): SendResult => $this->resendUnderLock($binding, $hash, $factors),
                );

                return AttemptOutcome::uncounted();
            },
        );

        return $outcome->lockout === null ? $result : SendResult::refusedBy(ChallengeAdmission::locked($outcome->lockout));
    }

    /**
     * Cancel the enrolment the grant holds, deleting its pending factor:
     * `false` for a grant that is not the caller's. It needs no step-up, and
     * works during a lockout, since it only gives something up.
     *
     * @param  \SineMacula\Laravel\Mfa\Secrets\RevealedSecret|string  $grant
     * @return bool
     *
     * @throws \Throwable
     *
     * @imperative
     */
    public function cancel(#[\SensitiveParameter] RevealedSecret|string $grant): bool
    {
        $caller  = $this->callers->resolve(PendingAction::START_BOOTSTRAP_ENROLLMENT);
        $binding = $caller === null ? null : $this->callers->binding($caller, Purpose::ENROLLMENT);

        if ($caller === null || $binding === null) {
            return false;
        }

        $hash = EnrollmentGrant::hash($grant);

        return FactorStateTransaction::forIdentity(
            $caller->identity,
            new (ConfiguredModels::factor($this->config)),
            function (Collection $factors) use ($caller, $binding, $hash): bool {

                $granted = $this->enrollments->granted($hash, $binding, $caller, $factors);

                if ($granted === null) {
                    return false;
                }

                [$enrollment, $factor] = $granted;

                $this->enrollments->discard($enrollment, $factor);

                $this->events->dispatch(new EnrollmentAbandoned($this->events->context($caller->identity, $binding->application), FactorSummary::fromFactor($factor)));

                return true;
            },
        );
    }

    /**
     * Under the lock: refuse a sign-in that changed and a grant that is not the
     * caller's, then send the code again.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $hash
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private function resendUnderLock(ProofBinding $binding, string $hash, Collection $factors): SendResult
    {
        $caller  = $this->callers->still(PendingAction::START_BOOTSTRAP_ENROLLMENT, $binding);
        $granted = $caller === null ? null : $this->enrollments->granted($hash, $binding, $caller, $factors);

        return $caller === null || $granted === null
            ? SendResult::refused(FailureReason::NOT_FOUND)
            : $this->sendAgain($caller, $binding, $granted[0], $granted[1]);
    }

    /**
     * Admit the pending factor, which reads the grant's expiry, its generation,
     * the type and the lockout again, send the code, and record the challenge
     * once it has gone. A type that delivers no codes has none to send.
     *
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

        $admission = $this->container->make(ChallengeCounters::class)->underLock($caller->identity, $factor, $binding);

        if (!$admission->isAdmitted()) {
            return SendResult::refusedBy($admission);
        }

        $result      = $this->container->make(ChallengeGateway::class)->send($factor, $binding);
        $challengeId = $result->challengeId;

        if ($challengeId !== null) {
            $this->enrollments->recordChallenge($enrollment, $challengeId);

            $context = $this->events->context($caller->identity, $binding->application);

            $this->events->dispatch(new CodeSent($context, FactorSummary::fromFactor($factor), Purpose::ENROLLMENT, $challengeId));
        }

        return $result;
    }
}
