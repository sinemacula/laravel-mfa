<?php

declare(strict_types = 1);

namespace Tests\Feature\Enrollment;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Assurance\Combination;
use SineMacula\Laravel\Mfa\Assurance\DefaultCombinationPolicy;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpSettings;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentAuthority;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmer;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentGrant;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentService;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentSettings;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentStarter;
use SineMacula\Laravel\Mfa\Enrollment\GrantAuthority;
use SineMacula\Laravel\Mfa\Enrollment\PendingEnrollments;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\CodeSent;
use SineMacula\Laravel\Mfa\Events\EnrollmentAbandoned;
use SineMacula\Laravel\Mfa\Exceptions\CodeNotSentException;
use SineMacula\Laravel\Mfa\Factors\FactorChannel;
use SineMacula\Laravel\Mfa\Factors\FactorLabel;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeIssuance;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\ReenrollmentObligation;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use SineMacula\Laravel\Mfa\Requirements\SessionReevaluation;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use SineMacula\Laravel\Mfa\Verification\ProofAcceptance;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Seams\AcceptingChallengeGateway;
use Tests\Fixtures\Seams\InterruptingProofStore;
use Tests\TestCase;

/**
 * Resends go through the delivered-code cooldown and caps, renewing nothing;
 * cancelling needs no step-up and works during a lockout.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnrollmentService::class)]
#[CoversClass(EnrollmentStarter::class)]
#[CoversClass(EnrollmentConfirmer::class)]
#[CoversClass(PendingEnrollments::class)]
#[CoversClass(EnrollmentAuthority::class)]
#[CoversClass(GrantAuthority::class)]
#[CoversClass(EnrollmentGrant::class)]
#[CoversClass(EnrollmentRequest::class)]
#[CoversClass(EnrollmentStart::class)]
#[CoversClass(EnrollmentConfirmation::class)]
#[CoversClass(EnrollmentSettings::class)]
#[CoversClass(FactorChannel::class)]
#[CoversClass(FactorLabel::class)]
#[CoversClass(ChallengeCounters::class)]
#[CoversClass(PackageChallengeGateway::class)]
#[CoversClass(CodeNotSentException::class)]
#[CoversClass(ProofAcceptance::class)]
#[CoversClass(ProofStoreCompletion::class)]
#[CoversClass(RecoveryCodeIssuance::class)]
#[CoversClass(RecoveryCodeService::class)]
#[CoversClass(ReenrollmentObligation::class)]
#[CoversClass(SessionReevaluation::class)]
#[CoversClass(ConfiguredFreshnessGate::class)]
#[CoversClass(RequirementService::class)]
#[CoversClass(TotpDriver::class)]
#[CoversClass(TotpSettings::class)]
#[CoversClass(EmailDriver::class)]
#[CoversClass(SmsDriver::class)]
#[CoversClass(MfaManager::class)]
#[CoversClass(Evaluation::class)]
#[CoversClass(Combination::class)]
#[CoversClass(DefaultCombinationPolicy::class)]
final class ResendAndCancelEnrollmentServiceTest extends TestCase
{
    use ArrangesEnrollment;

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
    }

    /**
     * It reports it and records its challenge.
     *
     * @return void
     */
    public function testAResendSendsAnotherCode(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedEmail();
        $first = $this->mailbox->lastCodeTo(self::ADDRESS);

        Carbon::setTestNow(CarbonImmutable::now()->addSeconds(61));

        $this->forgetReports();

        $result = $this->mfa()->resendEnrollmentCode(Callers::current(), $this->grantOf($start));

        self::assertTrue($result->wasSent());
        self::assertSame(['CodeSent'], $this->reportedNames());
        self::assertInstanceOf(CodeSent::class, $this->reported[0]);
        self::assertSame(Purpose::ENROLLMENT, $this->reported[0]->purpose);
        self::assertSame($result->challengeId, $this->reported[0]->challengeId);
        self::assertSame($start->factor?->id, $this->reported[0]->factor->id);
        self::assertSame($result->challengeId, $this->rowOf($start)->challenge_id);
        self::assertNotSame($first, $this->mailbox->lastCodeTo(self::ADDRESS));
    }

    /**
     * That is the one the code answers.
     *
     * @return void
     */
    public function testAResendRecordsANewChallenge(): void
    {
        config()->set('mfa.enrollment.ttl_minutes', 60);
        config()->set('mfa.codes.challenge_ttl_minutes', 10);

        $this->enableApplication(['freshness' => ['mfa.add_factor' => 7200]]);
        $this->steppedUpPerson();

        $start = $this->startedEmail();
        $first = $this->rowOf($start)->challenge_id;

        Carbon::setTestNow(CarbonImmutable::now()->addMinutes(11));

        $result = $this->mfa()->resendEnrollmentCode(Callers::current(), $this->grantOf($start));

        self::assertNotSame($first, $result->challengeId);
        self::assertSame($result->challengeId, $this->rowOf($start)->challenge_id);
        self::assertTrue($this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), (string) $this->mailbox->lastCodeTo(self::ADDRESS))->isConfirmed());
    }

    /**
     * It keeps the challenge and reports nothing.
     *
     * @return void
     */
    public function testAResendInTheCooldownIsCapped(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedEmail();
        $first = $this->rowOf($start)->challenge_id;

        $this->forgetReports();

        $result = $this->mfa()->resendEnrollmentCode(Callers::current(), new RevealedSecret($this->grantOf($start)));

        self::assertSame(FailureReason::SENDING_CAPPED, $result->reason);
        self::assertNotNull($result->retryAfter);
        self::assertSame([], $this->reported);
        self::assertSame($first, $this->rowOf($start)->challenge_id);
    }

    /**
     * Each with what it said, leaving the enrolment.
     *
     * @return void
     */
    public function testAResendIsRefusedWhatItMayNotDo(): void
    {
        $user  = $this->reauthenticatedPerson();
        $start = $this->startedEmail();
        $grant = $this->grantOf($start);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->resendEnrollmentCode(Callers::current(), 'unknown')->reason);

        $this->lock($user);

        Carbon::setTestNow(CarbonImmutable::now()->addSeconds(61));

        $locked = $this->mfa()->resendEnrollmentCode(Callers::current(), $grant);

        self::assertSame(FailureReason::LOCKED, $locked->reason);
        self::assertSame(239, $locked->retryAfter);

        $this->unlock($user);

        $this->enableApplication(['types' => ['totp']]);

        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->mfa()->resendEnrollmentCode(Callers::current(), $grant)->reason);

        $this->enableApplication();

        Carbon::setTestNow(CarbonImmutable::now()->addHour());

        self::assertSame(FailureReason::EXPIRED, $this->mfa()->resendEnrollmentCode(Callers::current(), $grant)->reason);
        self::assertTrue($this->rowOf($start)->exists);
    }

    /**
     * The admission is the package's own, whichever gateway is bound.
     *
     * @return void
     */
    public function testABoundGatewayIsNotAskedWhatTheAdmissionRefuses(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedEmail();

        Carbon::setTestNow(CarbonImmutable::now()->addHour());

        $this->container()->instance(ChallengeGateway::class, new AcceptingChallengeGateway);

        self::assertSame(FailureReason::EXPIRED, $this->mfa()->resendEnrollmentCode(Callers::current(), $this->grantOf($start))->reason);
    }

    /**
     * @return void
     */
    public function testATotpEnrollmentHasNoCodeToSend(): void
    {
        $this->reauthenticatedPerson();

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->resendEnrollmentCode(Callers::current(), $this->grantOf($this->startedTotp()))->reason);
        self::assertSame([], $this->mailbox->sent());
    }

    /**
     * The start action on a pending session; `not_found` with nobody served or
     * the sign-in changed.
     *
     * @return void
     */
    public function testAResendNeedsItsCaller(): void
    {
        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->resendEnrollmentCode(Callers::current(), 'any')->reason);

        $this->actingAs($this->person('other@example.test'));

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->resendEnrollmentCode(Callers::current(), 'any')->reason);

        $user  = $this->bootstrapPerson();
        $start = $this->startedEmail();

        Carbon::setTestNow(CarbonImmutable::now()->addSeconds(61));

        $this->pendingSession($user, null, [PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT, PendingAction::SEND_CODE]);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->resendEnrollmentCode(Callers::current(), $this->grantOf($start))->reason);

        $this->pendingSession($user, null, self::BOOTSTRAP_ACTIONS);

        self::assertTrue($this->mfa()->resendEnrollmentCode(Callers::current(), $this->grantOf($start))->wasSent());

        Carbon::setTestNow(CarbonImmutable::now()->addSeconds(61));

        $this->container()->instance(ProofStore::class, new InterruptingProofStore($this->container()->make(ProofStore::class), 0));
        $this->pendingSession($user, null, self::BOOTSTRAP_ACTIONS, session: 'pending-b');

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->resendEnrollmentCode(Callers::current(), $this->grantOf($start))->reason);
    }

    /**
     * Between capture and lock.
     *
     * @return void
     */
    public function testASignInChangedBeforeTheLockSendsNothing(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedEmail();

        Carbon::setTestNow(CarbonImmutable::now()->addSeconds(61));

        $this->mailbox->reset();

        $this->container()->instance(ProofStore::class, new InterruptingProofStore($this->container()->make(ProofStore::class)));

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->resendEnrollmentCode(Callers::current(), $this->grantOf($start))->reason);
        self::assertSame([], $this->mailbox->sent());
    }

    /**
     * With how long to wait.
     *
     * @return void
     */
    public function testTheAddressThrottleRefusesAResend(): void
    {
        config()->set('mfa.attempts.ip_limit', 1);

        $this->reauthenticatedPerson();

        $start = $this->startedEmail();

        $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), 'wrong');

        $result = $this->mfa()->resendEnrollmentCode(Callers::current(), $this->grantOf($start));

        self::assertSame(FailureReason::LOCKED, $result->reason);
        self::assertNotNull($result->retryAfter);
    }

    /**
     * The factor and the row go, and it is reported.
     *
     * @return void
     */
    public function testCancelingDeletesTheEnrollment(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedTotp();

        $this->forgetReports();

        self::assertTrue($this->mfa()->cancelEnrollment(Callers::current(), $start->grant ?? ''));
        self::assertSame(['EnrollmentAbandoned'], $this->reportedNames());
        self::assertInstanceOf(EnrollmentAbandoned::class, $this->reported[0]);
        self::assertSame($start->factor?->id, $this->reported[0]->factor->id);
        self::assertSame(self::APPLICATION, $this->reported[0]->context()['application']);
        self::assertSame(0, Factor::query()->count());
        self::assertSame(0, Enrollment::query()->count());
        self::assertFalse($this->mfa()->cancelEnrollment(Callers::current(), $start->grant ?? ''));
    }

    /**
     * It answers `false` for anything that does not match or nobody served.
     *
     * @return void
     */
    public function testCancelingWorksDuringALockoutAndOnlyWithItsGrant(): void
    {
        self::assertFalse($this->mfa()->cancelEnrollment(Callers::current(), 'any'));

        $user  = $this->reauthenticatedPerson();
        $start = $this->startedTotp();

        $this->lock($user);

        $this->forgetReports();

        self::assertFalse($this->mfa()->cancelEnrollment(Callers::current(), 'unknown'));
        self::assertSame([], $this->reported);
        self::assertSame(1, Factor::query()->count());
        self::assertTrue($this->mfa()->cancelEnrollment(Callers::current(), $this->grantOf($start)));
    }

    /**
     * On a pending session.
     *
     * @return void
     */
    public function testCancelingNeedsTheStartAction(): void
    {
        $user  = $this->bootstrapPerson();
        $start = $this->startedTotp();

        $this->pendingSession($user, null, [PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT]);

        self::assertFalse($this->mfa()->cancelEnrollment(Callers::current(), $this->grantOf($start)));

        $this->pendingSession($user, null, self::BOOTSTRAP_ACTIONS);

        self::assertTrue($this->mfa()->cancelEnrollment(Callers::current(), $this->grantOf($start)));
    }

    /**
     * The credential is read again under the identity's lock.
     *
     * @return void
     */
    public function testACallerRevokedOnceReadCancelsNothing(): void
    {
        $user  = $this->bootstrapPerson();
        $start = $this->startedTotp();

        $this->pendingSession($user, null, self::BOOTSTRAP_ACTIONS);

        $caller = Callers::current();

        $this->noPendingSession();

        self::assertFalse($this->mfa()->cancelEnrollment($caller, $this->grantOf($start)));

        $this->pendingSession($user, null, self::BOOTSTRAP_ACTIONS);

        self::assertTrue($this->mfa()->cancelEnrollment(Callers::current(), $this->grantOf($start)));
    }

    /**
     * @return void
     */
    public function testAPersonWithNoSignInCancelsNothing(): void
    {
        $this->actingAs($this->person());

        self::assertFalse($this->mfa()->cancelEnrollment(Callers::current(), 'any'));
    }

    /**
     * For five minutes.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return void
     */
    private function lock(TestUser $user): void
    {
        $owner = ProofOwner::of($user);

        IdentityState::query()->updateOrCreate(
            ['authenticatable_type' => $owner->type, 'authenticatable_id' => $owner->key],
            ['locked_until' => CarbonImmutable::now()->addMinutes(5)],
        );
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return void
     */
    private function unlock(TestUser $user): void
    {
        $owner = ProofOwner::of($user);

        IdentityState::query()->where('authenticatable_type', $owner->type)->where('authenticatable_id', $owner->key)->update(['locked_until' => null]);
    }
}
