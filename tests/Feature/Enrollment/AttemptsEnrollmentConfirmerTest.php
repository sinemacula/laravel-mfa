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
use SineMacula\Laravel\Mfa\Enums\AbandonmentCause;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Events\EnrollmentAbandoned;
use SineMacula\Laravel\Mfa\Exceptions\CodeNotSentException;
use SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException;
use SineMacula\Laravel\Mfa\Factors\FactorChannel;
use SineMacula\Laravel\Mfa\Factors\FactorLabel;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeIssuance;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\ReenrollmentObligation;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use SineMacula\Laravel\Mfa\Requirements\SessionReevaluation;
use SineMacula\Laravel\Mfa\Verification\ProofAcceptance;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\TestCase;

/**
 * An enrolment's own attempt cap: wrong or replayed codes count against it and
 * abandon the pending factor at the cap, leaving factor and identity failure
 * counts alone.
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
final class AttemptsEnrollmentConfirmerTest extends TestCase
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
     * It keeps the address's slot, charges neither the factor nor the identity,
     * and leaves the enrolment open.
     *
     * @return void
     */
    public function testAWrongCodeCountsAgainstTheEnrollmentOnly(): void
    {
        $user  = $this->reauthenticatedPerson();
        $start = $this->startedTotp();

        $confirmation = $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $this->wrongCode($start));

        self::assertSame(FailureReason::INVALID_CODE, $confirmation->reason);
        self::assertFalse($confirmation->abandoned);
        self::assertSame(1, $this->rowOf($start)->attempts);
        self::assertSame(1, $this->addressHits('127.0.0.1'));
        self::assertSame(0, $this->factorRun($this->pendingFactorOf($start)));
        self::assertSame(0, $this->identityRun($user));
    }

    /**
     * @return void
     */
    public function testAReplayedCodeCounts(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedTotp();
        $code  = $this->appCode($start);

        $this->pendingFactorOf($start)->storeAcceptedStep((int) (now()->getTimestamp() / 30));

        self::assertSame(FailureReason::REPLAYED, $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $code)->reason);
        self::assertSame(1, $this->rowOf($start)->attempts);
        self::assertSame(1, $this->addressHits('127.0.0.1'));
    }

    /**
     * The event says so and it commits; below the cap neither goes.
     *
     * @return void
     */
    public function testTheCapAbandonsThePendingFactor(): void
    {
        config()->set('mfa.enrollment.max_attempts', 2);

        $this->reauthenticatedPerson();

        $start = $this->startedTotp();
        $wrong = $this->wrongCode($start);
        $grant = $this->grantOf($start);

        self::assertFalse($this->mfa()->confirmEnrollment(Callers::current(), $grant, $wrong)->abandoned);
        self::assertSame(1, Factor::query()->count());
        self::assertSame(1, $this->addressHits('127.0.0.1'));

        $last = $this->mfa()->confirmEnrollment(Callers::current(), $grant, $wrong);

        self::assertTrue($last->abandoned);
        self::assertSame(2, $this->addressHits('127.0.0.1'));
        self::assertSame(FailureReason::INVALID_CODE, $last->reason);
        self::assertSame(0, Factor::query()->count());
        self::assertSame(0, Enrollment::query()->count());
        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->confirmEnrollment(Callers::current(), $grant, $wrong)->reason);
        self::assertSame(AbandonmentCause::ATTEMPTS_EXHAUSTED, $this->abandonment()->cause);
    }

    /**
     * @return void
     */
    public function testTheDefaultCapIsFiveAndCountsSurviveAResend(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedTotp();
        $wrong = $this->wrongCode($start);
        $grant = $this->grantOf($start);

        for ($attempt = 1; $attempt < 5; $attempt++) {
            self::assertFalse($this->mfa()->confirmEnrollment(Callers::current(), $grant, $wrong)->abandoned);
        }

        self::assertSame(4, $this->rowOf($start)->attempts);

        $this->mfa()->resendEnrollmentCode(Callers::current(), $grant);

        self::assertSame(4, $this->rowOf($start)->attempts);
        self::assertTrue($this->mfa()->confirmEnrollment(Callers::current(), $grant, $wrong)->abandoned);
    }

    /**
     * @return void
     */
    public function testARestartStartsAFreshCount(): void
    {
        config()->set('mfa.enrollment.max_attempts', 2);

        $this->reauthenticatedPerson();

        $first = $this->startedTotp();

        self::assertSame(FailureReason::INVALID_CODE, $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($first), $this->wrongCode($first))->reason);
        self::assertSame(1, $this->rowOf($first)->attempts);

        $second = $this->startedTotp();

        self::assertSame(0, $this->rowOf($second)->attempts);
        self::assertFalse($this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($second), $this->wrongCode($second))->abandoned);
        self::assertSame(1, $this->rowOf($second)->attempts);
    }

    /**
     * Charging neither the factor nor the identity.
     *
     * @return void
     */
    public function testWrongDeliveredCodesAbandonAtTheCap(): void
    {
        $user  = $this->reauthenticatedPerson();
        $start = $this->startedEmail();
        $grant = $this->grantOf($start);
        $wrong = $this->wrongEmailCode();

        for ($attempt = 1; $attempt < 5; $attempt++) {
            $confirmation = $this->mfa()->confirmEnrollment(Callers::current(), $grant, $wrong);

            self::assertSame(FailureReason::INVALID_CODE, $confirmation->reason);
            self::assertFalse($confirmation->abandoned);
            self::assertSame($attempt, $this->rowOf($start)->attempts);
        }

        self::assertSame(0, $this->factorRun($this->pendingFactorOf($start)));

        $last = $this->mfa()->confirmEnrollment(Callers::current(), $grant, $wrong);

        self::assertTrue($last->abandoned);
        self::assertSame(FailureReason::INVALID_CODE, $last->reason);
        self::assertSame(0, Factor::query()->count());
        self::assertSame(0, Enrollment::query()->count());
        self::assertSame(0, $this->identityRun($user));
        self::assertSame(AbandonmentCause::ATTEMPTS_EXHAUSTED, $this->abandonment()->cause);
        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->confirmEnrollment(Callers::current(), $grant, $wrong)->reason);
    }

    /**
     * It answers expired; no code is sent until the challenge ends, then a
     * resend opens another and the count carries on.
     *
     * @return void
     */
    public function testAnExhaustedChallengeCountsNothing(): void
    {
        config()->set('mfa.codes.max_attempts', 2);
        config()->set('mfa.codes.ttl_minutes', 2);
        config()->set('mfa.codes.challenge_ttl_minutes', 2);

        $user  = $this->reauthenticatedPerson();
        $start = $this->startedEmail();
        $grant = $this->grantOf($start);

        $this->mfa()->confirmEnrollment(Callers::current(), $grant, $this->wrongEmailCode());
        $this->mfa()->confirmEnrollment(Callers::current(), $grant, $this->wrongEmailCode());

        $exhausted = $this->mfa()->confirmEnrollment(Callers::current(), $grant, $this->wrongEmailCode());

        self::assertSame(FailureReason::EXPIRED, $exhausted->reason);
        self::assertFalse($exhausted->abandoned);
        self::assertSame(2, $this->rowOf($start)->attempts);
        self::assertSame(2, $this->addressHits('127.0.0.1'));

        Carbon::setTestNow(CarbonImmutable::now()->addSeconds(61));

        self::assertSame(FailureReason::SENDING_CAPPED, $this->mfa()->resendEnrollmentCode(Callers::current(), $grant)->reason);
        self::assertCount(1, $this->mailbox->sentTo(self::ADDRESS));

        Carbon::setTestNow(CarbonImmutable::now()->addSeconds(60));

        self::assertTrue($this->mfa()->resendEnrollmentCode(Callers::current(), $grant)->wasSent());

        $this->mfa()->confirmEnrollment(Callers::current(), $grant, $this->wrongEmailCode());

        self::assertFalse($this->mfa()->confirmEnrollment(Callers::current(), $grant, $this->wrongEmailCode())->abandoned);
        self::assertSame(4, $this->rowOf($start)->attempts);

        Carbon::setTestNow(CarbonImmutable::now()->addMinutes(2));

        self::assertTrue($this->mfa()->resendEnrollmentCode(Callers::current(), $grant)->wasSent());
        self::assertTrue($this->mfa()->confirmEnrollment(Callers::current(), $grant, $this->wrongEmailCode())->abandoned);
        self::assertSame(AbandonmentCause::ATTEMPTS_EXHAUSTED, $this->abandonment()->cause);
        self::assertSame(0, $this->identityRun($user));
    }

    /**
     * The enrolment is kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACanceledDeletionPropagates(): void
    {
        config()->set('mfa.enrollment.max_attempts', 1);

        $this->reauthenticatedPerson();

        $start = $this->startedTotp();
        $wrong = $this->wrongCode($start);

        Factor::deleting(static fn (): bool => false);

        try {
            $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $wrong);

            self::fail('A cancelled deletion was expected to propagate.');
        } catch (WriteCanceledException) {
            self::assertSame(1, Enrollment::query()->count());
            self::assertSame(0, $this->addressHits('127.0.0.1'));
        }
    }

    /**
     * Reported once, counting nothing.
     *
     * @return void
     */
    public function testTheAddressThrottleRefusesAConfirmation(): void
    {
        config()->set('mfa.attempts.ip_limit', 1);

        $this->reauthenticatedPerson();

        $start = $this->startedTotp();

        $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $this->wrongCode($start));
        $this->forgetReports();

        $confirmation = $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $this->appCode($start));

        self::assertSame(FailureReason::LOCKED, $confirmation->reason);
        self::assertNotNull($confirmation->lockedUntil);
        self::assertSame(FailureReason::LOCKED, $this->failureReported()->reason);
        self::assertNull($this->failureReported()->factor);
        self::assertSame(1, $this->rowOf($start)->attempts);
    }

    /**
     * Fails the test unless exactly one abandonment was reported.
     *
     * @return \SineMacula\Laravel\Mfa\Events\EnrollmentAbandoned
     */
    private function abandonment(): EnrollmentAbandoned
    {
        $abandoned = array_values(array_filter($this->reported, static fn (object $event): bool => $event instanceof EnrollmentAbandoned));

        self::assertCount(1, $abandoned);

        return $abandoned[0];
    }

    /**
     * @return string
     */
    private function wrongEmailCode(): string
    {
        return $this->mailbox->lastCodeTo(self::ADDRESS) === '000000' ? '111111' : '000000';
    }
}
