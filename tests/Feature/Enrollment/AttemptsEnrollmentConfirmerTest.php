<?php

declare(strict_types = 1);

namespace Tests\Feature\Enrollment;

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
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Events\EnrollmentAbandoned;
use SineMacula\Laravel\Mfa\Exceptions\CodeNotSentException;
use SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException;
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
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\TestCase;

/**
 * An enrolment has an attempt cap of its own: a wrong or replayed code counts
 * against it and at the cap abandons the pending factor, and neither touches
 * the failure counts of the factor or the identity.
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
     * Arrange the application.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
    }

    /**
     * A wrong code counts on the row, keeps the address's slot, charges neither
     * the factor nor the identity, and leaves the enrolment open.
     *
     * @return void
     */
    public function testAWrongCodeCountsAgainstTheEnrollmentOnly(): void
    {
        $user  = $this->reauthenticatedPerson();
        $start = $this->startedTotp();

        $confirmation = $this->mfa()->confirmEnrollment($this->grantOf($start), $this->wrongCode($start));

        self::assertSame(FailureReason::INVALID_CODE, $confirmation->reason);
        self::assertFalse($confirmation->abandoned);
        self::assertSame(1, $this->rowOf($start)->attempts);
        self::assertSame(1, $this->addressHits('127.0.0.1'));
        self::assertSame(0, $this->factorRun($this->pendingFactorOf($start)));
        self::assertSame(0, $this->identityRun($user));
    }

    /**
     * A replayed code counts too.
     *
     * @return void
     */
    public function testAReplayedCodeCounts(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedTotp();
        $code  = $this->appCode($start);

        $this->pendingFactorOf($start)->storeAcceptedStep((int) (now()->getTimestamp() / 30));

        self::assertSame(FailureReason::REPLAYED, $this->mfa()->confirmEnrollment($this->grantOf($start), $code)->reason);
        self::assertSame(1, $this->rowOf($start)->attempts);
        self::assertSame(1, $this->addressHits('127.0.0.1'));
    }

    /**
     * At the cap the factor and row are gone, the event says so, and it commits;
     * below the cap neither is.
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

        self::assertFalse($this->mfa()->confirmEnrollment($grant, $wrong)->abandoned);
        self::assertSame(1, Factor::query()->count());

        $last = $this->mfa()->confirmEnrollment($grant, $wrong);

        self::assertTrue($last->abandoned);
        self::assertSame(FailureReason::INVALID_CODE, $last->reason);
        self::assertSame(0, Factor::query()->count());
        self::assertSame(0, Enrollment::query()->count());
        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->confirmEnrollment($grant, $wrong)->reason);
        self::assertCount(1, array_filter($this->reported, static fn (object $event): bool => $event instanceof EnrollmentAbandoned));
    }

    /**
     * The default cap is five, and a resend does not reset the count.
     *
     * @return void
     */
    public function testTheDefaultCapIsFiveAndCountsSurviveAResend(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedTotp();
        $wrong = $this->wrongCode($start);
        $grant = $this->grantOf($start);

        for ($attempt = 1; $attempt < 5; $attempt++) {
            self::assertFalse($this->mfa()->confirmEnrollment($grant, $wrong)->abandoned);
        }

        self::assertSame(4, $this->rowOf($start)->attempts);

        $this->mfa()->resendEnrollmentCode($grant);

        self::assertSame(4, $this->rowOf($start)->attempts);
        self::assertTrue($this->mfa()->confirmEnrollment($grant, $wrong)->abandoned);
    }

    /**
     * A model event that cancels deleting the pending factor keeps the
     * enrolment, and the failure propagates.
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
            $this->mfa()->confirmEnrollment($this->grantOf($start), $wrong);

            self::fail('A cancelled deletion was expected to propagate.');
        } catch (WriteCancelledException) {
            self::assertSame(1, Enrollment::query()->count());
            self::assertSame(0, $this->addressHits('127.0.0.1'));
        }
    }

    /**
     * The address's throttle refuses a confirmation, reported once, counting
     * nothing.
     *
     * @return void
     */
    public function testTheAddressThrottleRefusesAConfirmation(): void
    {
        config()->set('mfa.attempts.ip_limit', 1);

        $this->reauthenticatedPerson();

        $start = $this->startedTotp();

        $this->mfa()->confirmEnrollment($this->grantOf($start), $this->wrongCode($start));
        $this->forgetReports();

        $confirmation = $this->mfa()->confirmEnrollment($this->grantOf($start), $this->appCode($start));

        self::assertSame(FailureReason::LOCKED, $confirmation->reason);
        self::assertNotNull($confirmation->lockedUntil);
        self::assertSame(FailureReason::LOCKED, $this->failureReported()->reason);
        self::assertNull($this->failureReported()->factor);
        self::assertSame(1, $this->rowOf($start)->attempts);
    }
}
