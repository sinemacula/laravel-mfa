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
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Exceptions\CodeNotSentException;
use SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException;
use SineMacula\Laravel\Mfa\Factors\FactorChannel;
use SineMacula\Laravel\Mfa\Factors\FactorLabel;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
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
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * A cancelled write the enrolment needs fails closed: it propagates, rolls
 * back, and nothing is reported or issued.
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
final class CanceledWriteEnrollmentConfirmerTest extends TestCase
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
     * The grant, obligation and TOTP step stay, and nothing is issued or
     * reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACanceledFactorSaveRollsTheConfirmationBack(): void
    {
        $user  = $this->reauthenticatedPerson();
        $start = $this->arrangedConfirmation($user);
        $code  = $this->appCode($start);

        Factor::saving(static fn (): bool => false);

        $this->assertConfirmationCanceled($user, $start, $code);
    }

    /**
     * A cancelled row deletion would leave a used grant usable.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACanceledRowDeletionRollsTheConfirmationBack(): void
    {
        $user  = $this->reauthenticatedPerson();
        $start = $this->arrangedConfirmation($user);
        $code  = $this->appCode($start);

        Enrollment::deleting(static fn (): bool => false);

        $this->assertConfirmationCanceled($user, $start, $code);
    }

    /**
     * It is not taken for a counted failure.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACanceledCountPropagates(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedTotp();
        $wrong = $this->wrongCode($start);

        Enrollment::updating(static fn (): bool => false);

        try {
            $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $wrong);

            self::fail('A cancelled count was expected to propagate.');
        } catch (WriteCanceledException) {
            self::assertSame(0, Enrollment::query()->sole()->attempts);
            self::assertSame(0, $this->addressHits('127.0.0.1'));
        }
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testACanceledRowSaveStopsTheStart(): void
    {
        $this->reauthenticatedPerson();

        Enrollment::creating(static fn (): bool => false);

        try {
            $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT));

            self::fail('A cancelled save was expected to propagate.');
        } catch (WriteCanceledException) {
            self::assertSame(0, Factor::query()->count());
            self::assertSame(0, Enrollment::query()->count());
        }
    }

    /**
     * The code could never be confirmed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACanceledChallengeRecordRollsTheStartBack(): void
    {
        $this->reauthenticatedPerson();

        Enrollment::updating(static fn (): bool => false);

        try {
            $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::delivered('email', self::ADDRESS));

            self::fail('A cancelled record was expected to propagate.');
        } catch (WriteCanceledException) {
            self::assertSame(0, Factor::query()->count());
            self::assertSame(0, Enrollment::query()->count());
            self::assertSame(0, Code::query()->count());
        }
    }

    /**
     * Once the first challenge has ended.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACanceledChallengeRecordRollsTheResendBack(): void
    {
        config()->set('mfa.codes.ttl_minutes', 1);
        config()->set('mfa.codes.challenge_ttl_minutes', 1);

        $this->reauthenticatedPerson();

        $start = $this->startedEmail();
        $grant = $this->grantOf($start);

        Carbon::setTestNow(CarbonImmutable::now()->addSeconds(61));
        Enrollment::updating(static fn (): bool => false);

        try {
            $this->mfa()->resendEnrollmentCode(Callers::current(), $grant);

            self::fail('A cancelled record was expected to propagate.');
        } catch (WriteCanceledException) {
            self::assertSame(1, Code::query()->sole()->sends);
        }
    }

    /**
     * Of a row with no factor left.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACanceledDeletionOfAnOrphanStopsTheRestart(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedTotp();

        Factor::query()->whereKey($start->factor?->id)->delete();
        Enrollment::deleting(static fn (): bool => false);

        try {
            $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp(self::ACCOUNT));

            self::fail('A cancelled deletion was expected to propagate.');
        } catch (WriteCanceledException) {
            self::assertSame(1, Enrollment::query()->count());
            self::assertSame(0, Factor::query()->count());
        }
    }

    /**
     * It is never reported as made.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACanceledSaveStopsARename(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user, ['application' => self::APPLICATION, 'label' => 'Old']);

        $this->forgetReports();

        Factor::saving(static fn (): bool => false);

        try {
            $this->mfa()->renameFactor(Callers::current(), $factor->id, 'New');

            self::fail('A cancelled save was expected to propagate.');
        } catch (WriteCanceledException) {
            self::assertSame('Old', Factor::query()->sole()->getLabel());
            self::assertSame([], $this->reported);
        }
    }

    /**
     * For a person obliged to enrol, with nothing yet reported.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart
     */
    private function arrangedConfirmation(TestUser $user): EnrollmentStart
    {
        $this->obligeToEnroll($user);

        $start = $this->startedTotp();

        $this->forgetReports();

        return $start;
    }

    /**
     * Confirming propagates the cancellation and changes nothing.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart  $start
     * @param  string  $code
     * @return void
     *
     * @throws \Throwable
     */
    private function assertConfirmationCanceled(TestUser $user, EnrollmentStart $start, string $code): void
    {
        $grant = $this->grantOf($start);

        try {
            $this->mfa()->confirmEnrollment(Callers::current(), $grant, $code);

            self::fail('A cancelled write was expected to propagate.');
        } catch (WriteCanceledException) {
            $factor = $this->pendingFactorOf($start);

            self::assertSame(FactorStatus::PENDING, $factor->getStatus());
            self::assertNull($factor->getLastAcceptedStep());
            self::assertTrue($this->rowOf($start)->exists);
            self::assertTrue(ReenrollmentObligation::isRequired($user));
            self::assertSame(0, RecoveryCode::query()->count());
            self::assertSame([], $this->reported);
        }
    }
}
