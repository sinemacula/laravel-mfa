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
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\CodeSent;
use SineMacula\Laravel\Mfa\Events\EnrollmentExpired;
use SineMacula\Laravel\Mfa\Events\VerificationFailed;
use SineMacula\Laravel\Mfa\Events\VerificationPassed;
use SineMacula\Laravel\Mfa\Exceptions\CodeNotSentException;
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
 * The events of each path of an enrolment come in order once it commits, for
 * the application it ran through, and none are left after a rollback.
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
final class EventSequenceEnrollmentServiceTest extends TestCase
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
     * A TOTP start reports it started, and an email one the code it sent.
     *
     * @return void
     */
    public function testAStartReportsItStarted(): void
    {
        $this->steppedUpPerson();

        $this->startedTotp();

        self::assertSame(['EnrollmentStarted'], $this->reportedNames());
        self::assertSame(self::APPLICATION, $this->reported[0]->context()['application']);
        self::assertSame(Purpose::ENROLLMENT, $this->reported[0]->purpose());

        $this->forgetReports();

        $start = $this->startedEmail();

        self::assertSame(['EnrollmentStarted', 'CodeSent'], $this->reportedNames());
        self::assertInstanceOf(CodeSent::class, $this->reported[1]);
        self::assertSame(Purpose::ENROLLMENT, $this->reported[1]->purpose);
        self::assertSame($this->rowOf($start)->challenge_id, $this->reported[1]->challengeId);
        self::assertSame($start->factor?->id, $this->reported[1]->factor->id);
    }

    /**
     * Starting again discards what it replaces first; expired ones of other
     * types go too, and another application's stay.
     *
     * @return void
     */
    public function testAStartReportsWhatItDiscards(): void
    {
        $this->steppedUpPerson();

        $this->startedTotp();
        $email = $this->startedEmail();
        $other = $this->started(EnrollmentRequest::delivered('email', 'other@example.test'));

        self::assertSame(1, Enrollment::query()->where('factor_id', $other->factor?->id)->count());
        self::assertSame(0, Enrollment::query()->where('factor_id', $email->factor?->id)->count());

        $this->forgetReports();

        Enrollment::query()->where('factor_id', $other->factor?->id)->update(['expires_at' => CarbonImmutable::now()->subSecond()]);

        $admin  = $this->started(EnrollmentRequest::totp(self::ACCOUNT));
        $before = Enrollment::query()->count();

        self::assertSame(['EnrollmentAbandoned', 'EnrollmentExpired', 'EnrollmentStarted'], $this->reportedNames());
        self::assertSame(1, $before);
        self::assertSame($admin->factor?->id, Enrollment::query()->sole()->factor_id);
    }

    /**
     * Another application's pending factors stay, expired or not, and a
     * factor's row with nothing left of its factor goes quietly.
     *
     * @return void
     */
    public function testAStartLeavesAnotherApplicationsAlone(): void
    {
        $this->steppedUpPerson();

        $start = $this->startedEmail();

        Enrollment::query()->update(['application' => 'admin', 'expires_at' => CarbonImmutable::now()->subSecond()]);

        $this->forgetReports();
        $this->startedTotp();

        self::assertSame(['EnrollmentStarted'], $this->reportedNames());
        self::assertTrue($this->rowOf($start)->exists);

        Enrollment::query()->where('factor_id', $start->factor?->id)->update(['application' => self::APPLICATION]);
        Factor::query()->whereKey($start->factor?->id)->delete();

        $this->forgetReports();
        $this->startedEmail('second@example.test');

        self::assertSame(0, Enrollment::query()->where('factor_id', $start->factor?->id)->count());
        self::assertSame(['EnrollmentStarted', 'CodeSent'], $this->reportedNames());
    }

    /**
     * A wrong code reports one failure, and the cap adds the abandonment.
     *
     * @return void
     */
    public function testAWrongCodeReportsAFailure(): void
    {
        config()->set('mfa.enrollment.max_attempts', 2);

        $this->reauthenticatedPerson();

        $start = $this->startedTotp();
        $wrong = $this->wrongCode($start);

        $this->forgetReports();
        $this->mfa()->confirmEnrollment($this->grantOf($start), $wrong);

        self::assertSame(['VerificationFailed'], $this->reportedNames());
        self::assertInstanceOf(VerificationFailed::class, $this->reported[0]);
        self::assertSame(Purpose::ENROLLMENT, $this->reported[0]->purpose);
        self::assertSame('totp', $this->reported[0]->type);
        self::assertSame($start->factor?->id, $this->reported[0]->factor?->id);

        $this->forgetReports();
        $this->mfa()->confirmEnrollment($this->grantOf($start), $wrong);

        self::assertSame(['VerificationFailed', 'EnrollmentAbandoned'], $this->reportedNames());
    }

    /**
     * An expired grant reports it expired, then the failure.
     *
     * @return void
     */
    public function testAnExpiredGrantReportsIt(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedTotp();
        $code  = $this->appCode($start);

        $this->forgetReports();

        Carbon::setTestNow(CarbonImmutable::now()->addHour());

        $this->mfa()->confirmEnrollment($this->grantOf($start), $code);

        self::assertSame(['EnrollmentExpired', 'VerificationFailed'], $this->reportedNames());
        self::assertInstanceOf(EnrollmentExpired::class, $this->reported[0]);
        self::assertSame($start->factor?->id, $this->reported[0]->factor->id);
        self::assertSame(0, Factor::query()->count());
    }

    /**
     * A success on an active session reports the pass, the confirmation and the
     * codes generated.
     *
     * @return void
     */
    public function testASuccessReportsItsSequence(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedTotp();
        $code  = $this->appCode($start);

        $this->forgetReports();
        $this->mfa()->confirmEnrollment($this->grantOf($start), $code);

        self::assertSame(['VerificationPassed', 'FactorConfirmed', 'RecoveryCodesGenerated'], $this->reportedNames());
        self::assertInstanceOf(VerificationPassed::class, $this->reported[0]);
        self::assertSame(Purpose::ENROLLMENT, $this->reported[0]->purpose);
        self::assertSame('totp', $this->reported[0]->type);
        self::assertNull($this->reported[0]->challengeId);
        self::assertSame(self::APPLICATION, $this->reported[1]->context()['application']);
    }

    /**
     * A success on the bootstrap path reports its own event as well.
     *
     * @return void
     */
    public function testABootstrapSuccessReportsItsOwnEvent(): void
    {
        $this->bootstrapPerson();

        $start = $this->startedTotp();
        $code  = $this->appCode($start);

        $this->forgetReports();
        $this->mfa()->confirmEnrollment($this->grantOf($start), $code);

        self::assertSame(['VerificationPassed', 'FactorConfirmed', 'BootstrapEnrollmentCompleted', 'RecoveryCodesGenerated'], $this->reportedNames());
    }

    /**
     * A later factor reports no codes.
     *
     * @return void
     */
    public function testALaterFactorReportsNoCodes(): void
    {
        $this->steppedUpPerson();

        $start = $this->startedEmail();
        $code  = (string) $this->mailbox->lastCodeTo(self::ADDRESS);

        $this->forgetReports();
        $this->mfa()->confirmEnrollment($this->grantOf($start), $code);

        self::assertSame(['VerificationPassed', 'FactorConfirmed'], $this->reportedNames());
        self::assertSame(0, Enrollment::query()->where('factor_id', $start->factor?->id)->count());
    }
}
