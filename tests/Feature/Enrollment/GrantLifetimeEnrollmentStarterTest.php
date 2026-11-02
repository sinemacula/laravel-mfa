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
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
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
use SineMacula\Laravel\Mfa\Exceptions\CodeNotSentException;
use SineMacula\Laravel\Mfa\Factors\FactorChannel;
use SineMacula\Laravel\Mfa\Factors\FactorLabel;
use SineMacula\Laravel\Mfa\MfaManager;
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
use Tests\Fixtures\Enrollment\FixedDeadlineGate;
use Tests\Fixtures\Enrollment\UndatedCombinationPolicy;
use Tests\TestCase;

/**
 * An enrolment grant lives no longer than what authorised it: the expiry is
 * taken once, from the freshness of the step-up or reauthentication, or from
 * the pending session, and nothing renews it, a later proof included.
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
final class GrantLifetimeEnrollmentStarterTest extends TestCase
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
     * A step-up 800 seconds old against a 900-second requirement leaves the
     * grant 100 seconds, well below the configured lifetime.
     *
     * @return void
     */
    public function testAStepUpLeavesTheGrantOnlyWhatRemainsOfIt(): void
    {
        $this->enableApplication(['freshness' => ['mfa.add_factor' => 900]]);
        $this->steppedUpPerson(800);

        $start = $this->startedTotp();

        self::assertSame(CarbonImmutable::now()->addSeconds(100)->getTimestamp(), $start->expiresAt?->getTimestamp());
        self::assertSame(CarbonImmutable::now()->addSeconds(100)->getTimestamp(), $this->rowOf($start)->expires_at->getTimestamp());
    }

    /**
     * The configured lifetime caps the grant when it is the shortest.
     *
     * @return void
     */
    public function testTheConfiguredLifetimeCapsTheGrant(): void
    {
        config()->set('mfa.enrollment.ttl_minutes', 2);

        $this->enableApplication(['freshness' => ['mfa.add_factor' => 3600]]);
        $this->steppedUpPerson();

        self::assertSame(CarbonImmutable::now()->addMinutes(2)->getTimestamp(), $this->startedTotp()->expiresAt?->getTimestamp());
    }

    /**
     * A grant outliving its freshness is refused, and stays refused after a
     * newer step-up in the same session: a later proof revives nothing.
     *
     * @return void
     */
    public function testAGrantThatOutlivedItsFreshnessStaysRefusedAfterANewerStepUp(): void
    {
        $this->enableApplication(['freshness' => ['mfa.add_factor' => 900]]);

        $user   = $this->steppedUpPerson(800);
        $start  = $this->startedTotp();
        $code   = $this->appCode($start);
        $factor = Factor::query()->where('status', 'confirmed')->sole();

        Carbon::setTestNow(CarbonImmutable::now()->addSeconds(100));

        $this->recordStepUp($user, $factor);

        self::assertTrue($this->mfa()->isFresh('mfa.add_factor'));

        $confirmation = $this->mfa()->confirmEnrollment($this->grantOf($start), $code);

        self::assertSame(FailureReason::EXPIRED, $confirmation->reason);
        self::assertSame(0, Factor::query()->where('status', 'pending')->count());
    }

    /**
     * A grant is live up to the second before its expiry.
     *
     * @return void
     */
    public function testAGrantIsLiveUntilItsExpiry(): void
    {
        $this->enableApplication(['freshness' => ['mfa.add_factor' => 900]]);
        $this->steppedUpPerson(800);

        $start = $this->startedTotp();

        Carbon::setTestNow(CarbonImmutable::now()->addSeconds(99));

        self::assertTrue($this->mfa()->confirmEnrollment($this->grantOf($start), $this->appCode($start))->isConfirmed());
    }

    /**
     * Neither a failed attempt, nor a resend, nor a later proof moves the
     * stored expiry.
     *
     * @return void
     */
    public function testNothingMovesTheStoredExpiry(): void
    {
        $this->enableApplication(['freshness' => ['mfa.add_factor' => 900]]);

        $user    = $this->steppedUpPerson(600);
        $factor  = Factor::query()->where('status', 'confirmed')->sole();
        $start   = $this->startedEmail();
        $expires = $this->rowOf($start)->expires_at->getTimestamp();

        $this->mfa()->confirmEnrollment($this->grantOf($start), 'wrong');

        Carbon::setTestNow(CarbonImmutable::now()->addSeconds(61));

        self::assertTrue($this->mfa()->resendEnrollmentCode($this->grantOf($start))->wasSent());

        $this->recordStepUp($user, $factor);

        self::assertSame($expires, $this->rowOf($start)->expires_at->getTimestamp());
    }

    /**
     * A reauthentication caps the grant at five minutes after it was proved.
     *
     * @return void
     */
    public function testAReauthenticationCapsTheGrant(): void
    {
        $this->reauthenticatedPerson(100);

        self::assertSame(CarbonImmutable::now()->addSeconds(200)->getTimestamp(), $this->startedTotp()->expiresAt?->getTimestamp());
    }

    /**
     * A pending session caps a bootstrap grant, and the configured lifetime
     * caps it when that is shorter.
     *
     * @return void
     */
    public function testAPendingSessionCapsABootstrapGrant(): void
    {
        $this->bootstrapPerson(minutes: 5);

        self::assertSame(CarbonImmutable::now()->addMinutes(5)->getTimestamp(), $this->startedTotp()->expiresAt?->getTimestamp());

        $this->bootstrapPerson(minutes: 60);

        $second = $this->startedTotp();

        self::assertSame(CarbonImmutable::now()->addMinutes(15)->getTimestamp(), $second->expiresAt?->getTimestamp());
    }

    /**
     * A rebound policy that reports no time for a bounded requirement refuses
     * the enrolment, though the session is fresh.
     *
     * @return void
     */
    public function testAPolicyThatCannotSayRefusesTheEnrolment(): void
    {
        $this->container()->instance(CombinationPolicy::class, new UndatedCombinationPolicy);

        $this->steppedUpPerson();

        self::assertTrue($this->mfa()->isFresh('mfa.add_factor'));
        self::assertSame(FailureReason::NOT_FRESH, $this->mfa()->startEnrollment(EnrollmentRequest::totp(self::ACCOUNT))->reason);
    }

    /**
     * A deadline already past once floored to the second is not fresh, and one
     * that survives the floor stores the floored second.
     *
     * @return void
     */
    public function testADeadlineIsFlooredToTheSecond(): void
    {
        Carbon::setTestNow('2026-11-01 12:00:00.500000');

        $this->steppedUpPerson();

        $this->container()->instance(FreshnessGate::class, new FixedDeadlineGate(CarbonImmutable::now()->addMilliseconds(200)));

        self::assertSame(FailureReason::NOT_FRESH, $this->mfa()->startEnrollment(EnrollmentRequest::totp(self::ACCOUNT))->reason);
        self::assertSame(1, Factor::query()->count());

        $this->container()->instance(FreshnessGate::class, new FixedDeadlineGate(CarbonImmutable::now()->addMilliseconds(700)));

        $start = $this->startedTotp();

        self::assertSame('2026-11-01 12:00:01.000000', $start->expiresAt?->format('Y-m-d H:i:s.u'));
    }

    /**
     * A name that is no operation's has no deadline, whatever the gate says.
     *
     * @return void
     */
    public function testANameThatIsNoOperationHasNoDeadline(): void
    {
        $this->container()->instance(FreshnessGate::class, new FixedDeadlineGate(CarbonImmutable::now()->addHour()));

        $requirements = $this->container()->make(RequirementService::class);

        self::assertNull($requirements->freshUntil('Not An Operation'));
        self::assertNotNull($requirements->freshUntil('mfa.add_factor'));
    }
}
