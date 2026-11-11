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
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\CodeNotSentException;
use SineMacula\Laravel\Mfa\Factors\FactorChannel;
use SineMacula\Laravel\Mfa\Factors\FactorLabel;
use SineMacula\Laravel\Mfa\MfaManager;
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
use Tests\Fixtures\Enrollment\HardwareAppDriver;
use Tests\TestCase;

/**
 * An application's own type whose driver provisions an authenticator app starts
 * under an account name and confirms through its driver, as TOTP does.
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
final class ProvisionedTypeEnrollmentStarterTest extends TestCase
{
    use ArrangesEnrollment;

    /**
     * With the type enabled and its driver registered.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
        $this->enableApplication(['types' => ['totp', 'email', HardwareAppDriver::TYPE]]);

        $this->mfa()->extend(HardwareAppDriver::TYPE, fn (): HardwareAppDriver => new HardwareAppDriver);
    }

    /**
     * Its secret and URI are returned once, and it confirms with the code its
     * driver accepts.
     *
     * @return void
     */
    public function testTheTypeStartsAndConfirms(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->started(EnrollmentRequest::provisioned(HardwareAppDriver::TYPE, self::ACCOUNT, ' Key ', 'Example'));

        self::assertSame(HardwareAppDriver::TYPE, $start->factor?->type);
        self::assertSame('Key', $start->factor->label);
        self::assertSame(FactorStatus::PENDING, $start->factor->status);
        self::assertSame(HardwareAppDriver::SECRET, $start->secret?->reveal());
        self::assertSame('hardware://Example/' . self::ACCOUNT . '?secret=' . HardwareAppDriver::SECRET, $start->provisioningUri?->reveal());

        self::assertSame(FailureReason::INVALID_CODE, $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), 'wrong')->reason);

        $confirmation = $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), HardwareAppDriver::CODE);

        self::assertTrue($confirmation->isConfirmed());
        self::assertSame(FactorStatus::CONFIRMED, $confirmation->factor?->status);
    }

    /**
     * Without an issuer of its own.
     *
     * @return void
     */
    public function testTheConfiguredIssuerApplies(): void
    {
        config()->set('mfa.totp.issuer', 'Configured');

        $this->reauthenticatedPerson();

        $start = $this->started(EnrollmentRequest::provisioned(HardwareAppDriver::TYPE, self::ACCOUNT));

        self::assertSame('hardware://Configured/' . self::ACCOUNT . '?secret=' . HardwareAppDriver::SECRET, $start->provisioningUri?->reveal());
    }

    /**
     * Its absence is the caller's mistake.
     *
     * @return void
     */
    public function testAnAccountNameIsNeeded(): void
    {
        $this->reauthenticatedPerson();

        $this->expectException(\InvalidArgumentException::class);

        $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::of(HardwareAppDriver::TYPE));
    }
}
