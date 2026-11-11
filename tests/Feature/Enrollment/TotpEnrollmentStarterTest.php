<?php

declare(strict_types = 1);

namespace Tests\Feature\Enrollment;

use Illuminate\Support\Facades\DB;
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
use SineMacula\Laravel\Mfa\Exceptions\SecretNotRevealedException;
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
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use SineMacula\Laravel\Mfa\Secrets\SecretResponse;
use SineMacula\Laravel\Mfa\Verification\ProofAcceptance;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\Fixtures\Verification\Dumps;
use Tests\TestCase;

/**
 * A TOTP secret and URI are returned once, stored encrypted and discarded on
 * restart; confirming records the step so the code cannot be reused.
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
final class TotpEnrollmentStarterTest extends TestCase
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
     * The factor is pending, labelled, enrolled through the application and
     * holding its parameters.
     *
     * @return void
     */
    public function testAStartReturnsTheSecretsAndAPendingFactor(): void
    {
        config()->set('app.name', 'Acme');

        $user  = $this->reauthenticatedPerson();
        $start = $this->started(EnrollmentRequest::totp(self::ACCOUNT, '  My phone  '));

        self::assertInstanceOf(RevealedSecret::class, $start->secret);
        self::assertInstanceOf(RevealedSecret::class, $start->provisioningUri);
        self::assertInstanceOf(RevealedSecret::class, $start->grant);
        self::assertSame(
            'otpauth://totp/Acme:person%40example.test?secret=' . $start->secret->reveal() . '&issuer=Acme&algorithm=SHA1&digits=6&period=30',
            $start->provisioningUri->reveal(),
        );
        self::assertSame(FactorStatus::PENDING, $start->factor?->status);
        self::assertSame('My phone', $start->factor->label);

        $factor = $this->pendingFactorOf($start);

        self::assertSame($user->getMorphClass(), $factor->authenticatable_type);
        self::assertSame((string) $user->id, $factor->authenticatable_id);
        self::assertSame('totp', $factor->getType());
        self::assertSame(self::APPLICATION, $factor->getApplication());
        self::assertSame($start->secret->reveal(), $factor->getSecret());
        self::assertSame('sha1', $factor->getTotpAlgorithm());
        self::assertSame(6, $factor->getTotpDigits());
        self::assertSame(30, $factor->getTotpPeriod());
        self::assertNull($factor->getLastAcceptedStep());
    }

    /**
     * Then the application's name.
     *
     * @return void
     */
    public function testTheIssuerIsTheRequestsThenTheConfiguredOne(): void
    {
        config()->set('app.name', 'Acme');
        config()->set('mfa.totp.issuer', 'Configured');

        $this->reauthenticatedPerson();

        self::assertStringContainsString('issuer=Own', (string) $this->started(EnrollmentRequest::totp(self::ACCOUNT, null, 'Own'))->provisioningUri?->reveal());
        self::assertStringContainsString('issuer=Configured', (string) $this->startedTotp()->provisioningUri?->reveal());
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnusableAccountNameRollsTheStartBack(): void
    {
        $this->reauthenticatedPerson();

        try {
            $this->mfa()->startEnrollment(Callers::current(), EnrollmentRequest::totp('not:allowed'));

            self::fail('An account name holding a colon was expected to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('account name', $exception->getMessage());
        }

        self::assertSame(0, Factor::query()->count());
    }

    /**
     * Encrypted as the verifier needs it; no dump, cast or encoding shows it.
     *
     * @return void
     */
    public function testTheSecretIsEncryptedAndNeverShown(): void
    {
        $this->reauthenticatedPerson();

        $start  = $this->startedTotp();
        $secret = (string) $start->secret?->reveal();
        $grant  = $this->grantOf($start);
        $uri    = (string) $start->provisioningUri?->reveal();

        $stored = DB::table('mfa_factors')->where('id', $start->factor?->id)->value('secret');

        self::assertIsString($stored);
        self::assertStringNotContainsString($secret, $stored);

        foreach (Dumps::of($start) as $way => $dump) {
            self::assertStringNotContainsString($secret, $dump, $way);
            self::assertStringNotContainsString($grant, $dump, $way);
            self::assertStringNotContainsString($uri, $dump, $way);
        }

        foreach ([static fn (): string => json_encode($start, JSON_THROW_ON_ERROR), static fn (): string => serialize($start)] as $encode) {
            try {
                $encode();

                self::fail('A start holding secrets was expected to refuse.');
            } catch (SecretNotRevealedException) {
                // Refused by the secret itself.
            }
        }
    }

    /**
     * In a response no cache keeps.
     *
     * @return void
     */
    public function testTheSecretsGoOutWithoutBeingStored(): void
    {
        $this->reauthenticatedPerson();

        $start    = $this->startedTotp();
        $response = SecretResponse::json(['secret' => $start->secret, 'uri' => $start->provisioningUri, 'grant' => $start->grant]);

        self::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        self::assertSame($start->secret?->reveal(), $response->getData(true)['secret']);
    }

    /**
     * The old secret's code fails under the new grant, and the old grant is not
     * found.
     *
     * @return void
     */
    public function testRestartingDiscardsTheOldSecretAndGrant(): void
    {
        $this->reauthenticatedPerson();

        $first   = $this->startedTotp();
        $oldCode = $this->appCode($first);
        $second  = $this->startedTotp();

        self::assertNotSame($first->secret?->reveal(), $second->secret?->reveal());
        self::assertSame(1, Factor::query()->count());
        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($first), $oldCode)->reason);
        self::assertSame(FailureReason::INVALID_CODE, $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($second), $oldCode)->reason);
    }

    /**
     * The confirming code is replayed at the next verification; a later one
     * passes.
     *
     * @return void
     */
    public function testConfirmingRecordsTheStep(): void
    {
        $this->reauthenticatedPerson();

        $start = $this->startedTotp();
        $code  = $this->appCode($start);

        $confirmation = $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $code);

        self::assertTrue($confirmation->isConfirmed());
        self::assertSame(FactorStatus::CONFIRMED, $confirmation->factor?->status);

        $factor = Factor::query()->whereKey($start->factor?->id)->sole();

        self::assertTrue($factor->isConfirmed());
        self::assertNotNull($factor->getConfirmedAt());
        self::assertNotNull($factor->getLastAcceptedStep());
        self::assertSame(FailureReason::REPLAYED, $this->mfa()->verify(Callers::current(), Submission::factor($factor->id, $code))->reason);
    }

    /**
     * Whatever else is configured.
     *
     * @return void
     */
    public function testTheWindowIsTheGrantsApplicationsOwn(): void
    {
        $this->enableApplication(['totp_window' => 0]);
        $this->reauthenticatedPerson();

        $start = $this->startedTotp();

        self::assertSame(FailureReason::INVALID_CODE, $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $this->appCode($start, 1))->reason);
        self::assertTrue($this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $this->appCode($start))->isConfirmed());
    }

    /**
     * Until it is confirmed.
     *
     * @return void
     */
    public function testAPendingFactorIsNeitherUsableNorOffered(): void
    {
        $this->reauthenticatedPerson();

        $start  = $this->startedTotp();
        $factor = $this->pendingFactorOf($start);

        self::assertSame([], $this->mfa()->offeredFactors(Callers::current()));
        self::assertSame(FailureReason::NOT_CONFIRMED, $this->mfa()->verify(Callers::current(), Submission::factor($factor->id, $this->appCode($start)))->reason);

        $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $this->appCode($start));

        self::assertCount(1, $this->mfa()->offeredFactors(Callers::current()));
    }

    /**
     * Trimmed, a blank one is none, and one too long is refused.
     *
     * @return void
     */
    public function testALabelIsNormalized(): void
    {
        self::assertNull(EnrollmentRequest::totp(self::ACCOUNT, '   ')->label);
        self::assertNull(EnrollmentRequest::of('custom')->label);
        self::assertSame('Phone', EnrollmentRequest::delivered('sms', '+447700900123', ' Phone ')->label);
        self::assertSame(str_repeat('é', 255), FactorLabel::normalize(str_repeat('é', 255)));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A factor\'s label must not be longer than 255 characters.');

        FactorLabel::normalize(str_repeat('a', 256));
    }

    /**
     * @return void
     */
    public function testARequestHidesItsDestination(): void
    {
        $request = EnrollmentRequest::delivered('email', self::ADDRESS);

        self::assertSame(self::ADDRESS, $request->destination());
        self::assertNull(EnrollmentRequest::of('custom')->destination());

        foreach (Dumps::of($request) as $way => $dump) {
            self::assertStringNotContainsString(self::ADDRESS, $dump, $way);
        }
    }
}
