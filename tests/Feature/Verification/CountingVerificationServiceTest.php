<?php

declare(strict_types = 1);

namespace Tests\Feature\Verification;

use Carbon\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\AttemptOutcome;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertions;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Verification\ChallengeRequests;
use SineMacula\Laravel\Mfa\Verification\CheckOutcome;
use SineMacula\Laravel\Mfa\Verification\ProofAcceptance;
use SineMacula\Laravel\Mfa\Verification\Submission;
use SineMacula\Laravel\Mfa\Verification\SubmissionRoutes;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use SineMacula\Laravel\Mfa\Verification\VerificationService;
use Tests\Fixtures\Drivers\AuthenticatorApp;
use Tests\Fixtures\Seams\RefusingCompletion;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\TestCase;

/**
 * Every route counts an attempt exactly once and reports one failure, and the
 * request's address holds one slot around the whole verification, kept only by
 * a failure that was counted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerificationService::class)]
#[CoversClass(ProofAcceptance::class)]
#[CoversClass(AttemptService::class)]
#[CoversClass(AttemptOutcome::class)]
#[CoversClass(SubmissionRoutes::class)]
#[CoversClass(CheckOutcome::class)]
#[CoversClass(ChallengeRequests::class)]
#[CoversClass(VerificationResult::class)]
#[CoversClass(PasskeyAssertions::class)]
#[CoversClass(ChallengeOutcome::class)]
#[CoversClass(ChallengeCounters::class)]
#[CoversClass(PackageChallengeGateway::class)]
#[CoversClass(RecoveryCodeService::class)]
#[CoversClass(SendResult::class)]
final class CountingVerificationServiceTest extends TestCase
{
    use ArrangesVerification;

    /** @var string The address the requests come from. */
    private const string IP = '203.0.113.9';

    /**
     * Arrange the application and the request's address.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
        $this->requestFrom(self::IP);
    }

    /**
     * Release the frozen clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * A wrong code for a factor counts once against the factor, the identity
     * and the address, and reports once.
     *
     * @return void
     */
    public function testAFactorsWrongCodeCountsOnce(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        $this->mfa()->verify(Submission::factor($factor->id, 'wrong'));

        self::assertSame(1, $this->factorRun($factor));
        self::assertSame(1, $this->identityRun($user));
        self::assertSame(1, $this->addressHits(self::IP));
        self::assertSame(FailureReason::INVALID_CODE, $this->failureReported()->reason);
    }

    /**
     * A wrong code for a challenge counts once, through the gateway's report
     * alone.
     *
     * @return void
     */
    public function testAChallengesWrongCodeCountsOnce(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        [$challenge] = $this->sentCode($factor);

        $this->forgetReports();

        $this->mfa()->verify(Submission::challenge($factor->id, $challenge, 'wrong'));

        self::assertSame(1, $this->factorRun($factor));
        self::assertSame(1, $this->identityRun($user));
        self::assertSame(1, $this->addressHits(self::IP));
        self::assertSame(FailureReason::INVALID_CODE, $this->failureReported()->reason);
    }

    /**
     * A wrong recovery code counts once against the identity and the address.
     *
     * @return void
     */
    public function testARecoveryCodesWrongCodeCountsOnce(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        $this->recoveryCode($user);

        $this->mfa()->verify(Submission::recoveryCode('wrong'));

        self::assertSame(0, $this->factorRun($factor));
        self::assertSame(1, $this->identityRun($user));
        self::assertSame(1, $this->addressHits(self::IP));
        self::assertSame(FailureReason::INVALID_CODE, $this->failureReported()->reason);
    }

    /**
     * A pass gives the address's slot back, resets the factor's run and the
     * identity's, and stamps the factor's last use.
     *
     * @return void
     */
    public function testAPassGivesTheSlotBackAndResetsTheRun(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user, ['consecutive_failures' => 2]);

        self::assertTrue($this->mfa()->verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)))->isVerified());

        self::assertSame(0, $this->factorRun($factor));
        self::assertSame(0, $this->addressHits(self::IP));
        self::assertNotNull(Factor::query()->whereKey($factor->id)->sole()->getLastUsedAt());
    }

    /**
     * A refusal under the lock gives the address's slot back.
     *
     * @return void
     */
    public function testARefusalGivesTheSlotBack(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        $this->container()->instance(StepUp::class, new RefusingCompletion(new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'Refused.')));

        self::assertSame(FailureReason::NOT_ACCEPTED, $this->mfa()->verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)))->reason);
        self::assertSame(0, $this->addressHits(self::IP));

        $this->enableApplication(['types' => ['email']]);

        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->mfa()->verify(Submission::factor($factor->id, '000000'))->reason);
        self::assertSame(0, $this->addressHits(self::IP));
    }

    /**
     * An exception gives the address's slot back, and propagates.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExceptionGivesTheSlotBack(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        $this->container()->instance(StepUp::class, new RefusingCompletion(new \DomainException('Broken.')));

        try {
            $this->mfa()->verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)));

            self::fail('The exception must propagate.');
        } catch (\DomainException) {
            self::assertSame(0, $this->addressHits(self::IP));
        }
    }

    /**
     * A send refused or sent holds no slot.
     *
     * @return void
     */
    public function testASendHoldsNoSlot(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        self::assertTrue($this->mfa()->sendCode($factor->id)->wasSent());
        self::assertSame(0, $this->addressHits(self::IP));

        self::assertFalse($this->mfa()->sendCode($factor->id)->wasSent());
        self::assertSame(0, $this->addressHits(self::IP));
    }

    /**
     * Sending a code to a type with none to send sends nothing, and holds no
     * slot.
     *
     * @return void
     */
    public function testATypeWithNothingToSendIsNotFound(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->sendCode($factor->id)->reason);
        self::assertSame(0, $this->addressHits(self::IP));
        self::assertSame([], $this->reported);
    }

    /**
     * A lockout refuses a send with how long to wait, and resets nothing.
     *
     * @return void
     */
    public function testALockoutRefusesASendWithItsWait(): void
    {
        config()->set('mfa.attempts.factor_limit', 1);

        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        [$challenge] = $this->sentCode($factor);

        $this->mfa()->verify(Submission::challenge($factor->id, $challenge, 'wrong'));

        $result = $this->mfa()->sendCode($factor->id);

        self::assertSame(FailureReason::LOCKED, $result->reason);
        self::assertSame(900, $result->retryAfter);
        self::assertSame(1, $this->factorRun($factor));
    }
}
