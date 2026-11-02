<?php

declare(strict_types = 1);

namespace Tests\Feature\Verification;

use Carbon\Carbon;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\CodeSent;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesLow;
use SineMacula\Laravel\Mfa\Events\RecoveryCodeUsed;
use SineMacula\Laravel\Mfa\Events\VerificationFailed;
use SineMacula\Laravel\Mfa\Events\VerificationPassed;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\RefusedUnderLockException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Code;
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
 * The events of a sign-in, a step-up and a recovery code's use come in order
 * once the change commits, with the proof already in the store, and none after
 * a rollback.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerificationService::class)]
#[CoversClass(ProofAcceptance::class)]
#[CoversClass(ChallengeRequests::class)]
#[CoversClass(EventDispatcher::class)]
#[CoversClass(SubmissionRoutes::class)]
#[CoversClass(CheckOutcome::class)]
#[CoversClass(VerificationResult::class)]
#[CoversClass(PasskeyAssertions::class)]
#[CoversClass(ChallengeOutcome::class)]
#[CoversClass(ChallengeCounters::class)]
#[CoversClass(PackageChallengeGateway::class)]
#[CoversClass(RecoveryCodeService::class)]
#[CoversClass(SendResult::class)]
#[CoversClass(RefusedUnderLockException::class)]
final class EventSequenceVerificationServiceTest extends TestCase
{
    use ArrangesVerification;

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
     * A sign-in on a pending session sends one code and passes once, naming the
     * challenge, the factor, the type and the purpose.
     *
     * @return void
     */
    public function testASignInsEvents(): void
    {
        $user = $this->person();

        $this->pendingSession($user);
        $this->beginSignIn($user, self::PENDING);

        $factor = $this->emailFactor($user);

        [$challenge, $code] = $this->sentCode($factor);

        $this->mfa()->verify(Submission::challenge($factor->id, $challenge, $code));

        [$sent, $passed] = $this->reported;

        self::assertCount(2, $this->reported);
        self::assertInstanceOf(CodeSent::class, $sent);
        self::assertSame($challenge, $sent->challengeId);
        self::assertSame(Purpose::SIGN_IN, $sent->purpose);
        self::assertSame($factor->id, $sent->factor->id);
        self::assertSame(self::APPLICATION, $sent->context()['application']);
        self::assertInstanceOf(VerificationPassed::class, $passed);
        self::assertSame($challenge, $passed->challengeId);
        self::assertSame('email', $passed->type);
        self::assertSame($factor->id, $passed->factor?->id);
        self::assertSame(Purpose::SIGN_IN, $passed->purpose);
        self::assertSame(self::APPLICATION, $passed->context()['application']);
        self::assertNotSame(self::ADDRESS, $sent->factor->maskedDestination);
    }

    /**
     * A step-up passes once, and a listener already sees the new proof.
     *
     * @return void
     */
    public function testAStepUpsListenerSeesTheProof(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);
        $seen   = null;

        Event::listen(VerificationPassed::class, static function () use (&$seen): void {
            $seen = count(Mfa::proofs());
        });

        $this->mfa()->verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)));

        self::assertSame(1, $seen);
        self::assertCount(1, $this->reported);
        self::assertInstanceOf(VerificationPassed::class, $this->reported[0]);
        self::assertSame(Purpose::STEP_UP, $this->reported[0]->purpose);
        self::assertNull($this->reported[0]->challengeId);
    }

    /**
     * A recovery code's use reports the pass, then its use with the count left,
     * then that the set is low.
     *
     * @return void
     */
    public function testARecoveryCodesEventsComeInOrder(): void
    {
        config()->set('mfa.recovery_codes.low_count', 9);

        $user = $this->signedInPerson();

        $this->totpFactor($user);

        $code = $this->recoveryCode($user);

        $this->mfa()->verify(Submission::recoveryCode($code));

        self::assertCount(3, $this->reported);
        [$passed, $used, $low] = $this->reported;

        self::assertInstanceOf(VerificationPassed::class, $passed);
        self::assertSame('recovery_code', $passed->type);
        self::assertNull($passed->factor);
        self::assertInstanceOf(RecoveryCodeUsed::class, $used);
        self::assertSame(9, $used->remaining);
        self::assertSame(Purpose::STEP_UP, $used->purpose);
        self::assertSame(self::APPLICATION, $used->context()['application']);
        self::assertInstanceOf(RecoveryCodesLow::class, $low);
        self::assertSame(9, $low->remaining);
    }

    /**
     * A set above its low count reports its use and nothing more, and a low
     * count of zero never reports it.
     *
     * @return void
     */
    public function testASetAboveItsLowCountIsNotLow(): void
    {
        config()->set('mfa.recovery_codes.low_count', 8);

        $user = $this->signedInPerson();

        $this->totpFactor($user);

        $code = $this->recoveryCode($user);

        $this->mfa()->verify(Submission::recoveryCode($code));

        self::assertCount(2, $this->reported);
    }

    /**
     * After a rollback, nothing is reported but the failure.
     *
     * @return void
     */
    public function testNothingIsDispatchedAfterARollback(): void
    {
        $user = $this->signedInPerson();

        $this->totpFactor($user);

        $code = $this->recoveryCode($user);

        $this->container()->instance(StepUp::class, new RefusingCompletion(new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'Refused.')));

        $this->mfa()->verify(Submission::recoveryCode($code));

        self::assertCount(1, $this->reported);
        self::assertInstanceOf(VerificationFailed::class, $this->reported[0]);
        self::assertSame('recovery_code', $this->reported[0]->type);
        self::assertSame(10, $this->mfa()->recoveryCodes()?->remaining);
    }

    /**
     * A failure's report names the challenge the attempt went through, and
     * every event implements the catalogue's contract.
     *
     * @return void
     */
    public function testAFailureNamesItsChallenge(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        [$challenge] = $this->sentCode($factor);

        $this->forgetReports();

        $this->mfa()->verify(Submission::challenge($factor->id, $challenge, 'wrong'));

        $event = $this->failureReported();

        self::assertSame($challenge, $event->challengeId);
        self::assertSame('email', $event->type);
        self::assertSame($factor->id, $event->factor?->id);
        self::assertSame(self::APPLICATION, $event->context()['application']);
        self::assertSame(Purpose::STEP_UP, $event->purpose);
        self::assertContainsOnlyInstancesOf(MfaEvent::class, $this->reported);
    }

    /**
     * A listener's refusal after the commit does not undo a code already
     * delivered, nor is it answered as a refused send: it propagates.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAListenersRefusalOfASentCodePropagates(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        Event::listen(CodeSent::class, static function (): void {
            throw new OperationRefusedException(FailureReason::NOT_FRESH, 'A listener refused.');
        });

        try {
            $this->mfa()->sendCode($factor->id);

            self::fail('The listener\'s refusal must propagate.');
        } catch (OperationRefusedException $exception) {
            self::assertSame('A listener refused.', $exception->getMessage());
        }

        self::assertSame(1, Code::query()->count());
        self::assertNotNull($this->mailbox->lastCodeTo(self::ADDRESS));
    }

    /**
     * A passkey that reports a challenge has it on the pass and the proof.
     *
     * @return void
     */
    public function testAPasskeysChallengeIsReported(): void
    {
        $this->enablePasskeys();

        $user = $this->signedInPerson();
        $key  = $this->passkeyFactor($user);

        $result = $this->mfa()->verify(Submission::assertion($key->id, ['id' => self::CREDENTIAL]));

        self::assertSame('passkey-challenge', $result->proof?->challengeId);
        self::assertInstanceOf(VerificationPassed::class, $this->reported[0]);
        self::assertSame('passkey-challenge', $this->reported[0]->challengeId);
        self::assertSame('passkey', $this->reported[0]->type);
    }
}
