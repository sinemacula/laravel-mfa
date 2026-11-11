<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Codes\CodeService;
use SineMacula\Laravel\Mfa\Codes\DeliveredCodes;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\CodeDeliveryFailedException;
use SineMacula\Laravel\Mfa\Exceptions\SenderNotConfiguredException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Testing\FakeSmsSender;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\TestCase;

/**
 * Email and SMS codes end to end through the manager.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
#[CoversClass(CodeService::class)]
#[CoversClass(DeliveredCodes::class)]
#[CoversClass(EmailDriver::class)]
#[CoversClass(SmsDriver::class)]
final class OtpLifecycleTest extends TestCase
{
    use ArrangesVerification;

    /** @var string SMS factor destination. */
    private const string PHONE = '+447700900123';

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
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * @return void
     */
    public function testAnEmailCodeIsDeliveredAndVerifiedOnce(): void
    {
        $factor = $this->emailFactor($this->signedInPerson());

        $result = Mfa::sendCode(Callers::current(), $factor->id);
        $code   = $this->mailbox->lastCodeTo(self::ADDRESS);

        self::assertTrue($result->wasSent());
        self::assertNotNull($code);
        self::assertNotNull($result->challengeId);
        self::assertSame(Purpose::STEP_UP, $this->mailbox->sentTo(self::ADDRESS)[0]->purpose);

        self::assertTrue(Mfa::verify(Callers::current(), Submission::challenge($factor->id, $result->challengeId, $code))->isVerified());
        self::assertSame(FailureReason::REPLAYED, Mfa::verify(Callers::current(), Submission::challenge($factor->id, $result->challengeId, $code))->reason);
    }

    /**
     * The proof's email channel is named by the factor's destination.
     *
     * @return void
     */
    public function testAVerifiedEmailCodeRecordsAProof(): void
    {
        $factor = $this->emailFactor($this->signedInPerson());

        [$challenge, $code] = $this->sentCode($factor);

        self::assertTrue(Mfa::verify(Callers::current(), Submission::challenge($factor->id, $challenge, $code))->isVerified());

        $proofs = Mfa::proofs(Callers::current());

        self::assertCount(1, $proofs);
        self::assertSame(ProofKind::ADDITIONAL_FACTOR, $proofs[0]->kind);
        self::assertSame('email', $proofs[0]->method);
        self::assertSame($challenge, $proofs[0]->challengeId);
        self::assertSame(Purpose::STEP_UP, $proofs[0]->binding->purpose);
        self::assertSame(['kind' => 'email', 'reference' => self::ADDRESS], $proofs[0]->channel?->toArray());
    }

    /**
     * @return void
     */
    public function testAnSmsCodeIsDeliveredAndVerified(): void
    {
        $this->enableApplication(['types' => ['sms']]);

        $sender = FakeSmsSender::fake($this->container());
        $factor = $this->factorOf($this->signedInPerson(), ['type' => 'sms', 'destination' => self::PHONE]);

        $challenge = Mfa::sendCode(Callers::current(), $factor->id)->challengeId;
        $code      = $sender->lastCodeTo(self::PHONE);

        self::assertNotNull($challenge);
        self::assertNotNull($code);
        self::assertMatchesRegularExpression('/^\d{6}$/D', $code);
        self::assertTrue(Mfa::verify(Callers::current(), Submission::challenge($factor->id, $challenge, $code))->isVerified());
    }

    /**
     * Only a keyed hash is stored, in neither the factor nor the codes table.
     *
     * @return void
     */
    public function testTheCodeIsNeverStoredInClear(): void
    {
        $factor = $this->emailFactor($this->signedInPerson());

        [, $code] = $this->sentCode($factor);

        $row = Code::query()->sole();

        self::assertStringNotContainsString($code, (string) json_encode($row->getAttributes()));
        self::assertStringNotContainsString($code, (string) json_encode(Factor::query()->sole()->getAttributes()));
    }

    /**
     * @return void
     */
    public function testACodeMatchesOnlyItsOwnSignIn(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        [$challenge, $code] = $this->sentCode($factor);

        $this->beginSignIn($user, 'sign-in-b');

        self::assertSame(FailureReason::NOT_FOUND, Mfa::verify(Callers::current(), Submission::challenge($factor->id, $challenge, $code))->reason);

        [$next, $nextCode] = $this->sentCode($factor);

        self::assertTrue(Mfa::verify(Callers::current(), Submission::challenge($factor->id, $next, $nextCode))->isVerified());
    }

    /**
     * Even another of the identity's factors with the same address is refused.
     *
     * @return void
     */
    public function testACodeMatchesOnlyItsOwnFactor(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);
        $other  = $this->emailFactor($user);

        [$challenge, $code] = $this->sentCode($factor);

        self::assertSame(FailureReason::NOT_FOUND, Mfa::verify(Callers::current(), Submission::challenge($other->id, $challenge, $code))->reason);
        self::assertTrue(Mfa::verify(Callers::current(), Submission::challenge($factor->id, $challenge, $code))->isVerified());
    }

    /**
     * @return void
     */
    public function testAResendReplacesTheCodeAfterTheCooldown(): void
    {
        $factor = $this->emailFactor($this->signedInPerson());

        [$challenge, $first] = $this->sentCode($factor);

        $refused = Mfa::sendCode(Callers::current(), $factor->id);

        self::assertSame(FailureReason::SENDING_CAPPED, $refused->reason);
        self::assertSame(60, $refused->retryAfter);
        self::assertCount(1, $this->mailbox->sent());

        Carbon::setTestNow(CarbonImmutable::now()->addSeconds(60));

        [$resent, $second] = $this->sentCode($factor);

        self::assertSame($challenge, $resent);
        self::assertNotSame($first, $second);
        self::assertSame(FailureReason::INVALID_CODE, Mfa::verify(Callers::current(), Submission::challenge($factor->id, $resent, $first))->reason);
        self::assertTrue(Mfa::verify(Callers::current(), Submission::challenge($factor->id, $resent, $second))->isVerified());
    }

    /**
     * Failures and lockout survive a send, so a resend is never a free unlock.
     *
     * @return void
     */
    public function testAskingForACodeResetsNothing(): void
    {
        config()->set('mfa.attempts.factor_limit', 3);

        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        [$challenge] = $this->sentCode($factor);

        foreach (range(1, 3) as $attempt) {
            self::assertSame(FailureReason::INVALID_CODE, Mfa::verify(Callers::current(), Submission::challenge($factor->id, $challenge, 'wrong' . $attempt))->reason);
        }

        $attempts = $this->container()->make(AttemptService::class);
        $before   = $attempts->lockout($user, $factor);

        self::assertNotNull($before);
        self::assertSame(FailureReason::LOCKED, Mfa::sendCode(Callers::current(), $factor->id)->reason);

        $after = $attempts->lockout($user, $factor);

        self::assertSame(3, $this->factorRun($factor));
        self::assertNotNull($after);
        self::assertEquals($before->until, $after->until);
        self::assertCount(1, $this->mailbox->sent());
    }

    /**
     * @return void
     */
    public function testSendsAreCappedAcrossSignIns(): void
    {
        config()->set('mfa.codes.factor_send_limit', 2);

        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        foreach (['a', 'b'] as $id) {
            $this->beginSignIn($user, 'sign-in-' . $id);

            self::assertTrue(Mfa::sendCode(Callers::current(), $factor->id)->wasSent());
        }

        $this->beginSignIn($user, 'sign-in-c');

        self::assertSame(FailureReason::SENDING_CAPPED, Mfa::sendCode(Callers::current(), $factor->id)->reason);
        self::assertCount(2, $this->mailbox->sent());
    }

    /**
     * A code is never dropped silently; the send throws and no code is kept.
     *
     * @return void
     */
    public function testNothingIsSentWithoutASender(): void
    {
        $this->enableApplication(['types' => []]);

        // The manager checks the configuration once, when it is first resolved.
        $this->mfa();

        $factor = $this->factorOf($this->signedInPerson(), ['type' => 'sms', 'destination' => self::PHONE]);

        config()->set('mfa.applications.web.types', ['sms']);

        try {
            Mfa::sendCode(Callers::current(), $factor->id);

            self::fail('Expected the send to be refused.');
        } catch (CodeDeliveryFailedException $exception) {
            self::assertInstanceOf(SenderNotConfiguredException::class, $exception->getPrevious());
            self::assertSame(0, Code::query()->count());
        }
    }
}
