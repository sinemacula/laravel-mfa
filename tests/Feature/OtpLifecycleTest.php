<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Codes\CodeService;
use SineMacula\Laravel\Mfa\Codes\DeliveredCodes;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\CodeSent;
use SineMacula\Laravel\Mfa\Events\MfaChallengeIssued;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;
use SineMacula\Laravel\Mfa\Events\MfaVerified;
use SineMacula\Laravel\Mfa\Exceptions\SenderNotConfiguredException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Testing\FakeSmsSender;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * End-to-end lifecycle of the delivered codes (email and SMS) through the
 * manager: a code is delivered through the bound sender and accepted once, for
 * its own session, purpose and factor only; a resend replaces it after the
 * cooldown; the sends are capped across sessions; and nothing is sent without a
 * sender bound.
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
    use RefreshDatabase;

    /** @var string The address the email factor delivers to. */
    private const string ADDRESS = 'email-mfa@example.test';

    /** @var string The phone number the SMS factor delivers to. */
    private const string PHONE = '+447700900123';

    /**
     * An email code is delivered to the factor's address in the code message,
     * reported, and verified once.
     *
     * @return void
     */
    public function testAnEmailCodeIsDeliveredAndVerifiedOnce(): void
    {
        $sender = FakeEmailSender::fake($this->container());
        $factor = $this->enroll('email', self::ADDRESS);

        Event::fake([MfaChallengeIssued::class, CodeSent::class, MfaVerified::class]);

        $result = Mfa::challenge('email', $factor);
        $code   = $sender->lastCodeTo(self::ADDRESS);

        self::assertNotNull($result);
        self::assertTrue($result->wasSent());
        self::assertNotNull($code);
        self::assertInstanceOf(MfaCodeMessage::class, $sender->sentTo(self::ADDRESS)[0]['message']);
        Event::assertDispatched(MfaChallengeIssued::class);
        Event::assertDispatched(CodeSent::class, static fn (CodeSent $event): bool => $event->challengeId === $result->challengeId);

        self::assertTrue(Mfa::verify('email', $factor, $code));
        self::assertTrue(Mfa::hasEverVerified());
        Event::assertDispatched(MfaVerified::class);

        self::assertFalse(Mfa::verify('email', $factor, $code));
    }

    /**
     * An SMS code is delivered to the factor's phone number in the configured
     * message and verified.
     *
     * @return void
     */
    public function testAnSmsCodeIsDeliveredAndVerified(): void
    {
        $sender = FakeSmsSender::fake($this->container());
        $factor = $this->enroll('sms', self::PHONE);

        Mfa::challenge('sms', $factor);

        $message = $sender->lastMessageTo(self::PHONE);

        self::assertNotNull($message);
        self::assertSame(1, preg_match('/^Your verification code is: (\d{6})$/D', $message, $matches));
        self::assertTrue(Mfa::verify('sms', $factor, $matches[1]));
    }

    /**
     * The code is stored only as a keyed hash: neither the factor nor the codes
     * table holds it.
     *
     * @return void
     */
    public function testTheCodeIsNeverStoredInClear(): void
    {
        $sender = FakeEmailSender::fake($this->container());
        $factor = $this->enroll('email', self::ADDRESS);

        Mfa::challenge('email', $factor);

        $code = $sender->lastCodeTo(self::ADDRESS);
        $row  = Code::query()->sole();

        self::assertNotNull($code);
        self::assertStringNotContainsString($code, (string) json_encode($row->getAttributes()));
        self::assertStringNotContainsString($code, (string) json_encode(Factor::query()->sole()->getAttributes()));
    }

    /**
     * A code matches only the session it was sent in: after the session
     * changes, it is not found, and a code sent for the new session is.
     *
     * @return void
     */
    public function testACodeMatchesOnlyItsOwnSession(): void
    {
        $sender = FakeEmailSender::fake($this->container());
        $factor = $this->enroll('email', self::ADDRESS);

        Mfa::challenge('email', $factor);

        $first = $sender->lastCodeTo(self::ADDRESS);

        self::assertNotNull($first);

        $this->container()->make(Session::class)->setId(str_repeat('b', 40));

        Event::fake([MfaVerificationFailed::class]);

        self::assertFalse(Mfa::verify('email', $factor, $first));
        Event::assertDispatched(MfaVerificationFailed::class, static fn (MfaVerificationFailed $event): bool => $event->reason === FailureReason::EXPIRED);

        Mfa::challenge('email', $factor);

        $second = $sender->lastCodeTo(self::ADDRESS);

        self::assertNotNull($second);
        self::assertTrue(Mfa::verify('email', $factor, $second));
    }

    /**
     * A code matches only the purpose it was sent for.
     *
     * @return void
     */
    public function testACodeMatchesOnlyItsOwnPurpose(): void
    {
        $sender = FakeEmailSender::fake($this->container());
        $factor = $this->enroll('email', self::ADDRESS);

        Mfa::challenge('email', $factor, Purpose::STEP_UP);

        $code = $sender->lastCodeTo(self::ADDRESS);

        self::assertNotNull($code);
        self::assertFalse(Mfa::verify('email', $factor, $code));
        self::assertFalse(Mfa::verify('email', $factor, $code, Purpose::ENROLLMENT));
        self::assertTrue(Mfa::verify('email', $factor, $code, Purpose::STEP_UP));
    }

    /**
     * A code matches only the factor it was sent for, even another of the
     * identity's factors with the same address.
     *
     * @return void
     */
    public function testACodeMatchesOnlyItsOwnFactor(): void
    {
        $sender = FakeEmailSender::fake($this->container());
        $factor = $this->enroll('email', self::ADDRESS);
        $other  = Factor::query()->create([...$this->ownerOf($factor), 'type' => 'email', 'destination' => self::ADDRESS]);

        Mfa::challenge('email', $factor);

        $code = $sender->lastCodeTo(self::ADDRESS);

        self::assertNotNull($code);
        self::assertFalse(Mfa::verify('email', $other, $code));
        self::assertTrue(Mfa::verify('email', $factor, $code));
    }

    /**
     * A resend waits out the cooldown, then sends a new code that replaces the
     * previous one.
     *
     * @return void
     */
    public function testAResendReplacesTheCodeAfterTheCooldown(): void
    {
        $this->travelTo(CarbonImmutable::parse('2026-11-01 12:00:00'));

        $sender = FakeEmailSender::fake($this->container());
        $factor = $this->enroll('email', self::ADDRESS);

        Mfa::challenge('email', $factor);

        $first   = $sender->lastCodeTo(self::ADDRESS);
        $refused = Mfa::challenge('email', $factor);

        self::assertNotNull($refused);
        self::assertSame(FailureReason::SENDING_CAPPED, $refused->reason);
        self::assertSame(60, $refused->retryAfter);
        self::assertCount(1, $sender->sent());

        $this->travel(60)->seconds();

        $resent = Mfa::challenge('email', $factor);
        $second = $sender->lastCodeTo(self::ADDRESS);

        self::assertNotNull($resent);
        self::assertTrue($resent->wasSent());
        self::assertNotNull($first);
        self::assertNotNull($second);

        if ($first !== $second) {
            self::assertFalse(Mfa::verify('email', $factor, $first));
        }

        self::assertTrue(Mfa::verify('email', $factor, $second));
    }

    /**
     * The sends of a factor are capped across sessions, so a new session does
     * not bring new sends.
     *
     * @return void
     */
    public function testSendsAreCappedAcrossSessions(): void
    {
        config()->set('mfa.codes.factor_send_limit', 2);

        $sender  = FakeEmailSender::fake($this->container());
        $factor  = $this->enroll('email', self::ADDRESS);
        $session = $this->container()->make(Session::class);

        foreach (['a', 'b'] as $id) {
            $session->setId(str_repeat($id, 40));

            self::assertTrue(Mfa::challenge('email', $factor)?->wasSent());
        }

        $session->setId(str_repeat('c', 40));

        self::assertSame(FailureReason::SENDING_CAPPED, Mfa::challenge('email', $factor)?->reason);
        self::assertCount(2, $sender->sent());
    }

    /**
     * Without a sender bound, a code is never dropped silently: the send
     * throws, and no code is kept.
     *
     * @return void
     */
    public function testNothingIsSentWithoutASender(): void
    {
        $factor = $this->enroll('sms', self::PHONE);

        try {
            Mfa::challenge('sms', $factor);
            self::fail('Expected the send to be refused.');
        } catch (SenderNotConfiguredException) {
            self::assertSame(0, Code::query()->count());
        }
    }

    /**
     * Sign in as a new user with a factor of the type, delivering to the
     * destination.
     *
     * @param  string  $type
     * @param  string  $destination
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function enroll(string $type, string $destination): Factor
    {
        $user = TestUser::query()->create(['email' => self::ADDRESS, 'mfa_enabled' => true]);

        $this->actingAs($user);

        return Factor::query()->create([
            'authenticatable_type' => $user->getMorphClass(),
            'authenticatable_id'   => (string) $user->id,
            'type'                 => $type,
            'destination'          => $destination,
        ]);
    }

    /**
     * The owner columns of a factor, to create another for the same identity.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return array{authenticatable_type: string, authenticatable_id: string}
     */
    private function ownerOf(Factor $factor): array
    {
        return [
            'authenticatable_type' => $factor->authenticatable_type,
            'authenticatable_id'   => $factor->authenticatable_id,
        ];
    }
}
