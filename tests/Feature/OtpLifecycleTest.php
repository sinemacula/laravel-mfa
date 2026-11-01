<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Mail;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Contracts\SmsGateway;
use SineMacula\Laravel\Mfa\Drivers\AbstractOtpDriver;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Events\MfaChallengeIssued;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;
use SineMacula\Laravel\Mfa\Events\MfaVerified;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Testing\FakeSmsGateway;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * End-to-end lifecycle for the OTP-delivery drivers (email + SMS).
 *
 * Covers challenge dispatch (via Mail::fake / FakeSmsGateway), code
 * persistence, successful verification, the "wrong code" and "expired code"
 * branches, and event emissions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
#[CoversClass(AbstractOtpDriver::class)]
#[CoversClass(EmailDriver::class)]
#[CoversClass(SmsDriver::class)]
final class OtpLifecycleTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Test email challenge sends the mailable to the destination.
     *
     * @return void
     */
    public function testEmailChallengeSendsMailableToDestination(): void
    {
        Mail::fake();

        [$user, $factor] = $this->enrollEmail();

        Mfa::challenge('email', $factor);

        Mail::assertSent(MfaCodeMessage::class, static fn (MfaCodeMessage $mail): bool => $mail->hasTo($user->email));
    }

    /**
     * Test email challenge dispatches the MfaChallengeIssued event.
     *
     * @return void
     */
    public function testEmailChallengeDispatchesChallengeIssuedEvent(): void
    {
        Mail::fake();
        Event::fake([MfaChallengeIssued::class]);

        [, $factor] = $this->enrollEmail();

        Mfa::challenge('email', $factor);

        Event::assertDispatched(MfaChallengeIssued::class);
    }

    /**
     * Test email challenge persists a code on the factor.
     *
     * @return void
     */
    public function testEmailChallengePersistsCodeOnFactor(): void
    {
        Mail::fake();

        [, $factor] = $this->enrollEmail();

        Mfa::challenge('email', $factor);

        $factor->refresh();

        self::assertNotNull($factor->getCode());
    }

    /**
     * Test verifying the persisted email code returns true.
     *
     * @return void
     */
    public function testVerifyingPersistedEmailCodeReturnsTrue(): void
    {
        Mail::fake();

        [, $factor] = $this->enrollEmail();

        Mfa::challenge('email', $factor);
        $factor->refresh();

        $code = $factor->getCode();
        self::assertNotNull($code);

        self::assertTrue(Mfa::verify('email', $factor, $code));
    }

    /**
     * Test verifying the persisted email code marks the verification store.
     *
     * @return void
     */
    public function testVerifyingPersistedEmailCodeMarksVerificationStore(): void
    {
        Mail::fake();

        [, $factor] = $this->enrollEmail();

        Mfa::challenge('email', $factor);
        $factor->refresh();

        Mfa::verify('email', $factor, $factor->getCode() ?? '');

        self::assertTrue(Mfa::hasEverVerified());
    }

    /**
     * Test verifying the persisted email code dispatches MfaVerified.
     *
     * @return void
     */
    public function testVerifyingPersistedEmailCodeDispatchesVerifiedEvent(): void
    {
        Mail::fake();
        Event::fake([MfaVerified::class]);

        [, $factor] = $this->enrollEmail();

        Mfa::challenge('email', $factor);
        $factor->refresh();

        Mfa::verify('email', $factor, $factor->getCode() ?? '');

        Event::assertDispatched(MfaVerified::class);
    }

    /**
     * Test verifying the persisted email code clears code and expiry.
     *
     * @return void
     */
    public function testVerifyingPersistedEmailCodeClearsCodeAndExpiry(): void
    {
        Mail::fake();

        [, $factor] = $this->enrollEmail();

        Mfa::challenge('email', $factor);
        $factor->refresh();

        Mfa::verify('email', $factor, $factor->getCode() ?? '');

        $factor->refresh();

        self::assertNull($factor->getCode());
        self::assertNull($factor->getExpiresAt());
    }

    /**
     * Issuing an SMS challenge through the bound `FakeSmsGateway` should record
     * the outbound message and verify successfully against the persisted code.
     *
     * @return void
     */
    public function testSmsChallengeIssuedAndVerifiedViaBoundGateway(): void
    {
        $gateway = new FakeSmsGateway;
        $this->container()->instance(SmsGateway::class, $gateway);

        Event::fake([MfaChallengeIssued::class, MfaVerified::class]);

        [, $factor] = $this->enrollSms('+441234567890');

        Mfa::challenge('sms', $factor);

        $factor->refresh();

        $sent = $gateway->sentTo('+441234567890');
        self::assertCount(1, $sent);
        self::assertStringContainsString(
            $factor->getCode() ?? '',
            $sent[0]['message'],
        );

        $verified = Mfa::verify('sms', $factor, $factor->getCode() ?? '');

        self::assertTrue($verified);
    }

    /**
     * A submitted email code that does not match the persisted code should fail
     * verification and dispatch an `invalid_code` failure event.
     *
     * @return void
     */
    public function testEmailVerificationFailsWithWrongCode(): void
    {
        Mail::fake();
        Event::fake([MfaVerificationFailed::class]);

        [, $factor] = $this->enrollEmail();
        Mfa::challenge('email', $factor);
        $factor->refresh();

        $wrongCodeAttempt = Mfa::verify('email', $factor, '000000');

        self::assertFalse($wrongCodeAttempt);

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === FailureReason::INVALID_CODE,
        );
    }

    /**
     * A code whose `expires_at` has passed must be rejected with an `expired`
     * failure event even when the submitted code matches the stored value.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testExpiredCodeIsRejected(): void
    {
        Mail::fake();

        [, $factor] = $this->enrollEmail();
        Mfa::challenge('email', $factor);
        $factor->refresh();

        // Force the code to be expired by rewinding expires_at.
        $factor->forceFill(['expires_at' => now()->subMinute()])->save();

        Event::fake([MfaVerificationFailed::class]);

        $expiredCodeAttempt = Mfa::verify('email', $factor, $factor->getCode() ?? '');

        self::assertFalse($expiredCodeAttempt);

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === FailureReason::EXPIRED,
        );
    }

    /**
     * Sending a fresh code resets nothing: the factor's failures in a row and
     * its lockout survive the send, so a resend is never a free unlock.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function testEmailChallengeResetsNothing(): void
    {
        Mail::fake();

        config()->set('mfa.attempts.factor_limit', 3);

        [$user, $factor] = $this->enrollEmail();

        self::assertFalse(Mfa::verify('email', $factor, '000000'));
        self::assertFalse(Mfa::verify('email', $factor, '000000'));
        self::assertFalse(Mfa::verify('email', $factor, '000000'));

        $attempts = $this->container()->make(AttemptService::class);
        $before   = $attempts->lockout($user, $factor);

        self::assertNotNull($before);

        Mfa::challenge('email', $factor);

        $factor->refresh();

        $after = $attempts->lockout($user, $factor);

        self::assertSame(3, $factor->getConsecutiveFailures());
        self::assertNotNull($after);
        self::assertEquals($before->until, $after->until);
        self::assertNotNull($factor->getCode());
    }

    /**
     * Enrol a fresh test user with an email factor and authenticate as them.
     *
     * @return array{0: \Tests\Fixtures\Identities\TestUser, 1: \SineMacula\Laravel\Mfa\Models\Factor}
     */
    private function enrollEmail(): array
    {
        $user = TestUser::create([
            'email'       => 'email-mfa@example.test',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        /** @var \SineMacula\Laravel\Mfa\Models\Factor $factor */
        $factor = Factor::create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'email',
            'destination'          => $user->email,
        ]);

        return [$user, $factor];
    }

    /**
     * Enrol a fresh test user with an SMS factor and authenticate as them.
     *
     * @param  string  $phone
     * @return array{0: \Tests\Fixtures\Identities\TestUser, 1: \SineMacula\Laravel\Mfa\Models\Factor}
     */
    private function enrollSms(string $phone): array
    {
        $user = TestUser::create([
            'email'       => 'sms-mfa@example.test',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        /** @var \SineMacula\Laravel\Mfa\Models\Factor $factor */
        $factor = Factor::create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'sms',
            'destination'          => $phone,
        ]);

        return [$user, $factor];
    }
}
