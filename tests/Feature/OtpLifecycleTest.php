<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Mail;
use SineMacula\Laravel\Mfa\Contracts\SmsGateway;
use SineMacula\Laravel\Mfa\Enums\MfaVerificationFailureReason;
use SineMacula\Laravel\Mfa\Events\MfaChallengeIssued;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;
use SineMacula\Laravel\Mfa\Events\MfaVerified;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Gateways\FakeSmsGateway;
use SineMacula\Laravel\Mfa\Mail\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * End-to-end lifecycle for the OTP-delivery drivers (email + SMS).
 *
 * Covers challenge dispatch (via Mail::fake / FakeSmsGateway), code
 * persistence, successful verification, the "wrong code" and "expired code"
 * branches, and event emissions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class OtpLifecycleTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Test email challenge sends the mailable to the recipient.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEmailChallengeSendsMailableToRecipient(): void
    {
        Mail::fake();

        [$user, $factor] = $this->enrolEmail();

        Mfa::challenge('email', $factor);

        Mail::assertSent(MfaCodeMessage::class, static fn (MfaCodeMessage $mail): bool => $mail->hasTo($user->email));
    }

    /**
     * Test email challenge dispatches the MfaChallengeIssued event.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEmailChallengeDispatchesChallengeIssuedEvent(): void
    {
        Mail::fake();
        Event::fake([MfaChallengeIssued::class]);

        [, $factor] = $this->enrolEmail();

        Mfa::challenge('email', $factor);

        Event::assertDispatched(MfaChallengeIssued::class);
    }

    /**
     * Test email challenge persists a code on the factor.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEmailChallengePersistsCodeOnFactor(): void
    {
        Mail::fake();

        [, $factor] = $this->enrolEmail();

        Mfa::challenge('email', $factor);

        $factor->refresh();

        self::assertNotNull($factor->getCode());
    }

    /**
     * Test verifying the persisted email code returns true.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifyingPersistedEmailCodeReturnsTrue(): void
    {
        Mail::fake();

        [, $factor] = $this->enrolEmail();

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
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifyingPersistedEmailCodeMarksVerificationStore(): void
    {
        Mail::fake();

        [, $factor] = $this->enrolEmail();

        Mfa::challenge('email', $factor);
        $factor->refresh();

        Mfa::verify('email', $factor, $factor->getCode() ?? '');

        self::assertTrue(Mfa::hasEverVerified());
    }

    /**
     * Test verifying the persisted email code dispatches MfaVerified.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifyingPersistedEmailCodeDispatchesVerifiedEvent(): void
    {
        Mail::fake();
        Event::fake([MfaVerified::class]);

        [, $factor] = $this->enrolEmail();

        Mfa::challenge('email', $factor);
        $factor->refresh();

        Mfa::verify('email', $factor, $factor->getCode() ?? '');

        Event::assertDispatched(MfaVerified::class);
    }

    /**
     * Test verifying the persisted email code clears code and expiry.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifyingPersistedEmailCodeClearsCodeAndExpiry(): void
    {
        Mail::fake();

        [, $factor] = $this->enrolEmail();

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
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testSmsChallengeIssuedAndVerifiedViaBoundGateway(): void
    {
        $gateway = new FakeSmsGateway;
        $this->container()->instance(SmsGateway::class, $gateway);

        Event::fake([MfaChallengeIssued::class, MfaVerified::class]);

        [, $factor] = $this->enrolSms('+441234567890');

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
     * verification and dispatch a `CodeInvalid` failure event.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEmailVerificationFailsWithWrongCode(): void
    {
        Mail::fake();
        Event::fake([MfaVerificationFailed::class]);

        [, $factor] = $this->enrolEmail();
        Mfa::challenge('email', $factor);
        $factor->refresh();

        $wrongCodeAttempt = Mfa::verify('email', $factor, '000000');

        self::assertFalse($wrongCodeAttempt);

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::CODE_INVALID,
        );
    }

    /**
     * A code whose `expires_at` has passed must be rejected with a
     * `CodeExpired` failure event even when the submitted code matches the
     * stored value.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testExpiredCodeIsRejected(): void
    {
        Mail::fake();

        [, $factor] = $this->enrolEmail();
        Mfa::challenge('email', $factor);
        $factor->refresh();

        // Force the code to be expired by rewinding expires_at.
        $factor->forceFill(['expires_at' => now()->subMinute()])->save();

        Event::fake([MfaVerificationFailed::class]);

        $expiredCodeAttempt = Mfa::verify('email', $factor, $factor->getCode() ?? '');

        self::assertFalse($expiredCodeAttempt);

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::CODE_EXPIRED,
        );
    }

    /**
     * The OTP driver path must reset the attempt counter when it issues a fresh
     * code — paired with a transport hop the user has to receive, so an
     * attacker cannot use it as a free unlock the way an unconditional
     * manager-side reset would have allowed.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEmailChallengeResetsAttemptsAlongsideFreshCode(): void
    {
        Mail::fake();

        [, $factor] = $this->enrolEmail();

        // Stage a previously-locked-out factor: max attempts burned and a
        // future lockout still active.
        $factor->forceFill([
            'attempts'     => 3,
            'locked_until' => now()->addMinutes(15),
        ])->save();

        self::assertTrue($factor->isLocked());

        Mfa::challenge('email', $factor);

        $factor->refresh();

        // OTP rotation closes the bypass risk: a brand-new code lands in the
        // user's inbox alongside the cleared lockout, so an attacker without
        // inbox access cannot exploit the reset.
        self::assertSame(0, $factor->getAttempts());
        self::assertNull($factor->getLockedUntil());
        self::assertFalse($factor->isLocked());
        self::assertNotNull($factor->getCode());
    }

    /**
     * Enrol a fresh test user with an email factor and authenticate as them.
     *
     * @return array{0: \Tests\Fixtures\TestUser, 1: \SineMacula\Laravel\Mfa\Models\Factor}
     */
    private function enrolEmail(): array
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
            'driver'               => 'email',
            'recipient'            => $user->email,
        ]);

        return [$user, $factor];
    }

    /**
     * Enrol a fresh test user with an SMS factor and authenticate as them.
     *
     * @param  string  $phone
     * @return array{0: \Tests\Fixtures\TestUser, 1: \SineMacula\Laravel\Mfa\Models\Factor}
     */
    private function enrolSms(string $phone): array
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
            'driver'               => 'sms',
            'recipient'            => $phone,
        ]);

        return [$user, $factor];
    }
}
