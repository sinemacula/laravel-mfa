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
 * persistence, successful verification, the "wrong code" and "expired
 * code" branches, and event emissions.
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
     * Issuing an email challenge should send the Mailable, persist
     * the code, dispatch the challenge event, and then verify
     * successfully against the persisted code.
     *
     * @return void
     */
    public function testEmailChallengeIssuedAndVerified(): void
    {
        Mail::fake();
        Event::fake([MfaChallengeIssued::class, MfaVerified::class]);

        [$user, $factor] = $this->enrolEmail();

        Mfa::challenge('email', $factor);

        $factor->refresh();

        Mail::assertSent(MfaCodeMessage::class, static fn (MfaCodeMessage $mail): bool => $mail->hasTo($user->email));
        Event::assertDispatched(MfaChallengeIssued::class);

        $code = $factor->getCode();
        self::assertNotNull($code);

        $result = Mfa::verify('email', $factor, $code);

        self::assertTrue($result);
        self::assertTrue(Mfa::hasEverVerified());

        Event::assertDispatched(MfaVerified::class);

        $factor->refresh();
        self::assertNull($factor->getCode());
        self::assertNull($factor->getExpiresAt());
    }

    /**
     * Issuing an SMS challenge through the bound `FakeSmsGateway`
     * should record the outbound message and verify successfully
     * against the persisted code.
     *
     * @return void
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

        $result = Mfa::verify('sms', $factor, $factor->getCode() ?? '');

        self::assertTrue($result);
    }

    /**
     * A submitted email code that does not match the persisted code
     * should fail verification and dispatch a `CodeInvalid` failure
     * event.
     *
     * @return void
     */
    public function testEmailVerificationFailsWithWrongCode(): void
    {
        Mail::fake();
        Event::fake([MfaVerificationFailed::class]);

        [, $factor] = $this->enrolEmail();
        Mfa::challenge('email', $factor);
        $factor->refresh();

        $result = Mfa::verify('email', $factor, '000000');

        self::assertFalse($result);

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::CodeInvalid,
        );
    }

    /**
     * A code whose `expires_at` has passed must be rejected with a
     * `CodeExpired` failure event even when the submitted code
     * matches the stored value.
     *
     * @return void
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

        $result = Mfa::verify('email', $factor, $factor->getCode() ?? '');

        self::assertFalse($result);

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::CodeExpired,
        );
    }

    /**
     * Enrol a fresh test user with an email factor and authenticate
     * as them.
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
