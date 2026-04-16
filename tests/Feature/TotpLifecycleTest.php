<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use PragmaRX\Google2FA\Google2FA;
use SineMacula\Laravel\Mfa\Enums\MfaVerificationFailureReason;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;
use SineMacula\Laravel\Mfa\Events\MfaVerified;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * End-to-end TOTP lifecycle feature tests.
 *
 * Exercises the full enrolment → challenge → verify flow against a
 * real Factor row, a real Google2FA instance, and the default
 * session-backed verification store. Assertions cover the events
 * fired, the factor state transitions, and the store updates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class TotpLifecycleTest extends TestCase
{
    use RefreshDatabase;

    public function testSuccessfulVerificationMarksStoreAndFactor(): void
    {
        Event::fake([MfaVerified::class]);

        [$user, $factor, $code] = $this->enrolTotp();

        $result = Mfa::verify('totp', $factor, $code);

        self::assertTrue($result);
        self::assertTrue(Mfa::hasEverVerified());
        self::assertFalse(Mfa::hasExpired());

        $factor->refresh();
        self::assertNotNull($factor->getVerifiedAt());
        self::assertSame(0, $factor->getAttempts());

        Event::assertDispatched(MfaVerified::class, static fn (MfaVerified $event): bool => $event->identity->is($user)
                && $event->factor->getFactorIdentifier() === $factor->getFactorIdentifier()
                && $event->driver                        === 'totp');
    }

    public function testFailedVerificationIncrementsAttemptsAndFiresFailureEvent(): void
    {
        Event::fake([MfaVerificationFailed::class]);

        [, $factor] = $this->enrolTotp();

        $result = Mfa::verify('totp', $factor, '000000');

        self::assertFalse($result);

        $factor->refresh();
        self::assertSame(1, $factor->getAttempts());
        self::assertNull($factor->getVerifiedAt());

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::CodeInvalid,
        );
    }

    public function testThresholdCrossingAppliesLockout(): void
    {
        [, $factor] = $this->enrolTotp();

        // TOTP max_attempts is not configured by default; mimic an OTP
        // driver's config by inlining the expectation. The shipped
        // email / sms defaults are 3.
        $this->app['config']->set('mfa.drivers.totp.max_attempts', 3);

        Mfa::verify('totp', $factor, '000000');
        Mfa::verify('totp', $factor->refresh(), '000000');
        Mfa::verify('totp', $factor->refresh(), '000000');

        $factor->refresh();

        self::assertSame(3, $factor->getAttempts());
        self::assertNotNull($factor->getLockedUntil());
        self::assertTrue($factor->isLocked());

        Event::fake([MfaVerificationFailed::class]);

        $result = Mfa::verify('totp', $factor, '000000');

        self::assertFalse($result);

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::FactorLocked,
        );
    }

    /**
     * Enrol a TOTP factor for a freshly created test user and return
     * the [user, factor, current-code] triple.
     *
     * @return array{0: TestUser, 1: Factor, 2: string}
     */
    private function enrolTotp(): array
    {
        $user = TestUser::create([
            'email'       => 'totp@example.test',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        $google = new Google2FA;
        $secret = $google->generateSecretKey();

        /** @var Factor $factor */
        $factor = Factor::create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->getKey(),
            'driver'               => 'totp',
            'secret'               => $secret,
        ]);

        return [$user, $factor, $google->getCurrentOtp($secret)];
    }
}
