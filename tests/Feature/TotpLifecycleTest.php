<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Carbon\Carbon;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use PragmaRX\Google2FA\Google2FA;
use SineMacula\Laravel\Mfa\Enums\MfaVerificationFailureReason;
use SineMacula\Laravel\Mfa\Events\MfaChallengeIssued;
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

    /** @var string A code that is astronomically unlikely to match the current TOTP for any freshly generated secret. */
    private const string WRONG_CODE = '000000';

    /**
     * A successful TOTP verification must update both the
     * verification store and the factor row, and dispatch the
     * `MfaVerified` event with the matching identity / driver /
     * factor.
     *
     * @return void
     */
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

        Event::assertDispatched(MfaVerified::class, static function (MfaVerified $event) use ($user, $factor): bool {
            $identity = $event->identity;

            return $identity instanceof TestUser
                && $identity->getKey()                   === $user->getKey()
                && $event->factor->getFactorIdentifier() === $factor->getFactorIdentifier()
                && $event->driver                        === 'totp';
        });
    }

    /**
     * A failed TOTP verification must increment the attempt counter
     * and dispatch a `CodeInvalid` failure event.
     *
     * @return void
     */
    public function testFailedVerificationIncrementsAttemptsAndFiresFailureEvent(): void
    {
        Event::fake([MfaVerificationFailed::class]);

        [, $factor] = $this->enrolTotp();

        $result = Mfa::verify('totp', $factor, self::WRONG_CODE);

        self::assertFalse($result);

        $factor->refresh();
        self::assertSame(1, $factor->getAttempts());
        self::assertNull($factor->getVerifiedAt());

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::CodeInvalid,
        );
    }

    /**
     * Crossing the configured `max_attempts` threshold must lock the
     * factor; subsequent verifies must short-circuit with a
     * `FactorLocked` failure event.
     *
     * @return void
     */
    public function testThresholdCrossingAppliesLockout(): void
    {
        [, $factor] = $this->enrolTotp();

        // TOTP max_attempts is not configured by default; mimic an OTP
        // driver's config by inlining the expectation. The shipped
        // email / sms defaults are 3.
        config()->set('mfa.drivers.totp.max_attempts', 3);

        Mfa::verify('totp', $factor, self::WRONG_CODE);
        Mfa::verify('totp', $factor->refresh(), self::WRONG_CODE);
        Mfa::verify('totp', $factor->refresh(), self::WRONG_CODE);

        $factor->refresh();

        self::assertSame(3, $factor->getAttempts());
        self::assertNotNull($factor->getLockedUntil());
        self::assertTrue($factor->isLocked());

        Event::fake([MfaVerificationFailed::class]);

        $result = Mfa::verify('totp', $factor, self::WRONG_CODE);

        self::assertFalse($result);

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::FactorLocked,
        );
    }

    /**
     * `challenge()` must NOT clear an active TOTP lockout — TOTP has
     * no per-challenge secret to rotate, so wiping the attempt counter
     * on every "start MFA" call would let any consumer-side resend
     * endpoint act as a free unlock against the configured
     * `max_attempts` defence.
     *
     * @return void
     */
    public function testChallengePreservesTotpLockoutAcrossInvocations(): void
    {
        [, $factor] = $this->enrolTotp();

        config()->set('mfa.drivers.totp.max_attempts', 3);

        // Burn through `max_attempts` to force the lockout.
        Mfa::verify('totp', $factor, self::WRONG_CODE);
        Mfa::verify('totp', $factor->refresh(), self::WRONG_CODE);
        Mfa::verify('totp', $factor->refresh(), self::WRONG_CODE);

        $factor->refresh();

        $lockedUntilBefore = $factor->getLockedUntil();
        self::assertNotNull($lockedUntilBefore);
        self::assertTrue($factor->isLocked());

        Event::fake([MfaChallengeIssued::class]);

        Mfa::challenge('totp', $factor);

        $factor->refresh();

        // The challenge must complete (TOTP has nothing to issue) but
        // the lockout state survives intact.
        self::assertSame(3, $factor->getAttempts());

        $lockedUntilAfter = $factor->getLockedUntil();
        self::assertNotNull($lockedUntilAfter);
        self::assertTrue($factor->isLocked());
        self::assertSame(
            $lockedUntilBefore->getTimestamp(),
            $lockedUntilAfter->getTimestamp(),
        );

        Event::assertDispatched(MfaChallengeIssued::class);
    }

    /**
     * Backup-code factors share the no-rotation property: their secret
     * is pre-issued at enrolment, so `challenge()` must also preserve
     * any active lockout. This catches the same bypass shape against
     * the recovery factor.
     *
     * @return void
     */
    public function testChallengePreservesBackupCodeLockoutAcrossInvocations(): void
    {
        $user = TestUser::create([
            'email'       => 'backup-lockout@example.test',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        /** @var \SineMacula\Laravel\Mfa\Models\Factor $factor */
        $factor = Factor::create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'driver'               => 'backup_code',
            'secret'               => hash('sha256', 'PLAIN12345'),
            'attempts'             => 5,
            'locked_until'         => Carbon::now()->addMinutes(15),
        ]);

        self::assertTrue($factor->isLocked());

        Mfa::challenge('backup_code', $factor);

        $factor->refresh();

        self::assertSame(5, $factor->getAttempts());
        self::assertTrue($factor->isLocked());
    }

    /**
     * Enrol a TOTP factor for a freshly created test user and return
     * the [user, factor, current-code] triple.
     *
     * @return array{0: \Tests\Fixtures\TestUser, 1: \SineMacula\Laravel\Mfa\Models\Factor, 2: string}
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

        /** @var \SineMacula\Laravel\Mfa\Models\Factor $factor */
        $factor = Factor::create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'driver'               => 'totp',
            'secret'               => $secret,
        ]);

        return [$user, $factor, $google->getCurrentOtp($secret)];
    }
}
