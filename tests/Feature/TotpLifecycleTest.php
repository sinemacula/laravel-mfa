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
 * Exercises the full enrolment → challenge → verify flow against a real Factor
 * row, a real Google2FA instance, and the default session-backed verification
 * store. Assertions cover the events fired, the factor state transitions, and
 * the store updates.
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
     * Test successful TOTP verification returns true.
     *
     * @return void
     */
    public function testSuccessfulVerificationReturnsTrue(): void
    {
        [, $factor, $code] = $this->enrolTotp();

        self::assertTrue(Mfa::verify('totp', $factor, $code));
    }

    /**
     * Test successful TOTP verification marks the verification store.
     *
     * @return void
     */
    public function testSuccessfulVerificationMarksVerificationStore(): void
    {
        [, $factor, $code] = $this->enrolTotp();

        Mfa::verify('totp', $factor, $code);

        self::assertTrue(Mfa::hasEverVerified());
        self::assertFalse(Mfa::hasExpired());
    }

    /**
     * Test successful TOTP verification stamps the factor verified_at.
     *
     * @return void
     */
    public function testSuccessfulVerificationStampsFactorVerifiedAt(): void
    {
        [, $factor, $code] = $this->enrolTotp();

        Mfa::verify('totp', $factor, $code);

        $factor->refresh();

        self::assertNotNull($factor->getVerifiedAt());
        self::assertSame(0, $factor->getAttempts());
    }

    /**
     * Test successful TOTP verification dispatches MfaVerified event.
     *
     * @return void
     */
    public function testSuccessfulVerificationDispatchesVerifiedEvent(): void
    {
        Event::fake([MfaVerified::class]);

        [$user, $factor, $code] = $this->enrolTotp();

        Mfa::verify('totp', $factor, $code);

        Event::assertDispatched(MfaVerified::class, static function (MfaVerified $event) use ($user, $factor): bool {
            $identity = $event->identity;

            return $identity instanceof TestUser
                && $identity->getKey()                   === $user->getKey()
                && $event->factor->getFactorIdentifier() === $factor->getFactorIdentifier()
                && $event->driver                        === 'totp';
        });
    }

    /**
     * A failed TOTP verification must increment the attempt counter and
     * dispatch a `CodeInvalid` failure event.
     *
     * @return void
     */
    public function testFailedVerificationIncrementsAttemptsAndFiresFailureEvent(): void
    {
        Event::fake([MfaVerificationFailed::class]);

        [, $factor] = $this->enrolTotp();

        $verified = Mfa::verify('totp', $factor, self::WRONG_CODE);

        self::assertFalse($verified);

        $factor->refresh();
        self::assertSame(1, $factor->getAttempts());
        self::assertNull($factor->getVerifiedAt());

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::CODE_INVALID,
        );
    }

    /**
     * Test crossing max_attempts records the configured attempts count.
     *
     * @return void
     */
    public function testThresholdCrossingRecordsConfiguredAttemptsCount(): void
    {
        $factor = $this->enrolAndBurnAttempts();

        self::assertSame(3, $factor->getAttempts());
    }

    /**
     * Test crossing max_attempts stamps a future locked_until.
     *
     * @return void
     */
    public function testThresholdCrossingStampsFutureLockedUntil(): void
    {
        $factor = $this->enrolAndBurnAttempts();

        self::assertNotNull($factor->getLockedUntil());
        self::assertTrue($factor->isLocked());
    }

    /**
     * Test verifying after lockout returns false.
     *
     * @return void
     */
    public function testVerifyingAfterLockoutReturnsFalse(): void
    {
        $factor = $this->enrolAndBurnAttempts();

        self::assertFalse(Mfa::verify('totp', $factor, self::WRONG_CODE));
    }

    /**
     * Test verifying after lockout dispatches FactorLocked failure.
     *
     * @return void
     */
    public function testVerifyingAfterLockoutDispatchesFactorLockedFailure(): void
    {
        $factor = $this->enrolAndBurnAttempts();

        Event::fake([MfaVerificationFailed::class]);

        Mfa::verify('totp', $factor, self::WRONG_CODE);

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::FACTOR_LOCKED,
        );
    }

    /**
     * Test challenge preserves the attempts count after lockout.
     *
     * `challenge()` must NOT clear an active TOTP lockout — TOTP has no
     * per-challenge secret to rotate, so wiping the attempt counter on every
     * "start MFA" call would let any consumer-side resend endpoint act as a
     * free unlock against the configured `max_attempts` defence.
     *
     * @return void
     */
    public function testChallengePreservesAttemptsAfterLockout(): void
    {
        $factor = $this->enrolAndBurnAttempts();

        Mfa::challenge('totp', $factor);

        $factor->refresh();

        self::assertSame(3, $factor->getAttempts());
    }

    /**
     * Test challenge preserves the locked_until timestamp after lockout.
     *
     * @return void
     */
    public function testChallengePreservesLockedUntilTimestampAfterLockout(): void
    {
        $factor = $this->enrolAndBurnAttempts();

        $lockedUntilBefore = $factor->getLockedUntil();
        self::assertNotNull($lockedUntilBefore);

        Mfa::challenge('totp', $factor);

        $factor->refresh();

        $lockedUntilAfter = $factor->getLockedUntil();
        self::assertNotNull($lockedUntilAfter);
        self::assertSame(
            $lockedUntilBefore->getTimestamp(),
            $lockedUntilAfter->getTimestamp(),
        );
    }

    /**
     * Test challenge keeps the factor locked after lockout.
     *
     * @return void
     */
    public function testChallengeKeepsFactorLockedAfterLockout(): void
    {
        $factor = $this->enrolAndBurnAttempts();

        Mfa::challenge('totp', $factor);

        $factor->refresh();

        self::assertTrue($factor->isLocked());
    }

    /**
     * Test challenge dispatches MfaChallengeIssued even when locked.
     *
     * @return void
     */
    public function testChallengeDispatchesEventEvenWhenLocked(): void
    {
        $factor = $this->enrolAndBurnAttempts();

        Event::fake([MfaChallengeIssued::class]);

        Mfa::challenge('totp', $factor);

        Event::assertDispatched(MfaChallengeIssued::class);
    }

    /**
     * Backup-code factors share the no-rotation property: their secret is
     * pre-issued at enrolment, so `challenge()` must also preserve any active
     * lockout. This catches the same bypass shape against the recovery factor.
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
     * Enrol a TOTP factor and burn through the configured max-attempts so the
     * factor is in a locked-out state when returned.
     *
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function enrolAndBurnAttempts(): Factor
    {
        [, $factor] = $this->enrolTotp();

        config()->set('mfa.drivers.totp.max_attempts', 3);

        Mfa::verify('totp', $factor, self::WRONG_CODE);
        Mfa::verify('totp', $factor->refresh(), self::WRONG_CODE);
        Mfa::verify('totp', $factor->refresh(), self::WRONG_CODE);

        $factor->refresh();

        return $factor;
    }

    /**
     * Enrol a TOTP factor for a freshly created test user and return the [user,
     * factor, current-code] triple.
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
