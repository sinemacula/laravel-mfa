<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\AttemptKeys;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Attempts\AttemptStore;
use SineMacula\Laravel\Mfa\Attempts\Lockout;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Events\MfaChallengeIssued;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;
use SineMacula\Laravel\Mfa\Events\MfaVerified;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Drivers\AuthenticatorApp;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * End-to-end TOTP lifecycle feature tests.
 *
 * Exercises the full enrolment → challenge → verify flow against a real Factor
 * row, the shipped TOTP driver, and the default session-backed verification
 * store. Assertions cover the events fired, the factor state transitions, the
 * store updates, and the single use of each time step. Time is frozen in the
 * middle of a step, so no assertion straddles a step boundary.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
#[CoversClass(TotpDriver::class)]
final class TotpLifecycleTest extends TestCase
{
    use RefreshDatabase;

    /** @var string A code matching no step of the window at the frozen time. */
    private const string WRONG_CODE = '000000';

    /** @var int The frozen time: 15 seconds into time step 60000000. */
    private const int NOW = 1800000015;

    /**
     * Freeze time in the middle of a step.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->travelTo(CarbonImmutable::createFromTimestamp(self::NOW));
    }

    /**
     * A successful verification records the step of its code on the factor's
     * row.
     *
     * @return void
     */
    public function testSuccessfulVerificationRecordsTheAcceptedStep(): void
    {
        [, $factor, $code] = $this->enrollTotp();

        Mfa::verify('totp', $factor, $code);

        self::assertSame(60000000, $factor->refresh()->getLastAcceptedStep());
    }

    /**
     * The same code is refused at a second verification, as an invalid code.
     *
     * @return void
     */
    public function testTheSameCodeIsRefusedAtTheSecondVerification(): void
    {
        [, $factor, $code] = $this->enrollTotp();

        self::assertTrue(Mfa::verify('totp', $factor, $code));

        Event::fake([MfaVerificationFailed::class]);

        self::assertFalse(Mfa::verify('totp', $factor->refresh(), $code));

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === FailureReason::INVALID_CODE,
        );
    }

    /**
     * Once a code is accepted, a code for an earlier step of the window is
     * refused, and a later one still passes.
     *
     * @return void
     */
    public function testACodeForAnEarlierStepIsRefusedAfterALaterOne(): void
    {
        [, $factor] = $this->enrollTotp();

        self::assertTrue(Mfa::verify('totp', $factor, AuthenticatorApp::code($factor)));
        self::assertFalse(Mfa::verify('totp', $factor->refresh(), AuthenticatorApp::code($factor, -1)));
        self::assertTrue(Mfa::verify('totp', $factor->refresh(), AuthenticatorApp::code($factor, 1)));
    }

    /**
     * Two copies of the factor, read before either verifies, cannot both pass
     * with one code.
     *
     * @return void
     */
    public function testTwoCopiesOfTheFactorCannotBothPassWithOneCode(): void
    {
        [, $factor, $code] = $this->enrollTotp();

        $copy = Factor::query()->findOrFail($factor->id);

        self::assertTrue(Mfa::verify('totp', $factor, $code));
        self::assertFalse(Mfa::verify('totp', $copy, $code));
    }

    /**
     * The code that confirmed a pending factor is refused at the factor's next
     * verification.
     *
     * @return void
     */
    public function testTheConfirmingCodeIsRefusedAtTheNextVerification(): void
    {
        [, $factor, $code] = $this->enrollTotp();

        $driver = Mfa::driver('totp');

        self::assertInstanceOf(TotpDriver::class, $driver);
        self::assertTrue($driver->confirm($factor, $code));
        self::assertSame(60000000, $factor->refresh()->getLastAcceptedStep());
        self::assertFalse(Mfa::verify('totp', $factor, $code));
        self::assertTrue(Mfa::verify('totp', $factor->refresh(), AuthenticatorApp::code($factor, 1)));
    }

    /**
     * Test successful TOTP verification returns true.
     *
     * @return void
     */
    public function testSuccessfulVerificationReturnsTrue(): void
    {
        [, $factor, $code] = $this->enrollTotp();

        self::assertTrue(Mfa::verify('totp', $factor, $code));
    }

    /**
     * Test successful TOTP verification marks the verification store.
     *
     * @return void
     */
    public function testSuccessfulVerificationMarksVerificationStore(): void
    {
        [, $factor, $code] = $this->enrollTotp();

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
        [, $factor, $code] = $this->enrollTotp();

        Mfa::verify('totp', $factor, $code);

        $factor->refresh();

        self::assertNotNull($factor->getVerifiedAt());
        self::assertSame(0, $factor->getConsecutiveFailures());
    }

    /**
     * Test successful TOTP verification dispatches MfaVerified event.
     *
     * @return void
     */
    public function testSuccessfulVerificationDispatchesVerifiedEvent(): void
    {
        Event::fake([MfaVerified::class]);

        [$user, $factor, $code] = $this->enrollTotp();

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
     * A failed TOTP verification must count a failure in a row and dispatch an
     * `invalid_code` failure event.
     *
     * @return void
     */
    public function testFailedVerificationIncrementsAttemptsAndFiresFailureEvent(): void
    {
        Event::fake([MfaVerificationFailed::class]);

        [, $factor] = $this->enrollTotp();

        $verified = Mfa::verify('totp', $factor, self::WRONG_CODE);

        self::assertFalse($verified);

        $factor->refresh();
        self::assertSame(1, $factor->getConsecutiveFailures());
        self::assertNull($factor->getVerifiedAt());

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === FailureReason::INVALID_CODE,
        );
    }

    /**
     * Test crossing `mfa.attempts.factor_limit` records the configured failures
     * in a row.
     *
     * @return void
     */
    public function testThresholdCrossingRecordsConfiguredAttemptsCount(): void
    {
        $factor = $this->enrollAndBurnAttempts();

        self::assertSame(3, $factor->getConsecutiveFailures());
    }

    /**
     * Test crossing `mfa.attempts.factor_limit` locks the factor until a future
     * time.
     *
     * @return void
     */
    public function testThresholdCrossingLocksTheFactorUntilAFutureTime(): void
    {
        $factor = $this->enrollAndBurnAttempts();

        $lockout = $this->lockoutOf($factor);

        self::assertNotNull($lockout);
        self::assertSame(AttemptScope::FACTOR, $lockout->scope);
        self::assertTrue($lockout->until?->isFuture());
    }

    /**
     * Test verifying after lockout returns false.
     *
     * @return void
     */
    public function testVerifyingAfterLockoutReturnsFalse(): void
    {
        $factor = $this->enrollAndBurnAttempts();

        self::assertFalse(Mfa::verify('totp', $factor, self::WRONG_CODE));
    }

    /**
     * Test verifying after lockout dispatches a locked failure.
     *
     * @return void
     */
    public function testVerifyingAfterLockoutDispatchesLockedFailure(): void
    {
        $factor = $this->enrollAndBurnAttempts();

        Event::fake([MfaVerificationFailed::class]);

        Mfa::verify('totp', $factor, self::WRONG_CODE);

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === FailureReason::LOCKED,
        );
    }

    /**
     * Test challenge preserves the failures in a row after lockout.
     *
     * `challenge()` must NOT clear an active lockout: wiping the count on every
     * "start MFA" call would let any consumer-side resend endpoint act as a
     * free unlock against the configured `mfa.attempts.factor_limit` defence.
     *
     * @return void
     */
    public function testChallengePreservesAttemptsAfterLockout(): void
    {
        $factor = $this->enrollAndBurnAttempts();

        Mfa::challenge('totp', $factor);

        $factor->refresh();

        self::assertSame(3, $factor->getConsecutiveFailures());
    }

    /**
     * Test challenge preserves the time the lockout ends.
     *
     * @return void
     */
    public function testChallengePreservesTheLockoutEndAfterLockout(): void
    {
        $factor = $this->enrollAndBurnAttempts();

        $lockedUntilBefore = $this->lockoutOf($factor)?->until;
        self::assertNotNull($lockedUntilBefore);

        Mfa::challenge('totp', $factor);

        $lockedUntilAfter = $this->lockoutOf($factor)?->until;
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
        $factor = $this->enrollAndBurnAttempts();

        Mfa::challenge('totp', $factor);

        self::assertNotNull($this->lockoutOf($factor));
    }

    /**
     * Test challenge dispatches MfaChallengeIssued even when locked.
     *
     * @return void
     */
    public function testChallengeDispatchesEventEvenWhenLocked(): void
    {
        $factor = $this->enrollAndBurnAttempts();

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
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
            'type'                 => 'backup_code',
            'secret'               => hash('sha256', 'PLAIN12345'),
            'consecutive_failures' => 5,
        ]);

        $this->container()->make(AttemptStore::class)->hold(
            $this->container()->make(AttemptKeys::class)->factor($factor->id),
            AttemptScope::FACTOR,
            5,
            Carbon::now()->addMinutes(15)->getTimestamp(),
        );

        self::assertNotNull($this->lockoutOf($factor));

        Mfa::challenge('backup_code', $factor);

        $factor->refresh();

        self::assertSame(5, $factor->getConsecutiveFailures());
        self::assertNotNull($this->lockoutOf($factor));
    }

    /**
     * Enrol a TOTP factor for a freshly created test user and return the [user,
     * factor, current-code] triple.
     *
     * @return array{0: \Tests\Fixtures\Identities\TestUser, 1: \SineMacula\Laravel\Mfa\Models\Factor, 2: string}
     */
    private function enrollTotp(): array
    {
        $user = TestUser::create([
            'email'       => 'totp@example.test',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        /** @var \SineMacula\Laravel\Mfa\Models\Factor $factor */
        $factor = Factor::create([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
        ]);

        return [$user, $factor, AuthenticatorApp::code($factor)];
    }

    /**
     * The lockout the factor's owner's attempts against it are refused by now.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return ?\SineMacula\Laravel\Mfa\Attempts\Lockout
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function lockoutOf(Factor $factor): ?Lockout
    {
        $user = TestUser::query()->findOrFail($factor->authenticatable_id);

        return $this->container()->make(AttemptService::class)->lockout($user, $factor);
    }

    /**
     * Enrol a TOTP factor and burn through the configured max-attempts so the
     * factor is in a locked-out state when returned.
     *
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function enrollAndBurnAttempts(): Factor
    {
        [, $factor] = $this->enrollTotp();

        config()->set('mfa.attempts.factor_limit', 3);

        Mfa::verify('totp', $factor, self::WRONG_CODE);
        Mfa::verify('totp', $factor->refresh(), self::WRONG_CODE);
        Mfa::verify('totp', $factor->refresh(), self::WRONG_CODE);

        $factor->refresh();

        return $factor;
    }
}
