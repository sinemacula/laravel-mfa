<?php

declare(strict_types = 1);

namespace Tests\Unit\Verification;

use Carbon\Carbon;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Events\MfaChallengeIssued;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;
use SineMacula\Laravel\Mfa\Events\MfaVerified;
use SineMacula\Laravel\Mfa\Exceptions\FactorDriverMismatchException;
use SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Verification\VerificationService;
use Tests\Fixtures\InMemoryFactor;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * Tests for `VerificationService`: challenges and verification run only for the
 * current identity's own factor through its own driver, record the outcome on
 * the factor, lock it at the configured attempt limit, and report each outcome
 * with its event.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerificationService::class)]
final class VerificationServiceTest extends TestCase
{
    /** @var string The detail of a locked factor's failure. */
    private const string LOCKED = 'The factor is locked after too many failed attempts.';

    /** @var string The detail of a factor whose enrolment never completed. */
    private const string UNCONFIRMED = 'The factor has no pending code or secret, so its enrolment never completed.';

    /** @var string The detail of an expired pending code. */
    private const string EXPIRED = 'The pending code has expired.';

    /** @var string The detail of a pending code without an expiry. */
    private const string NO_EXPIRY = 'The pending code has no expiry, so no live code exists.';

    /** @var string The detail of a code that did not match. */
    private const string MISMATCH = 'The code did not match.';

    /**
     * Release the frozen clock and the Mockery expectations.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();
        \Mockery::close();

        parent::tearDown();
    }

    /**
     * A guest's challenge reaches no driver and reports nothing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAGuestsChallengeDoesNothing(): void
    {
        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldNotReceive('issueChallenge');

        $this->stubDriver($driver);

        Event::fake();

        $this->service()->challenge($this->manager(), 'totp', new InMemoryFactor);

        Event::assertNothingDispatched();
    }

    /**
     * A challenge runs the factor's driver and reports it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAChallengeRunsTheDriverAndReportsIt(): void
    {
        $user   = $this->signIn();
        $factor = new InMemoryFactor(authenticatable: $user);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('issueChallenge')->once()->with($factor);

        $this->stubDriver($driver);

        Event::fake();

        $this->service()->challenge($this->manager(), 'totp', $factor);

        Event::assertDispatched(
            MfaChallengeIssued::class,
            static fn (MfaChallengeIssued $event): bool => $event->identity === $user
                && $event->factor                                           === $factor
                && $event->driver                                           === 'totp',
        );
    }

    /**
     * A challenge through another driver than the factor's is refused before
     * the driver runs.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAChallengeThroughAnotherDriverIsRefused(): void
    {
        $user = $this->signIn();

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldNotReceive('issueChallenge');

        $this->stubDriver($driver);

        $this->expectException(FactorDriverMismatchException::class);

        $this->service()->challenge($this->manager(), 'totp', new InMemoryFactor(driver: 'email', authenticatable: $user));
    }

    /**
     * A challenge for another identity's factor is refused before the driver
     * runs.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAChallengeForAnotherIdentitysFactorIsRefused(): void
    {
        $this->signIn();

        $other = TestUser::query()->create(['email' => 'other@example.com']);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldNotReceive('issueChallenge');

        $this->stubDriver($driver);

        $this->expectException(FactorOwnershipMismatchException::class);

        $this->service()->challenge($this->manager(), 'totp', new InMemoryFactor(authenticatable: $other));
    }

    /**
     * A guest's verification fails without reaching the driver.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAGuestsVerificationFails(): void
    {
        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldNotReceive('verify');

        $this->stubDriver($driver);

        Event::fake();

        self::assertFalse($this->service()->verify($this->manager(), 'totp', new InMemoryFactor, '123456'));
        Event::assertNothingDispatched();
    }

    /**
     * A verification through another driver than the factor's is refused.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAVerificationThroughAnotherDriverIsRefused(): void
    {
        $user = $this->signIn();

        $this->stubDriver($this->driverAnswering(null));

        $this->expectException(FactorDriverMismatchException::class);

        $this->service()->verify($this->manager(), 'totp', new InMemoryFactor(driver: 'email', authenticatable: $user), '123456');
    }

    /**
     * A verification of another identity's factor is refused.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAVerificationOfAnotherIdentitysFactorIsRefused(): void
    {
        $this->signIn();

        $other = TestUser::query()->create(['email' => 'other@example.com']);

        $this->stubDriver($this->driverAnswering(null));

        $this->expectException(FactorOwnershipMismatchException::class);

        $this->service()->verify($this->manager(), 'totp', new InMemoryFactor(authenticatable: $other), '123456');
    }

    /**
     * A locked factor fails without reaching the driver, reported as locked.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testALockedFactorFailsWithoutReachingTheDriver(): void
    {
        $user   = $this->signIn();
        $factor = new InMemoryFactor(secret: 'secret', lockedUntil: Carbon::now()->addMinutes(5), authenticatable: $user);

        $this->stubDriver($this->driverAnswering(null));

        Event::fake();

        self::assertFalse($this->service()->verify($this->manager(), 'totp', $factor, '123456'));
        $this->assertFailedWith(FailureReason::LOCKED, self::LOCKED);
        Event::assertNotDispatched(MfaVerified::class);
    }

    /**
     * A valid code verifies an Eloquent factor: its attempts reset, its
     * verification is stamped and persisted, the identity's verification is
     * recorded, its cached factors cleared, and the success reported.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAValidCodeVerifiesAnEloquentFactor(): void
    {
        Carbon::setTestNow('2026-10-31 12:00:00');

        $user   = $this->signIn();
        $factor = $this->eloquentFactor($user, attempts: 2);

        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldReceive('markVerified')->once()->with($user);

        $this->container()->instance(MfaVerificationStore::class, $store);
        $this->stubDriver($this->driverAnswering(true));

        $factors = $this->container()->make(FactorService::class);

        self::assertCount(1, $factors->getFactors() ?? collect());

        $this->eloquentFactor($user);

        Event::fake();

        self::assertTrue($this->service()->verify($this->manager(), 'totp', $factor, '123456'));

        $factor->refresh();

        self::assertSame(0, $factor->getAttempts());
        self::assertTrue(Carbon::now()->equalTo($factor->getVerifiedAt()));
        self::assertCount(2, $factors->getFactors() ?? collect());
        Event::assertDispatched(
            MfaVerified::class,
            static fn (MfaVerified $event): bool => $event->identity === $user
                && $event->factor                                    === $factor
                && $event->driver                                    === 'totp',
        );
        Event::assertNotDispatched(MfaVerificationFailed::class);
    }

    /**
     * A valid code verifies a non-Eloquent factor without writing to it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAValidCodeVerifiesANonEloquentFactor(): void
    {
        $user   = $this->signIn();
        $factor = new InMemoryFactor(secret: 'secret', authenticatable: $user);

        $this->stubDriver($this->driverAnswering(true));

        Event::fake();

        self::assertTrue($this->service()->verify($this->manager(), 'totp', $factor, '123456'));
        self::assertSame(0, $factor->getAttempts());
        Event::assertDispatched(MfaVerified::class);
    }

    /**
     * An invalid code counts an attempt on the factor and persists it, below
     * the limit without a lockout.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnInvalidCodeCountsAnAttempt(): void
    {
        config()->set('mfa.drivers.totp.max_attempts', 3);

        $user   = $this->signIn();
        $factor = $this->eloquentFactor($user, attempts: 1);

        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldNotReceive('markVerified');

        $this->container()->instance(MfaVerificationStore::class, $store);
        $this->stubDriver($this->driverAnswering(false));

        Event::fake();

        self::assertFalse($this->service()->verify($this->manager(), 'totp', $factor, '000000'));

        $factor->refresh();

        self::assertSame(2, $factor->getAttempts());
        self::assertNull($factor->getLockedUntil());
        self::assertNull($factor->getVerifiedAt());
        Event::assertNotDispatched(MfaVerified::class);
        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->identity === $user
                && $event->factor                                              === $factor
                && $event->driver                                              === 'totp'
                && $event->reason                                              === FailureReason::INVALID_CODE
                && $event->detail                                              === self::MISMATCH,
        );
    }

    /**
     * Attempt limits, configured lockouts and the lockout each applies.
     *
     * @return iterable<string, array{int, ?int, int}>
     */
    public static function lockouts(): iterable
    {
        yield 'a limit of one, the default lockout' => [1, null, 15];
        yield 'a limit of three, a configured lockout' => [3, 5, 5];
    }

    /**
     * The attempt that reaches the driver's limit locks the factor for the
     * configured lockout.
     *
     * @param  int  $maxAttempts
     * @param  ?int  $lockoutMinutes
     * @param  int  $expectedMinutes
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('lockouts')]
    public function testTheAttemptReachingTheLimitLocksTheFactor(int $maxAttempts, ?int $lockoutMinutes, int $expectedMinutes): void
    {
        Carbon::setTestNow('2026-10-31 12:00:00');

        config()->set('mfa.drivers.totp.max_attempts', $maxAttempts);

        if ($lockoutMinutes !== null) {
            config()->set('mfa.lockout_minutes', $lockoutMinutes);
        } else {
            config()->offsetUnset('mfa.lockout_minutes');
        }

        $user   = $this->signIn();
        $factor = $this->eloquentFactor($user, attempts: $maxAttempts - 1);

        $this->stubDriver($this->driverAnswering(false));

        self::assertFalse($this->service()->verify($this->manager(), 'totp', $factor, '000000'));

        $factor->refresh();

        self::assertSame($maxAttempts, $factor->getAttempts());
        self::assertTrue(Carbon::now()->addMinutes($expectedMinutes)->equalTo($factor->getLockedUntil()));
    }

    /**
     * Attempt limits that never lock.
     *
     * @return iterable<string, array{mixed}>
     */
    public static function unlimitedAttempts(): iterable
    {
        yield 'no limit configured' => [null];
        yield 'a limit of zero' => [0];
        yield 'a malformed limit' => ['many'];
    }

    /**
     * Without a positive attempt limit the factor is never locked.
     *
     * @param  mixed  $maxAttempts
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('unlimitedAttempts')]
    public function testWithoutALimitTheFactorIsNeverLocked(mixed $maxAttempts): void
    {
        config()->set('mfa.drivers.totp', $maxAttempts === null ? [] : ['max_attempts' => $maxAttempts]);

        $user   = $this->signIn();
        $factor = $this->eloquentFactor($user, attempts: 5);

        $this->stubDriver($this->driverAnswering(false));

        self::assertFalse($this->service()->verify($this->manager(), 'totp', $factor, '000000'));

        $factor->refresh();

        self::assertSame(6, $factor->getAttempts());
        self::assertNull($factor->getLockedUntil());
    }

    /**
     * Factor states (pending code, secret, minutes until the code expires) and
     * the failure reason and detail each explains.
     *
     * @return iterable<string, array{?string, ?string, ?int, \SineMacula\Laravel\Mfa\Enums\FailureReason, string}>
     */
    public static function failureReasons(): iterable
    {
        yield 'no code and no secret' => [null, null, null, FailureReason::NOT_CONFIRMED, self::UNCONFIRMED];
        yield 'no code and no secret, past an expiry' => [null, null, -1, FailureReason::NOT_CONFIRMED, self::UNCONFIRMED];
        yield 'an expired code without a secret' => ['123456', null, -1, FailureReason::EXPIRED, self::EXPIRED];
        yield 'an expired code with a secret' => ['123456', 'secret', -1, FailureReason::EXPIRED, self::EXPIRED];
        yield 'a secret past an expiry' => [null, 'secret', -1, FailureReason::EXPIRED, self::EXPIRED];
        yield 'a code without an expiry' => ['123456', null, null, FailureReason::EXPIRED, self::NO_EXPIRY];
        yield 'a code with a secret and no expiry' => ['123456', 'secret', null, FailureReason::EXPIRED, self::NO_EXPIRY];
        yield 'a live code' => ['123456', 'secret', 5, FailureReason::INVALID_CODE, self::MISMATCH];
        yield 'a live code without a secret' => ['123456', null, 5, FailureReason::INVALID_CODE, self::MISMATCH];
        yield 'a secret without a code' => [null, 'secret', null, FailureReason::INVALID_CODE, self::MISMATCH];
        yield 'a secret with a future expiry' => [null, 'secret', 5, FailureReason::INVALID_CODE, self::MISMATCH];
    }

    /**
     * A failed verification is reported with the reason the factor's state
     * explains, and the detail that tells apart failures sharing a reason.
     *
     * @param  ?string  $code
     * @param  ?string  $secret
     * @param  ?int  $expiresInMinutes
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('failureReasons')]
    public function testAFailureIsReportedWithItsReason(?string $code, ?string $secret, ?int $expiresInMinutes, FailureReason $reason, string $detail): void
    {
        $user      = $this->signIn();
        $expiresAt = $expiresInMinutes === null ? null : Carbon::now()->addMinutes($expiresInMinutes);
        $factor    = new InMemoryFactor(secret: $secret, code: $code, expiresAt: $expiresAt, authenticatable: $user);

        $this->stubDriver($this->driverAnswering(false));

        Event::fake();

        self::assertFalse($this->service()->verify($this->manager(), 'totp', $factor, '000000'));
        $this->assertFailedWith($reason, $detail);
    }

    /**
     * Assert one failure was reported, with the given reason and detail.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @return void
     */
    private function assertFailedWith(FailureReason $reason, string $detail): void
    {
        Event::assertDispatchedTimes(MfaVerificationFailed::class, 1);
        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === $reason && $event->detail === $detail && $event->driver === 'totp',
        );
    }

    /**
     * Resolve the package's MFA manager, the driver registry the service is
     * called with.
     *
     * @return \SineMacula\Laravel\Mfa\MfaManager
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function manager(): MfaManager
    {
        $manager = $this->container()->make('mfa');

        self::assertInstanceOf(MfaManager::class, $manager);

        return $manager;
    }

    /**
     * Resolve the verification service.
     *
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function service(): VerificationService
    {
        return $this->container()->make(VerificationService::class);
    }

    /**
     * Register the given driver as the manager's TOTP driver.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function stubDriver(FactorDriver $driver): void
    {
        $this->manager()->extend('totp', fn (): FactorDriver => $driver);
    }

    /**
     * A driver whose verification answers the given result, or that must not
     * verify at all when the result is null.
     *
     * @param  ?bool  $result
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorDriver
     */
    private function driverAnswering(?bool $result): FactorDriver
    {
        $driver = \Mockery::mock(FactorDriver::class);

        if ($result === null) {
            $driver->shouldNotReceive('verify');
        } else {
            $driver->shouldReceive('verify')->once()->andReturn($result);
        }

        return $driver;
    }

    /**
     * Create a test user and authenticate as them.
     *
     * @return \Tests\Fixtures\TestUser
     */
    private function signIn(): TestUser
    {
        /** @var \Tests\Fixtures\TestUser $user */
        $user = TestUser::query()->create(['email' => 'verify@example.com']);

        $this->actingAs($user);

        return $user;
    }

    /**
     * Create a TOTP factor for the user with the given attempts.
     *
     * @param  \Tests\Fixtures\TestUser  $user
     * @param  int  $attempts
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function eloquentFactor(TestUser $user, int $attempts = 0): Factor
    {
        /** @var \SineMacula\Laravel\Mfa\Models\Factor */
        return Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'driver'               => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
            'attempts'             => $attempts,
        ]);
    }
}
