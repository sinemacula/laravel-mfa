<?php

declare(strict_types = 1);

namespace Tests\Unit\Verification;

use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\MfaChallengeIssued;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;
use SineMacula\Laravel\Mfa\Events\MfaVerified;
use SineMacula\Laravel\Mfa\Exceptions\FactorDriverMismatchException;
use SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Verification\VerificationService;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Tests for `VerificationService`: challenges and verification run only for the
 * current identity's own factor through its own driver, send and check a
 * delivered code bound to this session, application and purpose, record the
 * outcome on the factor, lock it at the configured attempt limit, and report
 * each outcome with its event.
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
    private const string UNCONFIRMED = 'The factor has no secret, so its enrolment never completed.';

    /** @var string The address the email factor delivers to. */
    private const string ADDRESS = 'verify@example.com';

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

        self::assertNull($this->service()->challenge($this->manager(), 'totp', $factor));

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

        $this->service()->challenge($this->manager(), 'totp', new InMemoryFactor(type: 'email', authenticatable: $user));
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

        $this->service()->verify($this->manager(), 'totp', new InMemoryFactor(type: 'email', authenticatable: $user), '123456');
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
        config()->set('mfa.attempts.factor_limit', 3);

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
     * Attempt limits, configured lockouts and the lockout each applies, in
     * seconds.
     *
     * @return iterable<string, array{?int, ?int, int}>
     */
    public static function lockouts(): iterable
    {
        yield 'the default limit and lockout' => [null, null, 900];
        yield 'a limit of one, the default lockout' => [1, null, 900];
        yield 'a limit of three, a configured lockout' => [3, 300, 300];
    }

    /**
     * The attempt that reaches the factor limit locks the factor for the
     * configured lockout, whatever the driver.
     *
     * @param  ?int  $limit
     * @param  ?int  $lockoutSeconds
     * @param  int  $expectedSeconds
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('lockouts')]
    public function testTheAttemptReachingTheLimitLocksTheFactor(?int $limit, ?int $lockoutSeconds, int $expectedSeconds): void
    {
        Carbon::setTestNow('2026-10-31 12:00:00');

        config()->set('mfa.attempts', array_filter(['factor_limit' => $limit, 'lockout_seconds' => $lockoutSeconds], static fn (?int $value): bool => $value !== null));

        $attempts = $limit ?? 5;
        $user     = $this->signIn();
        $factor   = $this->eloquentFactor($user, attempts: $attempts - 1);

        $this->stubDriver($this->driverAnswering(false));

        self::assertFalse($this->service()->verify($this->manager(), 'totp', $factor, '000000'));

        $factor->refresh();

        self::assertSame($attempts, $factor->getAttempts());
        self::assertTrue(Carbon::now()->addSeconds($expectedSeconds)->equalTo($factor->getLockedUntil()));
    }

    /**
     * A failure that leaves the count below the default limit of five does not
     * lock the factor.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAFailureBelowTheDefaultLimitDoesNotLock(): void
    {
        config()->set('mfa.attempts', []);

        $user   = $this->signIn();
        $factor = $this->eloquentFactor($user, attempts: 3);

        $this->stubDriver($this->driverAnswering(false));

        self::assertFalse($this->service()->verify($this->manager(), 'totp', $factor, '000000'));

        $factor->refresh();

        self::assertSame(4, $factor->getAttempts());
        self::assertNull($factor->getLockedUntil());
    }

    /**
     * Factor secrets, and the failure reason and detail a miss on each
     * explains.
     *
     * @return iterable<string, array{?string, \SineMacula\Laravel\Mfa\Enums\FailureReason, string}>
     */
    public static function failureReasons(): iterable
    {
        yield 'no secret' => [null, FailureReason::NOT_CONFIRMED, self::UNCONFIRMED];
        yield 'a secret' => ['secret', FailureReason::INVALID_CODE, self::MISMATCH];
    }

    /**
     * A failed verification through a driver that does not deliver codes is
     * reported with the reason the factor's state explains, and its detail.
     *
     * @param  ?string  $secret
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('failureReasons')]
    public function testAFailureIsReportedWithItsReason(?string $secret, FailureReason $reason, string $detail): void
    {
        $user   = $this->signIn();
        $factor = new InMemoryFactor(secret: $secret, authenticatable: $user);

        $this->stubDriver($this->driverAnswering(false));

        Event::fake();

        self::assertFalse($this->service()->verify($this->manager(), 'totp', $factor, '000000'));
        $this->assertFailedWith($reason, $detail);
    }

    /**
     * A delivered code is sent bound to this session and the purpose, reported
     * as a challenge, and accepted only for that purpose.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function testADeliveredCodeIsBoundToTheSessionAndPurpose(): void
    {
        $sender = FakeEmailSender::fake($this->container());
        $user   = $this->signIn();
        $factor = $this->emailFactor($user);

        Event::fake([MfaChallengeIssued::class]);

        $result = $this->service()->challenge($this->manager(), 'email', $factor, Purpose::STEP_UP);
        $code   = $sender->lastCodeTo(self::ADDRESS);

        self::assertNotNull($result);
        self::assertTrue($result->wasSent());
        self::assertNotNull($code);
        Event::assertDispatched(MfaChallengeIssued::class, static fn (MfaChallengeIssued $event): bool => $event->driver === 'email');

        $row = Code::query()->find($result->challengeId);

        self::assertInstanceOf(Code::class, $row);
        self::assertSame('step_up', $row->purpose);
        self::assertSame('web', $row->application);

        self::assertFalse($this->service()->verify($this->manager(), 'email', $factor, $code));
        self::assertTrue($this->service()->verify($this->manager(), 'email', $factor, $code, Purpose::STEP_UP));
    }

    /**
     * A send refused for its cooldown is returned with its reason and is not
     * reported as a challenge.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function testARefusedSendIsNotReportedAsAChallenge(): void
    {
        FakeEmailSender::fake($this->container());

        $factor = $this->emailFactor($this->signIn());

        $this->service()->challenge($this->manager(), 'email', $factor);

        Event::fake([MfaChallengeIssued::class]);

        $result = $this->service()->challenge($this->manager(), 'email', $factor);

        self::assertNotNull($result);
        self::assertSame(FailureReason::SENDING_CAPPED, $result->reason);
        Event::assertNotDispatched(MfaChallengeIssued::class);
    }

    /**
     * Sending a code neither resets the factor's failed attempts nor lifts its
     * lockout.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function testSendingACodeResetsNothing(): void
    {
        FakeEmailSender::fake($this->container());

        $factor = $this->emailFactor($this->signIn());

        $factor->forceFill(['attempts' => 3, 'locked_until' => Carbon::now()->addMinutes(15)])->save();

        $this->service()->challenge($this->manager(), 'email', $factor);

        $factor->refresh();

        self::assertSame(3, $factor->getAttempts());
        self::assertTrue($factor->isLocked());
    }

    /**
     * A delivered code is bound to the application a bound resolver names for
     * the request.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function testADeliveredCodeIsBoundToTheResolvedApplication(): void
    {
        FakeEmailSender::fake($this->container());

        $resolver = \Mockery::mock(ApplicationResolver::class);
        $resolver->shouldReceive('resolve')->with(\Mockery::type(Request::class))->andReturn('admin');

        $this->container()->instance(ApplicationResolver::class, $resolver);

        $result = $this->service()->challenge($this->manager(), 'email', $this->emailFactor($this->signIn()));
        $row    = Code::query()->find($result?->challengeId);

        self::assertInstanceOf(Code::class, $row);
        self::assertSame('admin', $row->application);
    }

    /**
     * Rows of a delivered code's failure: whether a code was sent first, and
     * the reason and detail the check that follows fails with.
     *
     * @return iterable<string, array{bool, \SineMacula\Laravel\Mfa\Enums\FailureReason, string}>
     */
    public static function deliveredCodeFailures(): iterable
    {
        yield 'a wrong code' => [true, FailureReason::INVALID_CODE, self::MISMATCH];
        yield 'no code sent' => [false, FailureReason::EXPIRED, 'No code was sent for this factor, session, application and purpose.'];
    }

    /**
     * A failed delivered code is reported with the reason and detail its check
     * found, never by the factor's secret.
     *
     * @param  bool  $sent
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    #[DataProvider('deliveredCodeFailures')]
    public function testADeliveredCodeFailureIsReportedWithWhatItsCheckFound(bool $sent, FailureReason $reason, string $detail): void
    {
        FakeEmailSender::fake($this->container());

        $factor = $this->emailFactor($this->signIn());

        if ($sent) {
            $this->service()->challenge($this->manager(), 'email', $factor);
        }

        Event::fake([MfaVerificationFailed::class]);

        self::assertFalse($this->service()->verify($this->manager(), 'email', $factor, '000000'));
        Event::assertDispatchedTimes(MfaVerificationFailed::class, 1);
        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === $reason && $event->detail === $detail && $event->driver === 'email',
        );
    }

    /**
     * A delivered code is bound to an identity with a string key, as it is
     * stored on the factor.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function testADeliveredCodeIsBoundToAStringKeyedIdentity(): void
    {
        FakeEmailSender::fake($this->container());

        $identity = new NonEloquentIdentity('plain-1');

        $this->actingAs($identity);

        $result = $this->service()->challenge($this->manager(), 'email', $this->ownedEmailFactor($identity));
        $row    = Code::query()->find($result?->challengeId);

        self::assertInstanceOf(Code::class, $row);
        self::assertSame(NonEloquentIdentity::class, $row->authenticatable_type);
        self::assertSame('plain-1', $row->authenticatable_id);
    }

    /**
     * A delivered code is never bound to an identity with an empty key.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function testADeliveredCodeIsNeverBoundToAnEmptyIdentityKey(): void
    {
        $identity = new NonEloquentIdentity('');

        $this->actingAs($identity);

        $this->expectException(UnsupportedIdentifierException::class);
        $this->expectExceptionMessage('A delivered code is bound to an identity with a string or integer key; got [string].');

        $this->service()->verify($this->manager(), 'email', $this->ownedEmailFactor($identity), '000000');
    }

    /**
     * A factor with a secret but no pending code is confirmed, so a miss on it
     * is an invalid code.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAFactorWithOnlyASecretIsNotUnconfirmed(): void
    {
        $user = $this->signIn();

        $this->stubDriver($this->driverAnswering(false));

        Event::fake();

        self::assertFalse($this->service()->verify($this->manager(), 'totp', new InMemoryFactor(secret: 'secret', authenticatable: $user), '000000'));
        $this->assertFailedWith(FailureReason::INVALID_CODE, self::MISMATCH);
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
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function signIn(): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->create(['email' => 'verify@example.com']);

        $this->actingAs($user);

        return $user;
    }

    /**
     * Create an email factor for the user, delivering to its address.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function emailFactor(TestUser $user): Factor
    {
        return Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'email',
            'destination'          => self::ADDRESS,
        ]);
    }

    /**
     * Create an email factor owned by the identity, delivering to the test
     * address.
     *
     * @param  \Tests\Fixtures\Identities\NonEloquentIdentity  $identity
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function ownedEmailFactor(NonEloquentIdentity $identity): Factor
    {
        return Factor::query()->create([
            'authenticatable_type' => NonEloquentIdentity::class,
            'authenticatable_id'   => $identity->getAuthIdentifier(),
            'type'                 => 'email',
            'destination'          => self::ADDRESS,
        ]);
    }

    /**
     * Create a TOTP factor for the user with the given attempts.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  int  $attempts
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function eloquentFactor(TestUser $user, int $attempts = 0): Factor
    {
        /** @var \SineMacula\Laravel\Mfa\Models\Factor */
        return Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
            'attempts'             => $attempts,
        ]);
    }
}
