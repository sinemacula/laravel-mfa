<?php

declare(strict_types = 1);

namespace Tests\Unit\Verification;

use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Attempts\AttemptKeys;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Attempts\AttemptStore;
use SineMacula\Laravel\Mfa\Attempts\Lockout;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\MfaChallengeIssued;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;
use SineMacula\Laravel\Mfa\Events\MfaVerified;
use SineMacula\Laravel\Mfa\Exceptions\FactorDriverMismatchException;
use SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Verification\VerificationService;
use Tests\Fixtures\Exceptions\MidRotationFailureException;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Tests for `VerificationService`: challenges and verification run only for the
 * current identity's own factor through its own driver, send and check a
 * delivered code bound to this session, application and purpose, count the
 * outcome through the attempt service, which locks the factor at the configured
 * attempt limit, record a success's proof on the identity's sign-in, and report
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
     * @throws \InvalidArgumentException
     */
    public function testALockedFactorFailsWithoutReachingTheDriver(): void
    {
        $user   = $this->signIn();
        $factor = $this->eloquentFactor($user, failures: 5);

        $this->container()->make(AttemptStore::class)->hold(
            $this->container()->make(AttemptKeys::class)->factor($factor->id),
            AttemptScope::FACTOR,
            5,
            Carbon::now()->addMinutes(5)->getTimestamp(),
        );

        $this->stubDriver($this->driverAnswering(null));

        Event::fake();

        self::assertFalse($this->service()->verify($this->manager(), 'totp', $factor, '123456'));
        $this->assertFailedWith(FailureReason::LOCKED, self::LOCKED);
        Event::assertNotDispatched(MfaVerified::class);
    }

    /**
     * A factor removed after the caller read it is reported as not found,
     * without reaching the driver or counting anything.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testARemovedFactorIsNotFoundWithoutReachingTheDriver(): void
    {
        $user   = $this->signIn();
        $factor = $this->eloquentFactor($user);

        Factor::query()->whereKey($factor->id)->delete();

        $this->stubDriver($this->driverAnswering(null));

        Event::fake();

        self::assertFalse($this->service()->verify($this->manager(), 'totp', $factor, '123456'));
        $this->assertFailedWith(FailureReason::NOT_FOUND, 'The factor is no longer among the identity\'s factors.');
        Event::assertNotDispatched(MfaVerified::class);
        self::assertSame(0, (int) DB::table('mfa_attempts')->sum('hits'));
    }

    /**
     * The driver verifies the factor as stored, not the instance passed in, and
     * the instance passed in is brought up to date with what was stored.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheDriverVerifiesTheFactorAsStored(): void
    {
        $user   = $this->signIn();
        $factor = $this->eloquentFactor($user);

        Factor::query()->whereKey($factor->id)->update(['label' => 'Replaced']);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')
            ->once()
            ->with(\Mockery::on(static fn (mixed $stored): bool => $stored instanceof Factor && $stored !== $factor && $stored->getLabel() === 'Replaced'), '123456')
            ->andReturnTrue();

        $this->stubDriver($driver);

        Event::fake();

        self::assertTrue($this->service()->verify($this->manager(), 'totp', $factor, '123456'));
        self::assertSame('Replaced', $factor->getLabel());
        self::assertNotNull($factor->getLastUsedAt());
        self::assertFalse($factor->isDirty());
    }

    /**
     * A success is recorded on the factor in the attempt's transaction: when
     * counting it fails, the delivered code is left unused and the factor
     * unstamped, so the same code is accepted once counting works again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASuccessIsRecordedWithItsCount(): void
    {
        $sender = FakeEmailSender::fake($this->container());
        $user   = $this->signIn();
        $factor = $this->emailFactor($user);

        $this->service()->challenge($this->manager(), 'email', $factor);

        $code = $sender->lastCodeTo(self::ADDRESS);

        self::assertNotNull($code);
        self::assertFalse($this->service()->verify($this->manager(), 'email', $factor, $code === '000000' ? '111111' : '000000'));

        IdentityState::saving(static function (): void {
            throw new MidRotationFailureException('counting failed');
        });

        try {
            $this->service()->verify($this->manager(), 'email', $factor, $code);

            self::fail('The failure to count must propagate.');
        } catch (MidRotationFailureException $exception) {
            self::assertSame('counting failed', $exception->getMessage());
        }

        $stored = Factor::query()->findOrFail($factor->id);

        self::assertNull(Code::query()->sole()->consumed_at);
        self::assertNull($stored->getLastUsedAt());
        self::assertSame(1, $stored->getConsecutiveFailures());

        IdentityState::flushEventListeners();

        self::assertTrue($this->service()->verify($this->manager(), 'email', $factor, $code));
    }

    /**
     * An attempt on another identity's factor is refused before anything is
     * counted, so nobody is charged for it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function testAnAttemptOnAnotherIdentitysFactorChargesNobody(): void
    {
        $this->signIn();

        $other  = TestUser::query()->create(['email' => 'other@example.com']);
        $factor = $this->eloquentFactor($other);
        $thrown = null;

        $this->stubDriver($this->driverAnswering(null));

        try {
            $this->service()->verify($this->manager(), 'totp', $factor, '000000');
        } catch (FactorOwnershipMismatchException $exception) {
            $thrown = $exception;
        }

        self::assertInstanceOf(FactorOwnershipMismatchException::class, $thrown);
        self::assertSame(0, DB::table('mfa_identity_states')->count());
        self::assertSame(0, DB::table('mfa_attempts')->count());
        self::assertSame(0, $factor->refresh()->getConsecutiveFailures());
    }

    /**
     * A failure is counted against the request's address, so past its limit the
     * address is throttled whatever the factor, without reaching the driver.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAFailureIsCountedAgainstTheRequestsAddress(): void
    {
        config()->set('mfa.attempts.ip_limit', 1);

        $this->container()->instance('request', Request::create('/mfa/verify', 'POST', server: ['REMOTE_ADDR' => '192.0.2.1']));

        $user = $this->signIn();

        $this->stubDriver($this->driverAnswering(false));

        Event::fake();

        self::assertFalse($this->service()->verify($this->manager(), 'totp', $this->eloquentFactor($user), '000000'));
        self::assertFalse($this->service()->verify($this->manager(), 'totp', $this->eloquentFactor($user), '000000'));
        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === FailureReason::LOCKED
                && $event->detail                                            === 'The IP address is throttled after too many failed attempts.',
        );
    }

    /**
     * A valid code verifies an Eloquent factor on a signed-in session: its
     * failures in a row reset, its last use is stamped and persisted, an
     * additional factor proof of it is recorded on the sign-in for the purpose,
     * and the success reported.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAValidCodeVerifiesAnEloquentFactor(): void
    {
        Carbon::setTestNow('2026-10-31 12:00:00');

        $user   = $this->signIn();
        $factor = $this->eloquentFactor($user, failures: 2);
        $driver = \Mockery::mock(FactorDriver::class);

        $driver->shouldReceive('verify')->once()->andReturnTrue();
        $driver->shouldReceive('channelKind')->andReturn(ChannelKind::AUTHENTICATOR_APP);

        Auth::login($user);

        $this->stubDriver($driver);

        Event::fake();

        self::assertTrue($this->service()->verify($this->manager(), 'totp', $factor, '123456', Purpose::STEP_UP));

        $factor->refresh();

        $proofs = $this->container()->make(ProofService::class)->proofs();

        self::assertSame(0, $factor->getConsecutiveFailures());
        self::assertTrue(Carbon::now()->equalTo($factor->getLastUsedAt()));
        self::assertCount(1, $proofs);
        self::assertSame(ProofKind::ADDITIONAL_FACTOR, $proofs[0]->kind);
        self::assertSame('totp', $proofs[0]->method);
        self::assertSame($factor->getKey(), $proofs[0]->reference);
        self::assertSame(Purpose::STEP_UP, $proofs[0]->binding->purpose);
        self::assertSame(['kind' => 'authenticator_app', 'reference' => $factor->getKey()], $proofs[0]->channel?->toArray());
        Event::assertDispatched(
            MfaVerified::class,
            static fn (MfaVerified $event): bool => $event->identity === $user
                && $event->factor                                    === $factor
                && $event->driver                                    === 'totp',
        );
        Event::assertNotDispatched(MfaVerificationFailed::class);
    }

    /**
     * A success inside a transaction on the storage connection is reported,
     * with its proof kept first, only once that transaction commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASuccessInATransactionIsReportedOnceItCommits(): void
    {
        $user   = $this->signIn();
        $factor = $this->eloquentFactor($user);
        $driver = \Mockery::mock(FactorDriver::class);

        $driver->shouldReceive('verify')->once()->andReturnTrue();
        $driver->shouldReceive('channelKind')->andReturn(ChannelKind::AUTHENTICATOR_APP);

        Auth::login($user);

        $this->stubDriver($driver);

        Event::fake();

        DB::beginTransaction();

        self::assertTrue($this->service()->verify($this->manager(), 'totp', $factor, '123456', Purpose::STEP_UP));
        Event::assertNotDispatched(MfaVerified::class);

        DB::commit();

        Event::assertDispatched(MfaVerified::class);
        self::assertCount(1, $this->container()->make(ProofService::class)->proofs());
    }

    /**
     * A success inside a transaction that rolls back is never reported and
     * leaves no proof.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASuccessInATransactionThatRollsBackIsNeverReported(): void
    {
        $user   = $this->signIn();
        $factor = $this->eloquentFactor($user);
        $driver = \Mockery::mock(FactorDriver::class);

        $driver->shouldReceive('verify')->once()->andReturnTrue();
        $driver->shouldReceive('channelKind')->andReturn(ChannelKind::AUTHENTICATOR_APP);

        Auth::login($user);

        $this->stubDriver($driver);

        Event::fake();

        DB::beginTransaction();

        self::assertTrue($this->service()->verify($this->manager(), 'totp', $factor, '123456', Purpose::STEP_UP));

        DB::rollBack();

        Event::assertNotDispatched(MfaVerified::class);
        self::assertCount(0, $this->container()->make(ProofService::class)->proofs());
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
        Event::assertDispatched(MfaVerified::class);
    }

    /**
     * An invalid code counts a failure in a row on the factor and persists it,
     * below the limit without a lockout.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnInvalidCodeCountsAnAttempt(): void
    {
        config()->set('mfa.attempts.factor_limit', 3);

        $user   = $this->signIn();
        $factor = $this->eloquentFactor($user, failures: 1);

        Auth::login($user);

        $this->stubDriver($this->driverAnswering(false));

        Event::fake();

        self::assertFalse($this->service()->verify($this->manager(), 'totp', $factor, '000000'));

        $factor->refresh();

        self::assertSame(2, $factor->getConsecutiveFailures());
        self::assertNull($this->lockoutOf($user, $factor));
        self::assertNull($factor->getLastUsedAt());
        self::assertSame([], $this->container()->make(ProofService::class)->proofs());
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
        $factor   = $this->eloquentFactor($user, failures: $attempts - 1);

        $this->stubDriver($this->driverAnswering(false));

        self::assertFalse($this->service()->verify($this->manager(), 'totp', $factor, '000000'));

        $factor->refresh();

        $lockout = $this->lockoutOf($user, $factor);

        self::assertSame($attempts, $factor->getConsecutiveFailures());
        self::assertNotNull($lockout);
        self::assertNotNull($lockout->until);
        self::assertTrue(Carbon::now()->addSeconds($expectedSeconds)->equalTo($lockout->until));
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
        $factor = $this->eloquentFactor($user, failures: 3);

        $this->stubDriver($this->driverAnswering(false));

        self::assertFalse($this->service()->verify($this->manager(), 'totp', $factor, '000000'));

        $factor->refresh();

        self::assertSame(4, $factor->getConsecutiveFailures());
        self::assertNull($this->lockoutOf($user, $factor));
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
     * Sending a code neither resets the factor's failures in a row nor lifts
     * its lockout.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function testSendingACodeResetsNothing(): void
    {
        config()->set('mfa.attempts.factor_limit', 3);

        FakeEmailSender::fake($this->container());

        $user   = $this->signIn();
        $factor = $this->emailFactor($user);

        for ($failure = 0; $failure < 3; $failure++) {
            self::assertFalse($this->service()->verify($this->manager(), 'email', $factor, '000000'));
        }

        $before = $this->lockoutOf($user, $factor);

        self::assertNotNull($before);
        self::assertTrue($this->service()->challenge($this->manager(), 'email', $factor)?->wasSent());

        $factor->refresh();

        self::assertSame(3, $factor->getConsecutiveFailures());
        self::assertEquals($before->until, $this->lockoutOf($user, $factor)?->until);
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
     * A proof is stamped with the verification generation read before the
     * driver checked the code, so a generation advanced while it is checked
     * leaves the proof behind rather than letting it count.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGenerationAdvancedWhileTheCodeIsCheckedLeavesTheProofBehind(): void
    {
        $user   = $this->signIn();
        $factor = $this->eloquentFactor($user);
        $driver = \Mockery::mock(FactorDriver::class);

        $driver->shouldReceive('verify')->once()->andReturnUsing(static fn (): bool => VerificationGeneration::advance($user) > 0);
        $driver->shouldReceive('channelKind')->andReturn(ChannelKind::AUTHENTICATOR_APP);

        Auth::login($user);

        $this->stubDriver($driver);

        self::assertTrue($this->service()->verify($this->manager(), 'totp', $factor, '123456'));
        self::assertSame(1, VerificationGeneration::current($user));
        self::assertSame([], $this->container()->make(ProofService::class)->proofs());
    }

    /**
     * A valid code for a factor whose identifier cannot name it records no
     * proof, even on a signed-in session.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAFactorWhoseIdentifierCannotNameItRecordsNothing(): void
    {
        $user   = $this->signIn();
        $factor = new InMemoryFactor(secret: 'secret', identifier: null, authenticatable: $user);
        $driver = \Mockery::mock(FactorDriver::class);

        $driver->shouldReceive('verify')->once()->andReturnTrue();
        $driver->shouldReceive('channelKind')->andReturn(ChannelKind::AUTHENTICATOR_APP);

        Auth::login($user);

        $this->stubDriver($driver);

        self::assertTrue($this->service()->verify($this->manager(), 'totp', $factor, '123456'));
        self::assertSame([], $this->container()->make(ProofService::class)->proofs());
    }

    /**
     * A factor with an integer identifier is named by it as a string, and with
     * no destination its channel is named by the factor too.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnIntegerIdentifierNamesTheFactorAsAString(): void
    {
        $user   = $this->signIn();
        $factor = new InMemoryFactor(secret: 'secret', identifier: 7, authenticatable: $user);
        $driver = \Mockery::mock(FactorDriver::class);

        $driver->shouldReceive('verify')->once()->andReturnTrue();
        $driver->shouldReceive('channelKind')->andReturn(ChannelKind::AUTHENTICATOR_APP);

        Auth::login($user);

        $this->stubDriver($driver);

        self::assertTrue($this->service()->verify($this->manager(), 'totp', $factor, '123456'));

        $proofs = $this->container()->make(ProofService::class)->proofs();

        self::assertCount(1, $proofs);
        self::assertSame('7', $proofs[0]->reference);
        self::assertSame(['kind' => 'authenticator_app', 'reference' => '7'], $proofs[0]->channel?->toArray());
    }

    /**
     * A delivered code verified on a signed-in session records its proof on the
     * code's channel, named by the factor's destination, for the purpose the
     * code was sent and checked for, and an attempt a lockout refuses records
     * none.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function testADeliveredCodeRecordsItsProofForThePurpose(): void
    {
        $sender = FakeEmailSender::fake($this->container());
        $user   = $this->signIn();
        $factor = $this->emailFactor($user);

        Auth::login($user);

        $this->service()->challenge($this->manager(), 'email', $factor, Purpose::STEP_UP);

        $code = $sender->lastCodeTo(self::ADDRESS);

        self::assertNotNull($code);
        self::assertTrue($this->service()->verify($this->manager(), 'email', $factor, $code, Purpose::STEP_UP));

        $proofs = $this->container()->make(ProofService::class)->proofs();

        self::assertCount(1, $proofs);
        self::assertSame(ProofKind::ADDITIONAL_FACTOR, $proofs[0]->kind);
        self::assertSame(Purpose::STEP_UP, $proofs[0]->binding->purpose);
        self::assertSame(['kind' => 'email', 'reference' => self::ADDRESS], $proofs[0]->channel?->toArray());
    }

    /**
     * An attempt a lockout refuses never checks the code and records no proof,
     * even on a signed-in session.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function testARefusedAttemptRecordsNoProof(): void
    {
        $user   = $this->signIn();
        $factor = $this->eloquentFactor($user);

        $this->container()->make(AttemptStore::class)->hold(
            $this->container()->make(AttemptKeys::class)->factor($factor->id),
            AttemptScope::FACTOR,
            5,
            now()->addHour()->getTimestamp(),
        );

        Auth::login($user);

        $this->stubDriver($this->driverAnswering(null));

        self::assertFalse($this->service()->verify($this->manager(), 'totp', $factor, '123456'));
        self::assertSame([], $this->container()->make(ProofService::class)->proofs());
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
     * The lockout the user's attempts against the factor are refused by now.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return ?\SineMacula\Laravel\Mfa\Attempts\Lockout
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function lockoutOf(TestUser $user, Factor $factor): ?Lockout
    {
        return $this->container()->make(AttemptService::class)->lockout($user, $factor);
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
     * Create a TOTP factor for the user with the given failures in a row.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  int  $failures
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function eloquentFactor(TestUser $user, int $failures = 0): Factor
    {
        /** @var \SineMacula\Laravel\Mfa\Models\Factor */
        return Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
            'consecutive_failures' => $failures,
        ]);
    }
}
