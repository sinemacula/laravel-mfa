<?php

declare(strict_types = 1);

namespace Tests\Unit\Attempts;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\Attempt;
use SineMacula\Laravel\Mfa\Attempts\AttemptKeys;
use SineMacula\Laravel\Mfa\Attempts\AttemptOutcome;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Attempts\AttemptStore;
use SineMacula\Laravel\Mfa\Contracts\Factor as FactorContract;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Events\FactorDisabled;
use SineMacula\Laravel\Mfa\Events\LockoutApplied;
use SineMacula\Laravel\Mfa\Events\LockoutLifted;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use Tests\Fixtures\Exceptions\MidRotationFailureException;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\Fixtures\Identities\NonScalarIdentifierUser;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Tests for `AttemptService`: what each attempt is counted against, when it
 * locks a factor, the identity or an address, what a success resets and what
 * nothing but a success does, the failure ceiling, and lifting a lockout apart
 * from enabling a disabled factor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1448")
 */
#[CoversClass(AttemptService::class)]
final class AttemptServiceTest extends TestCase
{
    /** @var string The address the attempts are made from. */
    private const string IP = '192.0.2.1';

    /**
     * Freeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow('2026-11-01 12:00:00');
    }

    /**
     * Release the frozen clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * A failure is counted against the factor in a row, the identity's run and
     * its window, and the address.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureIsCountedAgainstEveryScope(): void
    {
        $user   = $this->user();
        $factor = $this->factor($user);

        $outcome = $this->attempt($user, $factor, false);

        self::assertTrue($outcome->isFailed());
        self::assertSame(1, $this->fresh($factor)->getConsecutiveFailures());
        self::assertSame(1, $this->state($user)?->consecutive_failures);
        self::assertSame(1, $this->hits($this->keys()->identity($user::class, (string) $user->id)));
        self::assertSame(1, $this->hits($this->keys()->ip(self::IP)));
        self::assertNull($this->service()->lockout($user, $factor, self::IP));
    }

    /**
     * A success resets the failures in a row of the factor it proved and the
     * identity's run, and nothing else: another factor keeps its count and its
     * lockout, the identity's window keeps its failures, and the success takes
     * no slot of the address's window.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASuccessResetsOnlyItsOwnFactor(): void
    {
        config()->set('mfa.attempts.factor_limit', 2);

        $user   = $this->user();
        $proved = $this->factor($user, failures: 1);
        $other  = $this->factor($user, failures: 1);

        $this->attempt($user, $other, false);

        $lockout = $this->service()->lockout($user, $other);

        $outcome = $this->attempt($user, $proved, true);

        self::assertTrue($outcome->passed);
        self::assertSame(0, $this->fresh($proved)->getConsecutiveFailures());
        self::assertSame(2, $this->fresh($other)->getConsecutiveFailures());
        self::assertNotNull($lockout);
        self::assertEquals($lockout, $this->service()->lockout($user, $other));
        self::assertSame(0, $this->state($user)?->consecutive_failures);
        self::assertSame(1, $this->hits($this->keys()->identity($user::class, (string) $user->id)));
        self::assertSame(1, $this->hits($this->keys()->ip(self::IP)));
    }

    /**
     * The failure that reaches the factor limit locks the factor for the
     * lockout period and reports it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFactorLimitLocksTheFactor(): void
    {
        config()->set('mfa.attempts.factor_limit', 3);
        config()->set('mfa.attempts.lockout_seconds', 300);

        Event::fake([LockoutApplied::class]);

        $user   = $this->user();
        $factor = $this->factor($user, failures: 1);

        $this->attempt($user, $factor, false);

        self::assertNull($this->service()->lockout($user, $factor));
        Event::assertNotDispatched(LockoutApplied::class);

        $this->attempt($user, $factor, false);

        $lockout = $this->service()->lockout($user, $factor);

        self::assertNotNull($lockout);
        self::assertSame(AttemptScope::FACTOR, $lockout->scope);
        self::assertEquals(CarbonImmutable::now()->addSeconds(300), $lockout->until);
        Event::assertDispatchedTimes(LockoutApplied::class, 1);
        Event::assertDispatched(
            LockoutApplied::class,
            static fn (LockoutApplied $event): bool => $event->factor?->id === $factor->id
                && $event->lockedUntil->equalTo(CarbonImmutable::now()->addSeconds(300))
                && $event->purpose                === Purpose::SIGN_IN
                && $event->context['identity_id'] === (string) $user->id,
        );
    }

    /**
     * A locked factor refuses the attempt without running the verification,
     * counts it nowhere and does not extend the lockout.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALockedFactorRefusesWithoutCountingOrExtending(): void
    {
        config()->set('mfa.attempts.factor_limit', 1);

        $user   = $this->user();
        $factor = $this->factor($user);

        $this->attempt($user, $factor, false);

        $before = $this->service()->lockout($user, $factor);

        Carbon::setTestNow('2026-11-01 12:05:00');

        $outcome = $this->service()->attempt(
            new Attempt($user, $factor, Purpose::SIGN_IN, self::IP),
            static function (): bool {
                throw new MidRotationFailureException('The verification must not run.');
            },
        );

        self::assertTrue($outcome->isRefused());
        self::assertEquals($before, $outcome->lockout);
        self::assertEquals($before, $this->service()->lockout($user, $factor));
        self::assertSame(1, $this->fresh($factor)->getConsecutiveFailures());
        self::assertSame(1, $this->state($user)?->consecutive_failures);
        self::assertSame(1, $this->hits($this->keys()->ip(self::IP)));
    }

    /**
     * The factor's failures in a row outlive its lockout: once it ends, the
     * next failure locks the factor again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureAfterTheLockoutEndsLocksAgain(): void
    {
        config()->set('mfa.attempts.factor_limit', 2);
        config()->set('mfa.attempts.lockout_seconds', 60);

        $user   = $this->user();
        $factor = $this->factor($user, failures: 1);

        $this->attempt($user, $factor, false);

        Carbon::setTestNow('2026-11-01 12:01:00');

        self::assertNull($this->service()->lockout($user, $factor));
        self::assertTrue($this->attempt($user, $factor, false)->isFailed());

        $lockout = $this->service()->lockout($user, $factor);

        self::assertSame(3, $this->fresh($factor)->getConsecutiveFailures());
        self::assertEquals(CarbonImmutable::parse('2026-11-01 12:02:00'), $lockout?->until);
    }

    /**
     * Failures across the identity's factors and recovery codes lock the
     * identity at its limit, for every factor and for recovery codes, until the
     * lockout ends, and report it with no factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheIdentityLimitLocksTheIdentityAcrossItsFactors(): void
    {
        config()->set('mfa.attempts.identity_limit', 3);

        Event::fake([LockoutApplied::class]);

        $user  = $this->user();
        $first = $this->factor($user);

        $this->attempt($user, $first, false);
        $this->attempt($user, $this->factor($user), false);
        $this->attempt($user, null, false);

        $refused = $this->attempt($user, $first, true);

        self::assertTrue($refused->isRefused());
        self::assertSame(AttemptScope::IDENTITY, $refused->lockout?->scope);
        self::assertEquals(CarbonImmutable::now()->addSeconds(900), $refused->lockout->until);
        self::assertTrue($this->attempt($user, null, true)->isRefused());
        self::assertSame(3, $this->state($user)?->consecutive_failures);
        Event::assertDispatched(
            LockoutApplied::class,
            static fn (LockoutApplied $event): bool => $event->factor === null && $event->lockedUntil->equalTo(CarbonImmutable::now()->addSeconds(900)),
        );

        Carbon::setTestNow('2026-11-01 12:15:00');

        self::assertNull($this->service()->lockout($user));
    }

    /**
     * The identity's failures count within the window only: failures spread
     * wider than it never lock the identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheIdentityCountEndsWithItsWindow(): void
    {
        config()->set('mfa.attempts.identity_limit', 2);
        config()->set('mfa.attempts.window_seconds', 60);

        $user = $this->user();

        $this->attempt($user, null, false);

        Carbon::setTestNow('2026-11-01 12:01:00');

        $this->attempt($user, null, false);

        self::assertNull($this->service()->lockout($user));
        self::assertSame(2, $this->state($user)?->consecutive_failures);
    }

    /**
     * Failures from one address across identities throttle it at its limit,
     * refusing the next identity without running its verification, while
     * another address is not throttled.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAddressLimitThrottlesItAcrossIdentities(): void
    {
        config()->set('mfa.attempts.ip_limit', 2);

        $this->attempt($this->user('first@example.com'), null, false);
        $this->attempt($this->user('second@example.com'), null, false);

        $third   = $this->user('third@example.com');
        $refused = $this->attempt($third, null, true);

        self::assertTrue($refused->isRefused());
        self::assertSame(AttemptScope::IP, $refused->lockout?->scope);
        self::assertEquals(CarbonImmutable::now()->addSeconds(900), $refused->lockout->until);
        self::assertNull($this->state($third));
        self::assertSame(AttemptScope::IP, $this->service()->lockout($third, null, self::IP)?->scope);
        self::assertTrue($this->attempt($third, null, true, '198.51.100.7')->passed);
    }

    /**
     * Successes take no slot of the address's window, so an address that only
     * succeeds is never throttled.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSuccessesNeverThrottleTheAddress(): void
    {
        config()->set('mfa.attempts.ip_limit', 1);

        $user = $this->user();

        self::assertTrue($this->attempt($user, null, true)->passed);
        self::assertTrue($this->attempt($user, null, true)->passed);
        self::assertSame(0, $this->hits($this->keys()->ip(self::IP)));
    }

    /**
     * An attempt made outside a request has no address to throttle.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAttemptWithoutAnAddressIsNotThrottled(): void
    {
        config()->set('mfa.attempts.ip_limit', 1);

        $user = $this->user();

        $this->attempt($user, null, false, null);

        self::assertTrue($this->attempt($user, null, false, null)->isFailed());
        self::assertNull($this->service()->lockout($user));
    }

    /**
     * The failure that reaches the failure ceiling disables the factor, reports
     * it, and from then on the factor is refused as disabled; past the factor
     * limit, it disables the factor rather than locking it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFailureCeilingDisablesTheFactor(): void
    {
        config()->set('mfa.attempts.factor_limit', 1);
        config()->set('mfa.attempts.failure_ceiling', 3);

        Event::fake([FactorDisabled::class, LockoutApplied::class]);

        $user   = $this->user();
        $factor = $this->factor($user, failures: 2);

        $this->attempt($user, $factor, false);

        $refused = $this->attempt($user, $factor, true);

        $disabledAt = $this->fresh($factor)->getDisabledAt();

        self::assertNotNull($disabledAt);
        self::assertTrue(Carbon::now()->equalTo($disabledAt));
        self::assertTrue($refused->isRefused());
        self::assertTrue($refused->lockout?->isDisabled());
        self::assertTrue($this->service()->lockout($user, $factor)?->isDisabled());
        Event::assertDispatched(
            FactorDisabled::class,
            static fn (FactorDisabled $event): bool => $event->factor->id === $factor->id && $event->purpose === Purpose::SIGN_IN,
        );
        Event::assertNotDispatched(LockoutApplied::class);
        self::assertSame(0, $this->hits($this->keys()->factor($factor->id)));
    }

    /**
     * Proving another factor enables every one of the identity's factors the
     * failure ceiling disabled, with their failures in a row cleared.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testProvingAnotherFactorEnablesEveryDisabledOne(): void
    {
        $user     = $this->user();
        $disabled = $this->factor($user, failures: 100, disabled: true);
        $proved   = $this->factor($user);
        $later    = $this->factor($user, failures: 100, disabled: true);

        $this->attempt($user, $proved, true);

        $disabled = $this->fresh($disabled);
        $later    = $this->fresh($later);

        self::assertNull($disabled->getDisabledAt());
        self::assertSame(0, $disabled->getConsecutiveFailures());
        self::assertNull($this->service()->lockout($user, $disabled));
        self::assertNull($later->getDisabledAt());
        self::assertSame(0, $later->getConsecutiveFailures());
    }

    /**
     * Enabling a disabled factor clears its failures in a row and leaves its
     * lockout to end on its own; a factor that is not disabled is left alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEnablingADisabledFactorLeavesItsLockout(): void
    {
        $user   = $this->user();
        $factor = $this->factor($user, failures: 100, disabled: true);

        $this->lockFactor($factor);

        self::assertTrue($this->service()->enableFactor($factor));

        $lockout = $this->service()->lockout($user, $factor);

        self::assertSame(0, $this->fresh($factor)->getConsecutiveFailures());
        self::assertNull($this->fresh($factor)->getDisabledAt());
        self::assertNotNull($lockout);
        self::assertSame(AttemptScope::FACTOR, $lockout->scope);
        self::assertFalse($lockout->isDisabled());
        self::assertFalse($this->service()->enableFactor($this->fresh($factor)));
    }

    /**
     * Lifting a factor's lockout reports it with the actor and keeps the
     * factor's failures in a row, so its next failure locks it again; lifting
     * it again lifts nothing and reports nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLiftingAFactorLockoutKeepsItsFailures(): void
    {
        config()->set('mfa.attempts.factor_limit', 2);

        Event::fake([LockoutLifted::class]);

        $user   = $this->user();
        $admin  = $this->user('admin@example.com');
        $factor = $this->factor($user, failures: 1);

        $this->attempt($user, $factor, false);

        self::assertTrue($this->service()->liftLockout($user, $factor, Actor::of($admin)));
        self::assertNull($this->service()->lockout($user, $factor));
        self::assertSame(2, $this->fresh($factor)->getConsecutiveFailures());
        Event::assertDispatched(
            LockoutLifted::class,
            static fn (LockoutLifted $event): bool => $event->factor?->id === $factor->id && $event->actor?->id === (string) $admin->id,
        );

        self::assertFalse($this->service()->liftLockout($user, $factor));
        Event::assertDispatchedTimes(LockoutLifted::class, 1);

        $this->attempt($user, $factor, false);

        self::assertSame(AttemptScope::FACTOR, $this->service()->lockout($user, $factor)?->scope);
    }

    /**
     * Lifting a lockout leaves a factor the failure ceiling disabled disabled.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLiftingALockoutLeavesADisabledFactorDisabled(): void
    {
        $user   = $this->user();
        $factor = $this->factor($user, failures: 100, disabled: true);

        $this->lockFactor($factor);

        self::assertTrue($this->service()->liftLockout($user, $factor));
        self::assertTrue($this->service()->lockout($user, $factor)?->isDisabled());
    }

    /**
     * Lifting the identity's lockout clears it and its window, and reports it
     * with no factor; lifting it again lifts nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLiftingTheIdentityLockout(): void
    {
        config()->set('mfa.attempts.identity_limit', 1);

        Event::fake([LockoutLifted::class]);

        $user = $this->user();

        $this->attempt($user, null, false);

        self::assertSame(AttemptScope::IDENTITY, $this->service()->lockout($user)?->scope);
        self::assertTrue($this->service()->liftLockout($user));
        self::assertNull($this->service()->lockout($user));
        self::assertSame(0, $this->hits($this->keys()->identity($user::class, (string) $user->id)));
        self::assertFalse($this->service()->liftLockout($user));
        Event::assertDispatchedTimes(LockoutLifted::class, 1);
        Event::assertDispatched(LockoutLifted::class, static fn (LockoutLifted $event): bool => $event->factor === null && $event->actor === null);
    }

    /**
     * A factor that keeps no state of its own is not counted itself, but the
     * identity is charged for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorWithoutStateChargesTheIdentity(): void
    {
        config()->set('mfa.attempts.factor_limit', 1);

        $user   = $this->user();
        $factor = new InMemoryFactor(authenticatable: $user);

        $this->attempt($user, $factor, false);

        self::assertTrue($this->attempt($user, $factor, false)->isFailed());
        self::assertSame(2, $this->state($user)?->consecutive_failures);
        self::assertNull($this->service()->lockout($user, $factor));
    }

    /**
     * A verification that throws counts nothing, rolls the attempt back and
     * gives the address's slot back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerificationThatThrowsCountsNothing(): void
    {
        $user   = $this->user();
        $factor = $this->factor($user);

        try {
            $this->service()->attempt(new Attempt($user, $factor, Purpose::SIGN_IN, self::IP), static function (): bool {
                throw new MidRotationFailureException('verification failed');
            });

            self::fail('The verification\'s exception must propagate.');
        } catch (MidRotationFailureException $exception) {
            self::assertSame('verification failed', $exception->getMessage());
        }

        self::assertNull($this->state($user));
        self::assertSame(0, $this->fresh($factor)->getConsecutiveFailures());
        self::assertSame(0, $this->hits($this->keys()->ip(self::IP)));
    }

    /**
     * An identity whose key is neither a string nor an integer cannot be
     * counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityWithoutAScalarKeyIsRefused(): void
    {
        $this->expectException(UnsupportedIdentifierException::class);

        $this->service()->lockout(new NonScalarIdentifierUser);
    }

    /**
     * Make an attempt whose verification answers as given.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  bool  $passes
     * @param  ?string  $ip
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptOutcome
     *
     * @throws \Throwable
     */
    private function attempt(TestUser $user, ?FactorContract $factor, bool $passes, ?string $ip = self::IP): AttemptOutcome
    {
        return $this->service()->attempt(new Attempt($user, $factor, Purpose::SIGN_IN, $ip), static fn (): bool => $passes);
    }

    /**
     * Lock the factor for five minutes, as its failures in a row would.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function lockFactor(Factor $factor): void
    {
        $this->container()->make(AttemptStore::class)->hold($this->keys()->factor($factor->id), AttemptScope::FACTOR, 5, CarbonImmutable::now()->addMinutes(5)->getTimestamp());
    }

    /**
     * The failures counted in a throttle row's live window.
     *
     * @param  string  $key
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function hits(string $key): int
    {
        return $this->container()->make(AttemptStore::class)->read([$key])[$key]['hits'] ?? 0;
    }

    /**
     * The user's identity state row, or `null` when it has none.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return ?\SineMacula\Laravel\Mfa\Models\IdentityState
     */
    private function state(TestUser $user): ?IdentityState
    {
        return IdentityState::query()
            ->where('authenticatable_type', $user::class)
            ->where('authenticatable_id', (string) $user->id)
            ->first();
    }

    /**
     * The factor as stored now.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function fresh(Factor $factor): Factor
    {
        return Factor::query()->findOrFail($factor->id);
    }

    /**
     * Create a TOTP factor for the user with the given failures in a row,
     * disabled at the failure ceiling when asked.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  int  $failures
     * @param  bool  $disabled
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function factor(TestUser $user, int $failures = 0, bool $disabled = false): Factor
    {
        /** @var \SineMacula\Laravel\Mfa\Models\Factor */
        return Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            'status'               => 'confirmed',
            'consecutive_failures' => $failures,
            'disabled_at'          => $disabled ? Carbon::now()->subDay() : null,
        ]);
    }

    /**
     * Create a test user.
     *
     * @param  string  $email
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function user(string $email = 'attempts@example.com'): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser */
        return TestUser::query()->create(['email' => $email]);
    }

    /**
     * Resolve the attempt keys.
     *
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptKeys
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function keys(): AttemptKeys
    {
        return $this->container()->make(AttemptKeys::class);
    }

    /**
     * Resolve the attempt service.
     *
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function service(): AttemptService
    {
        return $this->container()->make(AttemptService::class);
    }
}
