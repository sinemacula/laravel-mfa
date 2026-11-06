<?php

declare(strict_types = 1);

namespace Tests\Unit\Attempts;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Carbon\Exceptions\InvalidFormatException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
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
use SineMacula\Laravel\Mfa\Exceptions\InvalidModelException;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use Tests\Fixtures\Exceptions\MidRotationFailureException;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\Fixtures\Factors\RemappedLockoutFactor;
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
        self::assertFalse($outcome->causedLockout());
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
     * A success with nothing to reset saves nothing: not the identity's state,
     * not the factor proved, and not another factor that is not disabled. A
     * model event refusing those saves, as an application's observer may, is
     * never asked, so it cannot abort the success.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASuccessWithNothingToResetSavesNothing(): void
    {
        $user    = $this->user();
        $proved  = $this->factor($user);
        $sibling = $this->factor($user);
        $saves   = [];

        Factor::saving(static function (Factor $factor) use (&$saves): bool {
            $saves[] = $factor->id;

            return false;
        });

        IdentityState::saving(static function () use (&$saves): bool {
            $saves[] = 'identity state';

            return false;
        });

        $outcome = $this->attempt($user, $proved, true);

        self::assertTrue($outcome->passed);
        self::assertSame([], $saves);
        self::assertNull($this->fresh($sibling)->getDisabledAt());
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

        self::assertNull($this->attempt($user, $factor, false)->caused);
        self::assertNull($this->service()->lockout($user, $factor));
        Event::assertNotDispatched(LockoutApplied::class);

        $locking = $this->attempt($user, $factor, false);
        $lockout = $this->service()->lockout($user, $factor);

        self::assertNotNull($lockout);
        self::assertSame(AttemptScope::FACTOR, $lockout->scope);
        self::assertEquals(CarbonImmutable::now()->addSeconds(300), $lockout->until);
        self::assertTrue($locking->isFailed());
        self::assertFalse($locking->isRefused());
        self::assertTrue($locking->causedLockout());
        self::assertSame(AttemptScope::FACTOR, $locking->caused?->scope);
        self::assertEquals($lockout->until, $locking->caused->until);
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
     * The deadline goes on the factor's own row, in the one save that counts
     * the failure, and nothing of the factor goes in the attempts table.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDeadlineIsStoredOnTheFactorInTheSaveThatCountsTheFailure(): void
    {
        config()->set('mfa.attempts.factor_limit', 2);
        config()->set('mfa.attempts.lockout_seconds', 300);

        $user   = $this->user();
        $factor = $this->factor($user, failures: 1);
        $saves  = 0;

        Factor::saved(static function () use (&$saves): void {
            $saves++;
        });

        try {
            $this->attempt($user, $factor, false);
        } finally {
            Factor::flushEventListeners();
        }

        self::assertSame(1, $saves);
        self::assertSame(2, $this->fresh($factor)->getConsecutiveFailures());
        self::assertEquals(CarbonImmutable::now()->addSeconds(300), $this->fresh($factor)->getLockedUntil());
        self::assertTrue(DB::table('mfa_attempts')->where('scope', AttemptScope::FACTOR->value)->doesntExist());
    }

    /**
     * A locked factor refuses the attempt without running the verification,
     * counts it nowhere, does not extend the lockout and reports nothing more.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALockedFactorRefusesWithoutCountingOrExtending(): void
    {
        config()->set('mfa.attempts.factor_limit', 1);

        Event::fake([FactorDisabled::class, LockoutApplied::class]);

        $user   = $this->user();
        $factor = $this->factor($user);

        $this->attempt($user, $factor, false);

        $before   = $this->service()->lockout($user, $factor);
        $deadline = $this->fresh($factor)->getLockedUntil();

        self::assertNotNull($deadline);

        Carbon::setTestNow('2026-11-01 12:05:00');

        $outcome = $this->service()->attempt(
            new Attempt($user, $factor, Purpose::SIGN_IN),
            static function (): bool {
                throw new MidRotationFailureException('The verification must not run.');
            },
        );

        self::assertTrue($outcome->isRefused());
        self::assertEquals($before, $outcome->lockout);
        self::assertEquals($before, $this->service()->lockout($user, $factor));
        self::assertEquals($deadline, $this->fresh($factor)->getLockedUntil());
        self::assertSame(1, $this->fresh($factor)->getConsecutiveFailures());
        self::assertSame(1, $this->state($user)?->consecutive_failures);
        self::assertSame(1, $this->hits($this->keys()->ip(self::IP)));
        Event::assertDispatchedTimes(LockoutApplied::class, 1);
        Event::assertNotDispatched(FactorDisabled::class);
    }

    /**
     * A lockout applies up to the second before its deadline and not from the
     * deadline itself, for the read and for an attempt alike.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALockoutEndsExactlyAtItsDeadline(): void
    {
        $user   = $this->user();
        $factor = $this->factor($user, failures: 5);
        $until  = $this->lockFactor($factor);

        Carbon::setTestNow($until->subSecond());

        self::assertSame(AttemptScope::FACTOR, $this->service()->lockout($user, $factor)?->scope);
        self::assertSame(AttemptScope::FACTOR, $this->attempt($user, $factor, true)->lockout?->scope);
        self::assertSame(5, $this->fresh($factor)->getConsecutiveFailures());

        Carbon::setTestNow($until);

        self::assertNull($this->service()->lockout($user, $factor));
        self::assertTrue($this->attempt($user, $factor, true)->passed);
    }

    /**
     * Both an attempt and the lockout read answer from the row as stored, not
     * from the instance the caller holds: a copy read before the lockout is
     * refused, and a copy read before a lift is not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDeadlineIsReadFromTheRowAndNotTheCallersCopy(): void
    {
        $user   = $this->user();
        $before = $this->factor($user);

        $this->lockFactor($before);

        self::assertNull($before->getLockedUntil());
        self::assertSame(AttemptScope::FACTOR, $this->service()->lockout($user, $before)?->scope);
        self::assertSame(AttemptScope::FACTOR, $this->attempt($user, $before, true)->lockout?->scope);

        $locked = $this->fresh($before);

        self::assertTrue($this->service()->liftLockout($user, $before));
        self::assertNotNull($locked->getLockedUntil());
        self::assertNull($this->service()->lockout($user, $locked));
        self::assertTrue($this->attempt($user, $locked, true)->passed);
    }

    /**
     * A model event that cancels the save of the failure that locks the factor
     * throws and rolls everything back: nothing is counted, no deadline is
     * stored and nothing is reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACancelledSaveRollsTheLockoutBack(): void
    {
        config()->set('mfa.attempts.factor_limit', 1);

        Event::fake([LockoutApplied::class]);

        $user   = $this->user();
        $factor = $this->factor($user);

        Factor::saving(static fn (): bool => false);

        try {
            $this->attempt($user, $factor, false);

            self::fail('A cancelled save must not be counted as made.');
        } catch (WriteCanceledException $exception) {
            self::assertStringContainsString('cancelled', $exception->getMessage());
        } finally {
            Factor::flushEventListeners();
        }

        self::assertNull($this->fresh($factor)->getLockedUntil());
        self::assertSame(0, $this->fresh($factor)->getConsecutiveFailures());
        self::assertNull($this->state($user));
        self::assertSame(0, $this->hits($this->keys()->identity($user::class, (string) $user->id)));
        self::assertSame(0, $this->hits($this->keys()->ip(self::IP)));
        Event::assertNotDispatched(LockoutApplied::class);
    }

    /**
     * A failure that locks the identity and the factor at once names the
     * strictest of the two: the identity's, which ends no sooner; and a failure
     * of a factor that keeps no state, which brings the identity's run to the
     * failure ceiling, names the identity at the ceiling.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureNamesTheStrictestLockoutItCaused(): void
    {
        config()->set('mfa.attempts.factor_limit', 2);
        config()->set('mfa.attempts.identity_limit', 2);
        config()->set('mfa.attempts.lockout_seconds', 300);

        $user   = $this->user();
        $factor = $this->factor($user);

        $this->attempt($user, $factor, false);

        $locking = $this->attempt($user, $factor, false);

        self::assertNotNull($this->fresh($factor)->getLockedUntil());
        self::assertSame(AttemptScope::IDENTITY, $locking->caused?->scope);
        self::assertEquals(CarbonImmutable::now()->addSeconds(300), $locking->caused->until);

        config()->set('mfa.attempts.identity_limit', 100);
        config()->set('mfa.attempts.failure_ceiling', 2);

        $other     = $this->user('ceiling@example.com');
        $stateless = new InMemoryFactor;

        self::assertNull($this->attempt($other, $stateless, false)->caused);

        $reaching = $this->attempt($other, $stateless, false);

        self::assertSame(AttemptScope::IDENTITY, $reaching->caused?->scope);
        self::assertTrue($reaching->caused->isDisabled());
    }

    /**
     * A model event that cancels the save of the identity's lockout throws and
     * rolls everything back, rather than report a lockout that was never
     * stored.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACancelledSaveOfTheIdentityLockoutRollsItBack(): void
    {
        config()->set('mfa.attempts.identity_limit', 1);

        Event::fake([LockoutApplied::class]);

        $user = $this->user();

        $this->attempt($user, null, true);

        IdentityState::saving(static fn (): bool => false);

        try {
            $this->attempt($user, null, false);

            self::fail('A cancelled save must not be counted as made.');
        } catch (WriteCanceledException $exception) {
            self::assertStringContainsString('the identity\'s lockout', $exception->getMessage());
        } finally {
            IdentityState::flushEventListeners();
        }

        self::assertNull($this->state($user)?->locked_until);
        self::assertSame(0, $this->hits($this->keys()->identity($user::class, (string) $user->id)));
        Event::assertNotDispatched(LockoutApplied::class);
    }

    /**
     * A custom column with no cast declared works once the model is read back
     * from storage: the deadline is written to it, refuses from it and is
     * lifted from it. The shipped column is never touched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACustomColumnHoldsTheDeadlineAfterReloadingFromStorage(): void
    {
        config()->set('mfa.attempts.factor_limit', 1);
        config()->set('mfa.attempts.lockout_seconds', 300);
        config()->set('mfa.factor.model', RemappedLockoutFactor::class);

        Schema::table('mfa_factors', static function (Blueprint $table): void {
            $table->timestamp('held_until')->nullable();
        });

        $user   = $this->user();
        $factor = RemappedLockoutFactor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            'status'               => 'confirmed',
        ]);
        $row   = DB::table('mfa_factors')->where('id', $factor->getKey());
        $until = CarbonImmutable::now()->addSeconds(300);

        $this->attempt($user, $factor, false);

        /** @var \Tests\Fixtures\Factors\RemappedLockoutFactor $stored */
        $stored = RemappedLockoutFactor::query()->findOrFail($factor->getKey());

        self::assertEquals($until, $stored->getLockedUntil());
        self::assertNotNull((clone $row)->value('held_until'));
        self::assertNull((clone $row)->value('locked_until'));

        $refused = $this->attempt($user, $stored, true);

        self::assertSame(AttemptScope::FACTOR, $refused->lockout?->scope);
        self::assertEquals($until, $refused->lockout->until);
        self::assertEquals($until, $this->service()->lockout($user, $stored)?->until);
        self::assertTrue($this->service()->liftLockout($user, $stored));
        self::assertNull((clone $row)->value('held_until'));
    }

    /**
     * An independent model with no cast on `disabled_at`, disabled at the
     * failure ceiling, is read back from storage as disabled and refused as
     * disabled without running the verification.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUncastCustomModelDisabledAtTheCeilingIsRefusedAsDisabled(): void
    {
        config()->set('mfa.attempts.failure_ceiling', 1);
        config()->set('mfa.factor.model', RemappedLockoutFactor::class);

        Schema::table('mfa_factors', static function (Blueprint $table): void {
            $table->timestamp('held_until')->nullable();
        });

        $user   = $this->user();
        $factor = RemappedLockoutFactor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            'status'               => 'confirmed',
        ]);

        $this->attempt($user, $factor, false);

        /** @var \Tests\Fixtures\Factors\RemappedLockoutFactor $stored */
        $stored = RemappedLockoutFactor::query()->findOrFail($factor->getKey());

        self::assertNotNull($stored->getDisabledAt());

        $refused = $this->service()->attempt(new Attempt($user, $stored, Purpose::SIGN_IN), static function (): bool {
            throw new MidRotationFailureException('The verification must not run.');
        });

        self::assertTrue($refused->isRefused());
        self::assertTrue($refused->lockout?->isDisabled());
        self::assertTrue($this->service()->lockout($user, $stored)?->isDisabled());
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

        $locking = $this->attempt($user, null, false);
        $refused = $this->attempt($user, $first, true);

        self::assertSame(AttemptScope::IDENTITY, $locking->caused?->scope);
        self::assertEquals(CarbonImmutable::now()->addSeconds(900), $locking->caused->until);

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

        $disabling = $this->attempt($user, $factor, false);
        $refused   = $this->attempt($user, $factor, true);

        self::assertSame(AttemptScope::FACTOR, $disabling->caused?->scope);
        self::assertTrue($disabling->caused->isDisabled());

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
        self::assertNull($this->fresh($factor)->getLockedUntil());
    }

    /**
     * A failure that brings the identity's run to the failure ceiling takes
     * precedence over the factor limit too: it disables the factor, and writes
     * no deadline, however far past the limit the factor is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheIdentityCeilingTakesPrecedenceOverTheFactorLimit(): void
    {
        config()->set('mfa.attempts.factor_limit', 1);
        config()->set('mfa.attempts.failure_ceiling', 2);

        Event::fake([FactorDisabled::class, LockoutApplied::class]);

        $user   = $this->user();
        $factor = $this->factor($user);

        $this->attempt($user, null, false);

        $disabling = $this->attempt($user, $factor, false);

        self::assertNotNull($this->fresh($factor)->getDisabledAt());
        self::assertNull($this->fresh($factor)->getLockedUntil());
        self::assertSame(AttemptScope::FACTOR, $disabling->caused?->scope);
        self::assertTrue($disabling->caused->isDisabled());
        Event::assertDispatched(FactorDisabled::class);
        Event::assertNotDispatched(LockoutApplied::class);
    }

    /**
     * Proving another factor enables every one of the identity's factors the
     * failure ceiling disabled, and keeps their failures in a row, since only a
     * success of a factor resets its own count: the next failure of one
     * disables it again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testProvingAnotherFactorEnablesEveryDisabledOneAndKeepsItsCount(): void
    {
        $user     = $this->user();
        $disabled = $this->factor($user, failures: 100, disabled: true);
        $proved   = $this->factor($user);
        $later    = $this->factor($user, failures: 100, disabled: true);

        $this->attempt($user, $proved, true);

        $disabled = $this->fresh($disabled);
        $later    = $this->fresh($later);

        self::assertNull($disabled->getDisabledAt());
        self::assertSame(100, $disabled->getConsecutiveFailures());
        self::assertNull($this->service()->lockout($user, $disabled));
        self::assertNull($later->getDisabledAt());
        self::assertSame(100, $later->getConsecutiveFailures());

        $this->attempt($user, $disabled, false);

        self::assertTrue($this->service()->lockout($user, $disabled)?->isDisabled());
        self::assertSame(101, $this->fresh($disabled)->getConsecutiveFailures());
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
        self::assertNull($this->fresh($factor)->getLockedUntil());
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
     * Lifting clears a deadline that has already passed, the moment it ends
     * included, but it was not live, so nothing is reported as lifted and the
     * failures in a row are kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLiftingAnEndedLockoutClearsItAndReportsNothing(): void
    {
        Event::fake([LockoutLifted::class]);

        $user   = $this->user();
        $factor = $this->factor($user, failures: 5);

        foreach ([Carbon::now()->subMinute(), Carbon::now()] as $until) {

            $factor->update(['locked_until' => $until]);

            self::assertFalse($this->service()->liftLockout($user, $factor));
            self::assertNull($this->fresh($factor)->getLockedUntil());
            self::assertSame(5, $this->fresh($factor)->getConsecutiveFailures());
        }

        Event::assertNotDispatched(LockoutLifted::class);
    }

    /**
     * A model event that cancels the save of a lift throws, and leaves the
     * lockout in force and unreported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACancelledSaveLeavesTheLockoutInForce(): void
    {
        Event::fake([LockoutLifted::class]);

        $user   = $this->user();
        $factor = $this->factor($user);
        $until  = $this->lockFactor($factor);

        Factor::saving(static fn (): bool => false);

        try {
            $this->service()->liftLockout($user, $factor);

            self::fail('A cancelled save must not be reported as a lift.');
        } catch (WriteCanceledException $exception) {
            self::assertStringContainsString('cancelled', $exception->getMessage());
        } finally {
            Factor::flushEventListeners();
        }

        self::assertEquals($until, $this->fresh($factor)->getLockedUntil());
        Event::assertNotDispatched(LockoutLifted::class);
    }

    /**
     * Stored deadlines that cannot be read as a time.
     *
     * @return iterable<string, array{string, class-string<\Throwable>}>
     */
    public static function unreadableDeadlines(): iterable
    {
        yield 'not a time' => ['not a time', InvalidFormatException::class];
        yield 'empty' => ['', InvalidModelException::class];
        yield 'blank' => ['   ', InvalidModelException::class];
    }

    /**
     * A stored deadline that cannot be read as a time fails closed: an attempt
     * and the lockout read throw, the verification does not run and nothing is
     * counted, rather than the factor reading as unlocked. The column is text
     * here, as MySQL and PostgreSQL would refuse such a value in a timestamp.
     *
     * @param  string  $stored
     * @param  class-string<\Throwable>  $exception
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('unreadableDeadlines')]
    public function testAnUnreadableDeadlineFailsClosed(string $stored, string $exception): void
    {
        Schema::table('mfa_factors', static function (Blueprint $table): void {
            $table->string('held_until')->nullable();
        });

        $user   = $this->user();
        $factor = RemappedLockoutFactor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            'status'               => 'confirmed',
        ]);

        DB::table('mfa_factors')->where('id', $factor->getKey())->update(['held_until' => $stored]);

        try {
            $this->service()->attempt(new Attempt($user, $factor, Purpose::SIGN_IN), static function (): bool {
                throw new MidRotationFailureException('The verification must not run.');
            });

            self::fail('An unreadable deadline must not read as no lockout.');
        } catch (\Throwable $thrown) {
            self::assertInstanceOf($exception, $thrown);
        }

        self::assertNull($this->state($user));

        $this->expectException($exception);

        $this->service()->lockout($user, $factor);
    }

    /**
     * Lifting the lockout of a factor that is not the identity's lifts nothing
     * and reports nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLiftingAnotherIdentitysFactorLockoutLiftsNothing(): void
    {
        Event::fake([LockoutLifted::class]);

        $owner  = $this->user('owner@example.com');
        $factor = $this->factor($owner);

        $this->lockFactor($factor);

        self::assertFalse($this->service()->liftLockout($this->user(), $factor));
        self::assertSame(AttemptScope::FACTOR, $this->service()->lockout($owner, $factor)?->scope);
        Event::assertNotDispatched(LockoutLifted::class);
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
        self::assertNull($this->fresh($factor)->getLockedUntil());
        self::assertSame(100, $this->fresh($factor)->getConsecutiveFailures());
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
        $factor = new InMemoryFactor;

        $this->attempt($user, $factor, false);

        self::assertTrue($this->attempt($user, $factor, false)->isFailed());
        self::assertSame(2, $this->state($user)?->consecutive_failures);
        self::assertNull($this->service()->lockout($user, $factor));
    }

    /**
     * From the failure ceiling on, the identity's run refuses every attempt
     * that names no factor of its own (a recovery code, or a factor that keeps
     * no state) without running the verification, while one of its factors may
     * still be attempted; proving it resets the run.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheIdentityRunAtTheCeilingRefusesAttemptsWithoutAFactor(): void
    {
        config()->set('mfa.attempts.failure_ceiling', 3);

        $user      = $this->user();
        $factor    = $this->factor($user);
        $stateless = new InMemoryFactor;

        $this->attempt($user, null, false);
        $this->attempt($user, $stateless, false);

        $reaching = $this->attempt($user, null, false);

        self::assertSame(AttemptScope::IDENTITY, $reaching->caused?->scope);
        self::assertTrue($reaching->caused->isDisabled());

        $refused = $this->service()->throttled(self::IP, fn (): AttemptOutcome => $this->service()->attempt(
            new Attempt($user, null, Purpose::SIGN_IN),
            static function (): bool {
                throw new MidRotationFailureException('The verification must not run.');
            },
        ));

        self::assertTrue($refused->isRefused());
        self::assertSame(AttemptScope::IDENTITY, $refused->lockout?->scope);
        self::assertTrue($refused->lockout->isDisabled());
        self::assertTrue($this->attempt($user, $stateless, true)->isRefused());
        self::assertTrue($this->service()->lockout($user)?->isDisabled());
        self::assertTrue($this->service()->lockout($user, $stateless)?->isDisabled());
        self::assertNull($this->service()->lockout($user, $factor));
        self::assertSame(3, $this->state($user)?->consecutive_failures);
        self::assertSame(3, $this->hits($this->keys()->ip(self::IP)));

        self::assertTrue($this->attempt($user, $factor, true)->passed);
        self::assertSame(0, $this->state($user)?->consecutive_failures);
        self::assertTrue($this->attempt($user, null, true)->passed);
    }

    /**
     * The failure that brings the identity's run to the failure ceiling, spread
     * across its factors, disables the factor it was made against, however few
     * failures in a row that factor has, and reports it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureAtTheIdentityCeilingDisablesTheFactorAttempted(): void
    {
        config()->set('mfa.attempts.failure_ceiling', 3);

        Event::fake([FactorDisabled::class]);

        $user   = $this->user();
        $first  = $this->factor($user);
        $second = $this->factor($user);

        $this->attempt($user, $first, false);
        $this->attempt($user, null, false);

        Event::assertNotDispatched(FactorDisabled::class);

        $this->attempt($user, $second, false);

        self::assertNotNull($this->fresh($second)->getDisabledAt());
        self::assertSame(1, $this->fresh($second)->getConsecutiveFailures());
        self::assertNull($this->fresh($first)->getDisabledAt());
        self::assertTrue($this->service()->lockout($user, $second)?->isDisabled());
        Event::assertDispatched(FactorDisabled::class, static fn (FactorDisabled $event): bool => $event->factor->id === $second->id);

        $this->attempt($user, $first, false);

        self::assertNotNull($this->fresh($first)->getDisabledAt());
    }

    /**
     * Resetting the identity's failures clears its run, so attempts without a
     * factor are made again; with no run there is nothing to reset.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testResettingTheIdentityFailuresClearsItsRun(): void
    {
        config()->set('mfa.attempts.failure_ceiling', 2);

        $user = $this->user();

        self::assertFalse($this->service()->resetIdentityFailures($user));

        $this->attempt($user, null, false);
        $this->attempt($user, null, false);

        self::assertTrue($this->service()->lockout($user)?->isDisabled());
        self::assertTrue($this->service()->resetIdentityFailures($user));
        self::assertSame(0, $this->state($user)?->consecutive_failures);
        self::assertNull($this->service()->lockout($user));
        self::assertFalse($this->service()->resetIdentityFailures($user));
        self::assertTrue($this->attempt($user, null, true)->passed);
    }

    /**
     * A factor removed before the lock is taken is not found: the verification
     * does not run and nothing is counted anywhere.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorRemovedBeforeTheLockIsNotFound(): void
    {
        $user   = $this->user();
        $factor = $this->factor($user);

        Factor::query()->whereKey($factor->id)->delete();

        $outcome = $this->service()->throttled(self::IP, fn (): AttemptOutcome => $this->service()->attempt(
            new Attempt($user, $factor, Purpose::SIGN_IN),
            static function (): bool {
                throw new MidRotationFailureException('The verification must not run.');
            },
        ));

        self::assertTrue($outcome->isNotFound());
        self::assertFalse($outcome->passed);
        self::assertSame(0, $this->state($user)?->consecutive_failures);
        self::assertSame(0, $this->hits($this->keys()->identity($user::class, (string) $user->id)));
        self::assertSame(0, $this->hits($this->keys()->ip(self::IP)));
    }

    /**
     * Another identity's factor is not among the identity's own, so it is not
     * found either, and its own count is left alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherIdentitysFactorIsNotFound(): void
    {
        $user  = $this->user();
        $other = $this->factor($this->user('other@example.com'), failures: 1);

        $outcome = $this->service()->attempt(new Attempt($user, $other, Purpose::SIGN_IN), static function (): bool {
            throw new MidRotationFailureException('The verification must not run.');
        });

        self::assertTrue($outcome->isNotFound());
        self::assertSame(1, $this->fresh($other)->getConsecutiveFailures());
    }

    /**
     * The verification is handed the factor as stored under the lock, not the
     * instance the caller read before; a factor that keeps no state is handed
     * as it is, and an attempt without a factor is handed none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheVerificationIsHandedTheFactorAsStored(): void
    {
        $user      = $this->user();
        $factor    = $this->factor($user);
        $stateless = new InMemoryFactor;
        $handed    = [];

        Factor::query()->whereKey($factor->id)->update(['label' => 'Replaced']);

        foreach ([$factor, $stateless, null] as $named) {
            $this->service()->attempt(new Attempt($user, $named, Purpose::SIGN_IN), static function (?FactorContract $stored) use (&$handed): bool {

                $handed[] = $stored;

                return true;
            });
        }

        self::assertInstanceOf(Factor::class, $handed[0]);
        self::assertNotSame($factor, $handed[0]);
        self::assertSame('Replaced', $handed[0]->getLabel());
        self::assertSame($stateless, $handed[1]);
        self::assertNull($handed[2]);
    }

    /**
     * A listener that throws once the attempt has committed leaves the failure
     * counted against the factor and the identity. The address's slot is given
     * back, since the exception reaches the throttle.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAListenerThatThrowsLeavesTheFailureCounted(): void
    {
        config()->set('mfa.attempts.factor_limit', 1);

        Event::listen(LockoutApplied::class, static function (): void {
            throw new MidRotationFailureException('listener failed');
        });

        $user   = $this->user();
        $factor = $this->factor($user);

        try {
            $this->attempt($user, $factor, false);

            self::fail('The listener\'s exception must propagate.');
        } catch (MidRotationFailureException $exception) {
            self::assertSame('listener failed', $exception->getMessage());
        }

        self::assertSame(1, $this->fresh($factor)->getConsecutiveFailures());
        self::assertSame(0, $this->hits($this->keys()->ip(self::IP)));
        self::assertSame(AttemptScope::FACTOR, $this->service()->lockout($user, $factor)?->scope);
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
            $this->service()->throttled(self::IP, fn (): AttemptOutcome => $this->service()->attempt(
                new Attempt($user, $factor, Purpose::SIGN_IN),
                static function (): bool {
                    throw new MidRotationFailureException('verification failed');
                },
            ));

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
     * The lockout read under the lock, without an address: none for a usable
     * factor, the factor's own once disabled, and the identity's once locked;
     * with no factor, the identity's run at the failure ceiling too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLockoutReadUnderTheLock(): void
    {
        $user   = $this->user();
        $factor = $this->factor($user);

        self::assertNull($this->service()->lockedOut($user, $factor));

        $locked = $this->factor($user);
        $until  = $this->lockFactor($locked);

        self::assertEquals($until, $this->service()->lockedOut($user, $this->fresh($locked))?->until);

        $disabled = $this->factor($user, disabled: true);

        self::assertTrue($this->service()->lockedOut($user, $disabled)?->isDisabled());

        config()->set('mfa.attempts.failure_ceiling', 1);

        IdentityState::query()->create(['authenticatable_type' => $user::class, 'authenticatable_id' => (string) $user->id, 'consecutive_failures' => 1]);

        self::assertNull($this->service()->lockedOut($user, $factor));
        self::assertSame(AttemptScope::IDENTITY, $this->service()->lockedOut($user, null)?->scope);

        IdentityState::query()->update(['consecutive_failures' => 0, 'locked_until' => Carbon::now()->addMinute()]);

        self::assertSame(AttemptScope::IDENTITY, $this->service()->lockedOut($user, $factor)?->scope);
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
        return $this->service()->throttled($ip, fn (): AttemptOutcome => $this->service()->attempt(new Attempt($user, $factor, Purpose::SIGN_IN), static fn (): bool => $passes));
    }

    /**
     * Lock the factor for five minutes, as its failures in a row would.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return \Carbon\CarbonImmutable
     */
    private function lockFactor(Factor $factor): CarbonImmutable
    {
        $until = CarbonImmutable::now()->addMinutes(5);

        Factor::query()->whereKey($factor->id)->update(['locked_until' => $until]);

        return $until;
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
