<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Carbon\Carbon;
use Illuminate\Config\Repository;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Enums\MfaVerificationFailureReason;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\InMemoryFactor;
use Tests\Fixtures\TestUser;

/**
 * Unit tests for `MfaManager::verify()` covering every branch of the
 * orchestration pipeline and each outcome of `classifyFailure()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MfaManagerVerifyTest extends MfaManagerTestCase
{
    /** @var string Canonical right-shape OTP fixture used for the success-path assertions. */
    private const string VALID_CODE = '123456';

    /** @var string Sentinel mismatch code used to drive the failure-path assertions. */
    private const string WRONG_CODE = '000000';

    /**
     * Tear down Mockery expectations between test cases.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        if (class_exists(\Mockery::class)) {
            \Mockery::close();
        }

        parent::tearDown();
    }

    /**
     * Without a resolved identity `verify()` should short-circuit to false and
     * never invoke the driver.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifyReturnsFalseWhenNoIdentity(): void
    {
        $factor = new InMemoryFactor;

        $this->stubDriver('totp', $this->noopDriver());

        self::assertFalse($this->manager()->verify('totp', $factor, self::VALID_CODE));
    }

    /**
     * A locked factor must short-circuit to false and dispatch a
     * `MfaVerificationFailed` event with the `FactorLocked` reason.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifyReturnsFalseAndDispatchesWhenFactorLocked(): void
    {
        $user = TestUser::query()->create(['email' => 'v1@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(
            driver         : 'totp',
            secret         : 'JBSWY3DPEHPK3PXP',
            lockedUntil    : Carbon::now()->addMinutes(5),
            authenticatable: $user,
        );

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldNotReceive('verify');

        $this->stubDriver('totp', $driver);

        Event::fake();

        self::assertFalse($this->manager()->verify('totp', $factor, self::WRONG_CODE));

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::FACTOR_LOCKED
                && $event->driver                                            === 'totp',
        );
    }

    /**
     * A failed verify against an Eloquent factor should increment the attempt
     * counter and dispatch the failure event.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifyFailurePersistsAttemptAndDispatchesFailure(): void
    {
        $user = TestUser::query()->create(['email' => 'v4@example.com']);

        $this->actingAs($user);

        $factor = Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'driver'               => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
            'attempts'             => 0,
        ]);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('totp', $driver);

        Event::fake();

        self::assertFalse($this->manager()->verify('totp', $factor, self::WRONG_CODE));

        $factor->refresh();
        self::assertSame(1, $factor->getAttempts());
        self::assertNull($factor->getLockedUntil());

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::CODE_INVALID,
        );
    }

    /**
     * Crossing the configured `max_attempts` threshold must record a lockout
     * expiry on the factor.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifyFailureAppliesLockoutAtMaxAttemptsThreshold(): void
    {
        $user = TestUser::query()->create(['email' => 'v5@example.com']);

        $this->actingAs($user);

        $config = app(Repository::class);
        $config->set('mfa.drivers.email.max_attempts', 3);
        $config->set('mfa.lockout_minutes', 7);

        $factor = Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'driver'               => 'email',
            'recipient'            => 'v5@example.com',
            'code'                 => '999999',
            'expires_at'           => Carbon::now()->addMinutes(10),
            'attempts'             => 2,
        ]);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('email', $driver);

        self::assertFalse($this->manager()->verify('email', $factor, self::WRONG_CODE));

        $factor->refresh();
        self::assertSame(3, $factor->getAttempts());

        $lockedUntil = $factor->getLockedUntil();

        self::assertNotNull($lockedUntil);
        self::assertTrue($lockedUntil->isFuture());
    }

    /**
     * Configuring `max_attempts` to zero should disable lockout entirely, no
     * matter how many failed attempts have accrued.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifyFailureSkipsLockoutWhenMaxAttemptsIsZero(): void
    {
        $user = TestUser::query()->create(['email' => 'v6@example.com']);

        $this->actingAs($user);

        $config = app(Repository::class);
        $config->set('mfa.drivers.totp.max_attempts', 0);

        $factor = Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'driver'               => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
            'attempts'             => 99,
        ]);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('totp', $driver);

        self::assertFalse($this->manager()->verify('totp', $factor, self::WRONG_CODE));

        $factor->refresh();
        self::assertNull($factor->getLockedUntil());
    }

    /**
     * A non-int `mfa.lockout_minutes` config value should fall back to the
     * manager's safe default rather than break lockout.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifyFailureUsesFallbackLockoutMinutesWhenConfigIsNonInt(): void
    {
        $user = TestUser::query()->create(['email' => 'v7@example.com']);

        $this->actingAs($user);

        $config = app(Repository::class);
        $config->set('mfa.drivers.email.max_attempts', 2);
        $config->set('mfa.lockout_minutes', 'not-an-int');

        $factor = Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'driver'               => 'email',
            'recipient'            => 'v7@example.com',
            'code'                 => '999999',
            'expires_at'           => Carbon::now()->addMinutes(10),
            'attempts'             => 1,
        ]);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('email', $driver);

        self::assertFalse($this->manager()->verify('email', $factor, self::WRONG_CODE));

        $factor->refresh();
        self::assertNotNull($factor->getLockedUntil());
    }

    /**
     * A non-int `max_attempts` config value should be coerced to zero — i.e.
     * lockout disabled.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifyFailureTreatsNonIntMaxAttemptsAsZero(): void
    {
        $user = TestUser::query()->create(['email' => 'v8@example.com']);

        $this->actingAs($user);

        $config = app(Repository::class);
        $config->set('mfa.drivers.totp.max_attempts', 'not-an-int');

        $factor = Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'driver'               => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
            'attempts'             => 5,
        ]);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('totp', $driver);

        self::assertFalse($this->manager()->verify('totp', $factor, self::WRONG_CODE));

        $factor->refresh();
        self::assertNull($factor->getLockedUntil());
    }

    /**
     * Failure handling on a non-Eloquent factor must skip every persistence
     * side-effect while still dispatching the failure event.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifyFailureOnNonEloquentFactorSkipsStateMutation(): void
    {
        $user = TestUser::query()->create(['email' => 'v9@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(
            driver         : 'totp',
            secret         : 'JBSWY3DPEHPK3PXP',
            attempts       : 0,
            authenticatable: $user,
        );

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('totp', $driver);

        Event::fake();

        self::assertFalse($this->manager()->verify('totp', $factor, self::WRONG_CODE));

        // In-memory factor is untouched because it does not implement
        // `EloquentFactor`.
        self::assertSame(0, $factor->getAttempts());

        Event::assertDispatched(MfaVerificationFailed::class);
    }

    /**
     * Register a stub driver under the given name on the MFA manager.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @return void
     */
    private function stubDriver(string $name, FactorDriver $driver): void
    {
        $this->manager()->extend($name, fn (): FactorDriver => $driver);
    }

    /**
     * Resolve the package's MFA manager from the container.
     *
     * @return \SineMacula\Laravel\Mfa\MfaManager
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function manager(): MfaManager
    {
        $manager = $this->container()->make('mfa');
        Assert::assertInstanceOf(MfaManager::class, $manager);

        return $manager;
    }

    /**
     * Build a no-op driver stub whose `verify` method is never expected to run
     * (used when the pipeline short-circuits before driver dispatch).
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorDriver
     */
    private function noopDriver(): FactorDriver
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Mfa\Contracts\FactorDriver $driver */
        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldNotReceive('verify');

        return $driver;
    }
}
