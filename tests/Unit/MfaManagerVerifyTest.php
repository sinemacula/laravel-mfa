<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Carbon\Carbon;
use Illuminate\Config\Repository;
use Illuminate\Support\Facades\Event;
use Mockery;
use SineMacula\Laravel\Mfa\Contracts\Factor as FactorContract;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\Enums\MfaVerificationFailureReason;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;
use SineMacula\Laravel\Mfa\Events\MfaVerified;
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
     * Without a resolved identity `verify()` should short-circuit to
     * false and never invoke the driver.
     *
     * @return void
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
     */
    public function testVerifyReturnsFalseAndDispatchesWhenFactorLocked(): void
    {
        $user = TestUser::query()->create(['email' => 'v1@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(
            driver: 'totp',
            secret: 'JBSWY3DPEHPK3PXP',
            lockedUntil: Carbon::now()->addMinutes(5),
        );

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldNotReceive('verify');

        $this->stubDriver('totp', $driver);

        Event::fake();

        self::assertFalse($this->manager()->verify('totp', $factor, self::WRONG_CODE));

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::FactorLocked
                && $event->driver                                            === 'totp',
        );
    }

    /**
     * A successful verify against an Eloquent-backed factor should
     * persist the success state and dispatch the `MfaVerified` event.
     *
     * @return void
     */
    public function testVerifySuccessPersistsAndDispatchesVerifiedEvent(): void
    {
        $user = TestUser::query()->create(['email' => 'v2@example.com']);

        $this->actingAs($user);

        $factor = Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'driver'               => 'email',
            'recipient'            => 'v2@example.com',
            'code'                 => self::VALID_CODE,
            'expires_at'           => Carbon::now()->addMinutes(10),
            'attempts'             => 1,
        ]);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')
            ->once()
            ->with(\Mockery::type(FactorContract::class), self::VALID_CODE)
            ->andReturnTrue();

        $this->stubDriver('email', $driver);

        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldReceive('markVerified')
            ->once()
            ->andReturn();

        $this->container()->instance(MfaVerificationStore::class, $store);

        Event::fake();

        self::assertTrue($this->manager()->verify('email', $factor, self::VALID_CODE));

        $factor->refresh();

        self::assertSame(0, $factor->getAttempts());
        self::assertNotNull($factor->getVerifiedAt());
        self::assertNull($factor->getCode());

        Event::assertDispatched(MfaVerified::class);
        Event::assertNotDispatched(MfaVerificationFailed::class);
    }

    /**
     * A successful verify must clear the manager's per-identity cache
     * so subsequent state queries observe the updated factor row.
     *
     * @return void
     */
    public function testVerifySuccessClearsManagerCache(): void
    {
        $user = TestUser::query()->create([
            'email'       => 'v3@example.com',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        $factor = Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'driver'               => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')
            ->once()
            ->andReturnTrue();

        $this->stubDriver('totp', $driver);

        $manager = $this->manager();

        // Warm the setup cache.
        self::assertTrue($manager->isSetup());

        // Remove the backing row so a cache miss would return false.
        Factor::query()->where('authenticatable_id', $user->getKey())->delete();

        self::assertTrue($manager->isSetup(), 'cache still warm before verify');

        self::assertTrue($manager->verify('totp', $factor, self::WRONG_CODE));

        // Post-verify the identity cache is scoped-cleared.
        self::assertFalse($manager->isSetup());
    }

    /**
     * A failed verify against an Eloquent factor should increment the
     * attempt counter and dispatch the failure event.
     *
     * @return void
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
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::CodeInvalid,
        );
    }

    /**
     * Crossing the configured `max_attempts` threshold must record a
     * lockout expiry on the factor.
     *
     * @return void
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
     * Configuring `max_attempts` to zero should disable lockout
     * entirely, no matter how many failed attempts have accrued.
     *
     * @return void
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
     * A non-int `mfa.lockout_minutes` config value should fall back
     * to the manager's safe default rather than break lockout.
     *
     * @return void
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
     * A non-int `max_attempts` config value should be coerced to zero
     * — i.e. lockout disabled.
     *
     * @return void
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
     * Failure handling on a non-Eloquent factor must skip every
     * persistence side-effect while still dispatching the failure
     * event.
     *
     * @return void
     */
    public function testVerifyFailureOnNonEloquentFactorSkipsStateMutation(): void
    {
        $user = TestUser::query()->create(['email' => 'v9@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(
            driver: 'totp',
            secret: 'JBSWY3DPEHPK3PXP',
            attempts: 0,
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
     * `classifyFailure()` must report `SecretMissing` for a TOTP-shape
     * factor with no stored secret.
     *
     * @return void
     */
    public function testClassifyFailureReturnsSecretMissingForTotpShapedFactorWithoutSecret(): void
    {
        $user = TestUser::query()->create(['email' => 'cf1@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(driver: 'totp');

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('totp', $driver);

        Event::fake();

        $this->manager()->verify('totp', $factor, self::WRONG_CODE);

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::SecretMissing,
        );
    }

    /**
     * `classifyFailure()` must report `CodeExpired` when the factor
     * carries a pending code whose expiry has passed.
     *
     * @return void
     */
    public function testClassifyFailureReturnsCodeExpiredWhenPendingCodeHasExpired(): void
    {
        $user = TestUser::query()->create(['email' => 'cf2@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(
            driver: 'email',
            code: self::VALID_CODE,
            expiresAt: Carbon::now()->subMinute(),
        );

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('email', $driver);

        Event::fake();

        $this->manager()->verify('email', $factor, self::WRONG_CODE);

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::CodeExpired,
        );
    }

    /**
     * `classifyFailure()` must report `CodeInvalid` when a TOTP factor
     * has a stored secret but verification still fails.
     *
     * @return void
     */
    public function testClassifyFailureReturnsCodeInvalidForTotpSecretMismatch(): void
    {
        $user = TestUser::query()->create(['email' => 'cf3@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(
            driver: 'totp',
            secret: 'JBSWY3DPEHPK3PXP',
        );

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('totp', $driver);

        Event::fake();

        $this->manager()->verify('totp', $factor, self::WRONG_CODE);

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::CodeInvalid,
        );
    }

    /**
     * `classifyFailure()` must report `CodeMissing` when the factor
     * carries a pending code but no expiry timestamp.
     *
     * @return void
     */
    public function testClassifyFailureReturnsCodeMissingWhenPendingCodeHasNoExpiry(): void
    {
        $user = TestUser::query()->create(['email' => 'cf4@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(
            driver: 'email',
            code: self::VALID_CODE,
        );

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('email', $driver);

        Event::fake();

        $this->manager()->verify('email', $factor, self::WRONG_CODE);

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::CodeMissing,
        );
    }

    /**
     * `classifyFailure()` must report `CodeInvalid` when the factor
     * carries a valid pending code with a future expiry but the
     * driver still rejects verification.
     *
     * @return void
     */
    public function testClassifyFailureReturnsCodeInvalidForValidPendingCodeWithFutureExpiry(): void
    {
        $user = TestUser::query()->create(['email' => 'cf5@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(
            driver: 'email',
            code: self::VALID_CODE,
            expiresAt: Carbon::now()->addMinutes(5),
        );

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('email', $driver);

        Event::fake();

        $this->manager()->verify('email', $factor, self::WRONG_CODE);

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::CodeInvalid,
        );
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
     * Build a no-op driver stub whose `verify` method is never expected to
     * run (used when the pipeline short-circuits before driver dispatch).
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

    /**
     * Resolve the package's MFA manager from the container.
     *
     * @return \SineMacula\Laravel\Mfa\MfaManager
     */
    private function manager(): MfaManager
    {
        $manager = $this->container()->make('mfa');
        \PHPUnit\Framework\Assert::assertInstanceOf(MfaManager::class, $manager);

        return $manager;
    }
}
