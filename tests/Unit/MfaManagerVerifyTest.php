<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Carbon\Carbon;
use Illuminate\Contracts\Config\Repository;
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

    public function testVerifyReturnsFalseWhenNoIdentity(): void
    {
        $factor = new InMemoryFactor;

        $this->stubDriver('totp', $this->noopDriver());

        self::assertFalse($this->manager()->verify('totp', $factor, '123456'));
    }

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

        self::assertFalse($this->manager()->verify('totp', $factor, '000000'));

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::FactorLocked
                && $event->driver                                            === 'totp',
        );
    }

    public function testVerifySuccessPersistsAndDispatchesVerifiedEvent(): void
    {
        $user = TestUser::query()->create(['email' => 'v2@example.com']);

        $this->actingAs($user);

        $factor = Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->getKey(),
            'driver'               => 'email',
            'recipient'            => 'v2@example.com',
            'code'                 => '123456',
            'expires_at'           => Carbon::now()->addMinutes(10),
            'attempts'             => 1,
        ]);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')
            ->once()
            ->with(\Mockery::type(FactorContract::class), '123456')
            ->andReturnTrue();

        $this->stubDriver('email', $driver);

        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldReceive('markVerified')
            ->once()
            ->andReturn();

        $this->app->instance(MfaVerificationStore::class, $store);

        Event::fake();

        self::assertTrue($this->manager()->verify('email', $factor, '123456'));

        $factor->refresh();

        self::assertSame(0, $factor->getAttempts());
        self::assertNotNull($factor->getVerifiedAt());
        self::assertNull($factor->getCode());

        Event::assertDispatched(MfaVerified::class);
        Event::assertNotDispatched(MfaVerificationFailed::class);
    }

    public function testVerifySuccessClearsManagerCache(): void
    {
        $user = TestUser::query()->create([
            'email'       => 'v3@example.com',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        $factor = Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->getKey(),
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

        self::assertTrue($manager->verify('totp', $factor, '000000'));

        // Post-verify the identity cache is scoped-cleared.
        self::assertFalse($manager->isSetup());
    }

    public function testVerifyFailurePersistsAttemptAndDispatchesFailure(): void
    {
        $user = TestUser::query()->create(['email' => 'v4@example.com']);

        $this->actingAs($user);

        $factor = Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->getKey(),
            'driver'               => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
            'attempts'             => 0,
        ]);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('totp', $driver);

        Event::fake();

        self::assertFalse($this->manager()->verify('totp', $factor, '000000'));

        $factor->refresh();
        self::assertSame(1, $factor->getAttempts());
        self::assertNull($factor->getLockedUntil());

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::CodeInvalid,
        );
    }

    public function testVerifyFailureAppliesLockoutAtMaxAttemptsThreshold(): void
    {
        $user = TestUser::query()->create(['email' => 'v5@example.com']);

        $this->actingAs($user);

        /** @var Repository $config */
        $config = $this->app->make(Repository::class);
        $config->set('mfa.drivers.email.max_attempts', 3);
        $config->set('mfa.lockout_minutes', 7);

        $factor = Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->getKey(),
            'driver'               => 'email',
            'recipient'            => 'v5@example.com',
            'code'                 => '999999',
            'expires_at'           => Carbon::now()->addMinutes(10),
            'attempts'             => 2,
        ]);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('email', $driver);

        self::assertFalse($this->manager()->verify('email', $factor, '000000'));

        $factor->refresh();
        self::assertSame(3, $factor->getAttempts());

        $lockedUntil = $factor->getLockedUntil();

        self::assertNotNull($lockedUntil);
        self::assertTrue($lockedUntil->isFuture());
    }

    public function testVerifyFailureSkipsLockoutWhenMaxAttemptsIsZero(): void
    {
        $user = TestUser::query()->create(['email' => 'v6@example.com']);

        $this->actingAs($user);

        /** @var Repository $config */
        $config = $this->app->make(Repository::class);
        $config->set('mfa.drivers.totp.max_attempts', 0);

        $factor = Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->getKey(),
            'driver'               => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
            'attempts'             => 99,
        ]);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('totp', $driver);

        self::assertFalse($this->manager()->verify('totp', $factor, '000000'));

        $factor->refresh();
        self::assertNull($factor->getLockedUntil());
    }

    public function testVerifyFailureUsesFallbackLockoutMinutesWhenConfigIsNonInt(): void
    {
        $user = TestUser::query()->create(['email' => 'v7@example.com']);

        $this->actingAs($user);

        /** @var Repository $config */
        $config = $this->app->make(Repository::class);
        $config->set('mfa.drivers.email.max_attempts', 2);
        $config->set('mfa.lockout_minutes', 'not-an-int');

        $factor = Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->getKey(),
            'driver'               => 'email',
            'recipient'            => 'v7@example.com',
            'code'                 => '999999',
            'expires_at'           => Carbon::now()->addMinutes(10),
            'attempts'             => 1,
        ]);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('email', $driver);

        self::assertFalse($this->manager()->verify('email', $factor, '000000'));

        $factor->refresh();
        self::assertNotNull($factor->getLockedUntil());
    }

    public function testVerifyFailureTreatsNonIntMaxAttemptsAsZero(): void
    {
        $user = TestUser::query()->create(['email' => 'v8@example.com']);

        $this->actingAs($user);

        /** @var Repository $config */
        $config = $this->app->make(Repository::class);
        $config->set('mfa.drivers.totp.max_attempts', 'not-an-int');

        $factor = Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->getKey(),
            'driver'               => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
            'attempts'             => 5,
        ]);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('totp', $driver);

        self::assertFalse($this->manager()->verify('totp', $factor, '000000'));

        $factor->refresh();
        self::assertNull($factor->getLockedUntil());
    }

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

        self::assertFalse($this->manager()->verify('totp', $factor, '000000'));

        // In-memory factor is untouched because it does not implement
        // `EloquentFactor`.
        self::assertSame(0, $factor->getAttempts());

        Event::assertDispatched(MfaVerificationFailed::class);
    }

    public function testClassifyFailureReturnsSecretMissingForTotpShapedFactorWithoutSecret(): void
    {
        $user = TestUser::query()->create(['email' => 'cf1@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(driver: 'totp');

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('totp', $driver);

        Event::fake();

        $this->manager()->verify('totp', $factor, '000000');

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::SecretMissing,
        );
    }

    public function testClassifyFailureReturnsCodeExpiredWhenPendingCodeHasExpired(): void
    {
        $user = TestUser::query()->create(['email' => 'cf2@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(
            driver: 'email',
            code: '123456',
            expiresAt: Carbon::now()->subMinute(),
        );

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('email', $driver);

        Event::fake();

        $this->manager()->verify('email', $factor, '000000');

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::CodeExpired,
        );
    }

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

        $this->manager()->verify('totp', $factor, '000000');

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::CodeInvalid,
        );
    }

    public function testClassifyFailureReturnsCodeMissingWhenPendingCodeHasNoExpiry(): void
    {
        $user = TestUser::query()->create(['email' => 'cf4@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(
            driver: 'email',
            code: '123456',
        );

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('email', $driver);

        Event::fake();

        $this->manager()->verify('email', $factor, '000000');

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::CodeMissing,
        );
    }

    public function testClassifyFailureReturnsCodeInvalidForValidPendingCodeWithFutureExpiry(): void
    {
        $user = TestUser::query()->create(['email' => 'cf5@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(
            driver: 'email',
            code: '123456',
            expiresAt: Carbon::now()->addMinutes(5),
        );

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('email', $driver);

        Event::fake();

        $this->manager()->verify('email', $factor, '000000');

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
        $this->manager()->extend($name, static fn (): FactorDriver => $driver);
    }

    /**
     * Build a no-op driver stub whose `verify` method is never expected to
     * run (used when the pipeline short-circuits before driver dispatch).
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FactorDriver
     */
    private function noopDriver(): FactorDriver
    {
        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldNotReceive('verify');

        /** @var FactorDriver $driver */
        return $driver;
    }

    /**
     * Resolve the package's MFA manager from the container.
     *
     * @return \SineMacula\Laravel\Mfa\MfaManager
     */
    private function manager(): MfaManager
    {
        /** @var \SineMacula\Laravel\Mfa\MfaManager $manager */
        return $this->app->make('mfa');
    }
}
