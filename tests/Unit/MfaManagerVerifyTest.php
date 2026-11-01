<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Carbon\Carbon;
use Illuminate\Config\Repository;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\Fixtures\Identities\TestUser;

/**
 * Unit tests for `MfaManager::verify()` covering every branch of the
 * orchestration pipeline and each outcome of `classifyFailure()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
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
    #[\Override]
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
     * A locked identity must short-circuit to false and dispatch a
     * `MfaVerificationFailed` event with the `locked` reason.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifyReturnsFalseAndDispatchesWhenFactorLocked(): void
    {
        $user = TestUser::query()->create(['email' => 'v1@example.com']);

        $this->actingAs($user);

        IdentityState::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'locked_until'         => Carbon::now()->addMinutes(5),
        ]);

        $factor = new InMemoryFactor(
            type         : 'totp',
            secret         : 'JBSWY3DPEHPK3PXP',
            authenticatable: $user,
        );

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldNotReceive('verify');

        $this->stubDriver('totp', $driver);

        Event::fake();

        self::assertFalse($this->manager()->verify('totp', $factor, self::WRONG_CODE));

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === FailureReason::LOCKED
                && $event->driver                                            === 'totp',
        );
    }

    /**
     * A failed verify against an Eloquent factor should count a failure in a
     * row and dispatch the failure event.
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
            'type'                 => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('totp', $driver);

        Event::fake();

        self::assertFalse($this->manager()->verify('totp', $factor, self::WRONG_CODE));

        $factor->refresh();
        self::assertSame(1, $factor->getConsecutiveFailures());
        self::assertNull($this->attempts()->lockout($user, $factor));

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === FailureReason::INVALID_CODE,
        );
    }

    /**
     * Crossing the configured `mfa.attempts.factor_limit` threshold must lock
     * the factor for the configured lockout.
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
        $config->set('mfa.attempts.factor_limit', 3);
        $config->set('mfa.attempts.lockout_seconds', 420);

        $factor = Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'email',
            'destination'          => 'v5@example.com',
            'consecutive_failures' => 2,
        ]);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('email', $driver);

        self::assertFalse($this->manager()->verify('email', $factor, self::WRONG_CODE));

        $factor->refresh();
        self::assertSame(3, $factor->getConsecutiveFailures());

        $lockout = $this->attempts()->lockout($user, $factor);

        self::assertNotNull($lockout);
        self::assertSame(AttemptScope::FACTOR, $lockout->scope);
        self::assertNotNull($lockout->until);
        self::assertTrue($lockout->until->isFuture());
        self::assertLessThanOrEqual(420, Carbon::now()->diffInSeconds($lockout->until));
    }

    /**
     * A malformed attempt limit fails closed with an exception naming the key,
     * rather than skipping the lockout.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifyFailureRefusesAMalformedAttemptLimit(): void
    {
        $user = TestUser::query()->create(['email' => 'v8@example.com']);

        $this->actingAs($user);

        $factor = Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
            'consecutive_failures' => 5,
        ]);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('totp', $driver);

        app(Repository::class)->set('mfa.attempts.factor_limit', 'not-an-int');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('mfa.attempts.factor_limit must be an integer from 1 to 20.');

        $this->manager()->verify('totp', $factor, self::WRONG_CODE);
    }

    /**
     * Failure handling on a non-Eloquent factor must skip the factor's own
     * state, which it does not keep, while still charging the identity and
     * dispatching the failure event.
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
            type         : 'totp',
            secret         : 'JBSWY3DPEHPK3PXP',
            authenticatable: $user,
        );

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('totp', $driver);

        Event::fake();

        self::assertFalse($this->manager()->verify('totp', $factor, self::WRONG_CODE));

        // In-memory factor is untouched because it does not implement
        // `EloquentFactor`; the identity is charged all the same.
        self::assertSame(0, $factor->getConsecutiveFailures());
        self::assertSame(1, IdentityState::query()->where('authenticatable_id', (string) $user->id)->value('consecutive_failures'));

        Event::assertDispatched(MfaVerificationFailed::class);
    }

    /**
     * Resolve the attempt service.
     *
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function attempts(): AttemptService
    {
        return $this->container()->make(AttemptService::class);
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
