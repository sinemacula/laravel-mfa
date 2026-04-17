<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\Event;
use Mockery;
use SineMacula\Laravel\Mfa\Contracts\Factor as FactorContract;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Events\MfaChallengeIssued;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\InMemoryFactor;
use Tests\Fixtures\TestUser;

/**
 * Unit tests for `MfaManager::challenge()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MfaManagerChallengeTest extends MfaManagerTestCase
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

    /**
     * The manager should hand the Eloquent factor through to the driver
     * unchanged — the per-driver attempt-state policy lives in
     * `FactorDriver::issueChallenge()` (OTP drivers reset alongside
     * minting a fresh code; TOTP and backup-code drivers preserve the
     * lockout because they cannot rotate any secret of their own).
     *
     * @return void
     */
    public function testChallengeDispatchesToDriverAndPersistsEloquentFactor(): void
    {
        $user = TestUser::query()->create(['email' => 'c1@example.com']);

        $this->actingAs($user);

        $factor = Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'driver'               => 'email',
            'recipient'            => 'c1@example.com',
            'attempts'             => 4,
        ]);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('issueChallenge')
            ->once()
            ->with(\Mockery::type(FactorContract::class));

        $this->stubDriver('email', $driver);

        Event::fake();

        $this->manager()->challenge('email', $factor);

        $factor->refresh();

        // The mock driver is a no-op; the manager must NOT have wiped
        // the attempt counter on its own behalf.
        self::assertSame(4, $factor->getAttempts());

        Event::assertDispatched(
            MfaChallengeIssued::class,
            static fn (MfaChallengeIssued $event): bool => $event->driver === 'email'
                && $event->factor->getFactorIdentifier()                  === $factor->getFactorIdentifier(),
        );
    }

    /**
     * For non-Eloquent factors the manager should still dispatch the
     * driver's `issueChallenge()` without attempting to persist any
     * state.
     *
     * @return void
     */
    public function testChallengeDispatchesThroughInMemoryFactorWithoutMutation(): void
    {
        $user = TestUser::query()->create(['email' => 'c2@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(driver: 'totp', authenticatable: $user);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('issueChallenge')
            ->once()
            ->with($factor);

        $this->stubDriver('totp', $driver);

        Event::fake();

        $this->manager()->challenge('totp', $factor);

        Event::assertDispatched(MfaChallengeIssued::class);
    }

    /**
     * Without a resolved identity the manager must short-circuit
     * before any driver work — issuing a challenge for "no one" is
     * meaningless and a stray dispatch would leak side effects to a
     * factor whose ownership cannot be checked.
     *
     * @return void
     */
    public function testChallengeIsNoopWhenNoIdentity(): void
    {
        $factor = new InMemoryFactor(driver: 'totp');

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldNotReceive('issueChallenge');

        $this->stubDriver('totp', $driver);

        $dispatcher = \Mockery::mock(Dispatcher::class);
        $dispatcher->shouldNotReceive('dispatch');

        $this->container()->instance(Dispatcher::class, $dispatcher);

        $this->manager()->challenge('totp', $factor);

        $this->addToAssertionCount(1);
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
     */
    private function manager(): MfaManager
    {
        $manager = $this->container()->make('mfa');
        \PHPUnit\Framework\Assert::assertInstanceOf(MfaManager::class, $manager);

        return $manager;
    }
}
