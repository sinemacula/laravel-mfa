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

    public function testChallengeResetsAttemptsAndPersistsEloquentFactor(): void
    {
        $user = TestUser::query()->create(['email' => 'c1@example.com']);

        $this->actingAs($user);

        $factor = Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->getKey(),
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

        self::assertSame(0, $factor->getAttempts());

        Event::assertDispatched(
            MfaChallengeIssued::class,
            static fn (MfaChallengeIssued $event): bool => $event->driver === 'email'
                && $event->factor->getFactorIdentifier()                  === $factor->getFactorIdentifier(),
        );
    }

    public function testChallengeDispatchesThroughInMemoryFactorWithoutMutation(): void
    {
        $user = TestUser::query()->create(['email' => 'c2@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(driver: 'totp');

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('issueChallenge')
            ->once()
            ->with($factor);

        $this->stubDriver('totp', $driver);

        Event::fake();

        $this->manager()->challenge('totp', $factor);

        Event::assertDispatched(MfaChallengeIssued::class);
    }

    public function testChallengeIsNoopDispatchWhenNoIdentity(): void
    {
        $factor = new InMemoryFactor(driver: 'totp');

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('issueChallenge')
            ->once();

        $this->stubDriver('totp', $driver);

        $dispatcher = \Mockery::mock(Dispatcher::class);
        $dispatcher->shouldNotReceive('dispatch');

        $this->app->instance(Dispatcher::class, $dispatcher);

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
        $this->manager()->extend($name, static fn (): FactorDriver => $driver);
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
