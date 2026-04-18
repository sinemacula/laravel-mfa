<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Events\MfaChallengeIssued;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;
use SineMacula\Laravel\Mfa\Events\MfaVerified;
use SineMacula\Laravel\Mfa\Exceptions\FactorDriverMismatchException;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\InMemoryFactor;
use Tests\Fixtures\TestUser;

/**
 * Driver/factor identity enforcement at the manager boundary.
 *
 * `challenge()` and `verify()` accept both a driver name and a factor instance.
 * The two must agree — routing one driver's logic through a factor registered
 * against another is always a caller bug (different transport, different
 * persistence contract, confusing audit events). The manager fails fast with
 * `FactorDriverMismatchException` so the mistake cannot hide behind the
 * ownership check that runs immediately after.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MfaManagerDriverMismatchTest extends MfaManagerTestCase
{
    /** @var string Right-shape OTP value used to drive the rejected verify() paths. */
    private const string WRONG_CODE = '000000';

    /** @var string Distinguishing fragment of the mismatch-exception message — the marker used to confirm the guard fired. */
    private const string MISMATCH_MESSAGE = 'Driver mismatch';

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
     * `verify()` must reject a driver name that does not match the Eloquent
     * factor's registered driver — the driver is never invoked, no event is
     * dispatched, and the misconfiguration surfaces as
     * `FactorDriverMismatchException`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifyRejectsMismatchedDriverName(): void
    {
        [$user, $factor] = $this->stageEmailFactor();

        $this->actingAs($user);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldNotReceive('verify');

        $this->stubDriver('totp', $driver);

        Event::fake();

        $this->expectException(FactorDriverMismatchException::class);
        $this->expectExceptionMessage(self::MISMATCH_MESSAGE);

        try {
            $this->manager()->verify('totp', $factor, self::WRONG_CODE);
        } finally {
            Event::assertNotDispatched(MfaVerified::class);
            Event::assertNotDispatched(MfaVerificationFailed::class);
        }
    }

    /**
     * `challenge()` must reject a driver name that does not match the Eloquent
     * factor's registered driver — the driver is never invoked and no
     * `MfaChallengeIssued` event fires.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testChallengeRejectsMismatchedDriverName(): void
    {
        [$user, $factor] = $this->stageEmailFactor();

        $this->actingAs($user);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldNotReceive('issueChallenge');

        $this->stubDriver('sms', $driver);

        Event::fake();

        $this->expectException(FactorDriverMismatchException::class);
        $this->expectExceptionMessage(self::MISMATCH_MESSAGE);

        try {
            $this->manager()->challenge('sms', $factor);
        } finally {
            Event::assertNotDispatched(MfaChallengeIssued::class);
        }
    }

    /**
     * Mismatch enforcement must apply to non-Eloquent factors as well — the
     * manager reads the driver name off `Factor::getDriver()` regardless of
     * persistence backing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifyRejectsMismatchedDriverNameOnNonEloquentFactor(): void
    {
        $user = TestUser::query()->create([
            'email'       => 'mismatch-inmem@example.test',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        $factor = new InMemoryFactor(driver: 'totp', authenticatable: $user);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldNotReceive('verify');

        $this->stubDriver('email', $driver);

        $this->expectException(FactorDriverMismatchException::class);
        $this->expectExceptionMessage(self::MISMATCH_MESSAGE);

        $this->manager()->verify('email', $factor, self::WRONG_CODE);
    }

    /**
     * Stage an MFA-enabled user with a persisted `email`-driver factor owned by
     * that user. Returned as a tuple so individual tests can exercise the
     * mismatch shape without re-staging the setup.
     *
     * @return array{0: \Tests\Fixtures\TestUser, 1: \SineMacula\Laravel\Mfa\Models\Factor}
     */
    private function stageEmailFactor(): array
    {
        $user = TestUser::query()->create([
            'email'       => 'mismatch-user@example.test',
            'mfa_enabled' => true,
        ]);

        /** @var \SineMacula\Laravel\Mfa\Models\Factor $factor */
        $factor = Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'driver'               => 'email',
            'recipient'            => 'mismatch-user@example.test',
        ]);

        return [$user, $factor];
    }

    /**
     * Register a stub driver under the given name on the MFA manager.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
}
