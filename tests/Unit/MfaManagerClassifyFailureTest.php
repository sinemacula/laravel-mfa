<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Carbon\Carbon;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;
use SineMacula\Laravel\Mfa\MfaManager;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\Fixtures\Identities\TestUser;
use Tests\Unit\Concerns\InteractsWithMfaManagerVerify;

/**
 * Unit tests for `MfaManager::verify()` reason mapping.
 *
 * Split out from `MfaManagerVerifyTest` so each cohesive subject — the verify
 * orchestration pipeline vs. the failure-reason classifier — has a dedicated
 * suite under the project's max-methods-per-class threshold.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
final class MfaManagerClassifyFailureTest extends MfaManagerTestCase
{
    use InteractsWithMfaManagerVerify;

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
     * A TOTP-shape factor with no stored secret fails as `not_confirmed`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testClassifyFailureReturnsNotConfirmedForTotpShapedFactorWithoutSecret(): void
    {
        $user = TestUser::query()->create(['email' => 'cf1@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(type: 'totp', authenticatable: $user);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('totp', $driver);

        Event::fake();

        $this->manager()->verify('totp', $factor, self::WRONG_CODE);

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === FailureReason::NOT_CONFIRMED,
        );
    }

    /**
     * A factor whose pending code's expiry has passed fails as `expired`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testClassifyFailureReturnsExpiredWhenPendingCodeHasExpired(): void
    {
        $user = TestUser::query()->create(['email' => 'cf2@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(
            type         : 'email',
            code           : self::VALID_CODE,
            expiresAt      : Carbon::now()->subMinute(),
            authenticatable: $user,
        );

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('email', $driver);

        Event::fake();

        $this->manager()->verify('email', $factor, self::WRONG_CODE);

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === FailureReason::EXPIRED
                && $event->detail                                            === 'The pending code has expired.',
        );
    }

    /**
     * A TOTP factor with a stored secret whose verification still fails fails
     * as `invalid_code`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testClassifyFailureReturnsInvalidCodeForTotpSecretMismatch(): void
    {
        $user = TestUser::query()->create(['email' => 'cf3@example.com']);

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

        $this->manager()->verify('totp', $factor, self::WRONG_CODE);

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === FailureReason::INVALID_CODE,
        );
    }

    /**
     * A factor with a pending code but no expiry timestamp fails as `expired`,
     * with a detail that says no live code exists.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testClassifyFailureReturnsExpiredWhenPendingCodeHasNoExpiry(): void
    {
        $user = TestUser::query()->create(['email' => 'cf4@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(
            type         : 'email',
            code           : self::VALID_CODE,
            authenticatable: $user,
        );

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('email', $driver);

        Event::fake();

        $this->manager()->verify('email', $factor, self::WRONG_CODE);

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === FailureReason::EXPIRED
                && $event->detail                                            === 'The pending code has no expiry, so no live code exists.',
        );
    }

    /**
     * A factor with a valid pending code and a future expiry that the driver
     * still rejects fails as `invalid_code`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testClassifyFailureReturnsInvalidCodeForValidPendingCodeWithFutureExpiry(): void
    {
        $user = TestUser::query()->create(['email' => 'cf5@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(
            type         : 'email',
            code           : self::VALID_CODE,
            expiresAt      : Carbon::now()->addMinutes(5),
            authenticatable: $user,
        );

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('email', $driver);

        Event::fake();

        $this->manager()->verify('email', $factor, self::WRONG_CODE);

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === FailureReason::INVALID_CODE,
        );
    }
}
