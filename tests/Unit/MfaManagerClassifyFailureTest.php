<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Carbon\Carbon;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Enums\MfaVerificationFailureReason;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;
use Tests\Fixtures\InMemoryFactor;
use Tests\Fixtures\TestUser;
use Tests\Unit\Concerns\InteractsWithMfaManagerVerify;

/**
 * Unit tests for `MfaManager::verify()` reason mapping.
 *
 * Split out from `MfaManagerVerifyTest` so each cohesive subject — the verify
 * orchestration pipeline vs. the failure-reason classifier — has a dedicated
 * suite under the project's max-methods-per-class threshold.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
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
    protected function tearDown(): void
    {
        if (class_exists(\Mockery::class)) {
            \Mockery::close();
        }

        parent::tearDown();
    }

    /**
     * `classifyFailure()` must report `SecretMissing` for a TOTP-shape factor
     * with no stored secret.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testClassifyFailureReturnsSecretMissingForTotpShapedFactorWithoutSecret(): void
    {
        $user = TestUser::query()->create(['email' => 'cf1@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(driver: 'totp', authenticatable: $user);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('totp', $driver);

        Event::fake();

        $this->manager()->verify('totp', $factor, self::WRONG_CODE);

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::SECRET_MISSING,
        );
    }

    /**
     * `classifyFailure()` must report `CodeExpired` when the factor carries a
     * pending code whose expiry has passed.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testClassifyFailureReturnsCodeExpiredWhenPendingCodeHasExpired(): void
    {
        $user = TestUser::query()->create(['email' => 'cf2@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(
            driver         : 'email',
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
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::CODE_EXPIRED,
        );
    }

    /**
     * `classifyFailure()` must report `CodeInvalid` when a TOTP factor has a
     * stored secret but verification still fails.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testClassifyFailureReturnsCodeInvalidForTotpSecretMismatch(): void
    {
        $user = TestUser::query()->create(['email' => 'cf3@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(
            driver         : 'totp',
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
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::CODE_INVALID,
        );
    }

    /**
     * `classifyFailure()` must report `CodeMissing` when the factor carries a
     * pending code but no expiry timestamp.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testClassifyFailureReturnsCodeMissingWhenPendingCodeHasNoExpiry(): void
    {
        $user = TestUser::query()->create(['email' => 'cf4@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(
            driver         : 'email',
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
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::CODE_MISSING,
        );
    }

    /**
     * `classifyFailure()` must report `CodeInvalid` when the factor carries a
     * valid pending code with a future expiry but the driver still rejects
     * verification.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testClassifyFailureReturnsCodeInvalidForValidPendingCodeWithFutureExpiry(): void
    {
        $user = TestUser::query()->create(['email' => 'cf5@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(
            driver         : 'email',
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
            static fn (MfaVerificationFailed $event): bool => $event->reason === MfaVerificationFailureReason::CODE_INVALID,
        );
    }
}
