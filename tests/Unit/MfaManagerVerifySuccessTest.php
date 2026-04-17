<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Carbon\Carbon;
use Illuminate\Support\Facades\Event;
use Mockery;
use SineMacula\Laravel\Mfa\Contracts\Factor as FactorContract;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;
use SineMacula\Laravel\Mfa\Events\MfaVerified;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\TestUser;
use Tests\Unit\Concerns\InteractsWithMfaManagerVerify;

/**
 * Unit tests covering the verify success path and cache-invalidation invariants
 * on `MfaManager::verify()`.
 *
 * Split out from `MfaManagerVerifyTest` so the success-scenario and
 * cache-side-effect assertions stay cohesive and each test class remains under
 * the project's max-methods threshold.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MfaManagerVerifySuccessTest extends MfaManagerTestCase
{
    use InteractsWithMfaManagerVerify;

    /** @var string Canonical right-shape OTP fixture used for the success-path assertions. */
    private const string VALID_CODE = '123456';

    /** @var string Sentinel mismatch code used to drive cache-invalidation scenarios where the driver is stubbed to return success regardless of input. */
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
     * Test successful Eloquent verify returns true.
     *
     * @return void
     */
    public function testVerifySuccessReturnsTrueForEloquentFactor(): void
    {
        [$factor] = $this->seedEloquentVerifySuccessScenario();

        self::assertTrue($this->manager()->verify('email', $factor, self::VALID_CODE));
    }

    /**
     * Test successful Eloquent verify resets the attempt counter.
     *
     * @return void
     */
    public function testVerifySuccessResetsAttemptCounter(): void
    {
        [$factor] = $this->seedEloquentVerifySuccessScenario();

        $this->manager()->verify('email', $factor, self::VALID_CODE);

        $factor->refresh();

        self::assertSame(0, $factor->getAttempts());
    }

    /**
     * Test successful Eloquent verify stamps the factor verified_at.
     *
     * @return void
     */
    public function testVerifySuccessStampsVerifiedAtOnFactor(): void
    {
        [$factor] = $this->seedEloquentVerifySuccessScenario();

        $this->manager()->verify('email', $factor, self::VALID_CODE);

        $factor->refresh();

        self::assertNotNull($factor->getVerifiedAt());
    }

    /**
     * Test successful Eloquent verify clears the pending code.
     *
     * @return void
     */
    public function testVerifySuccessClearsPendingCode(): void
    {
        [$factor] = $this->seedEloquentVerifySuccessScenario();

        $this->manager()->verify('email', $factor, self::VALID_CODE);

        $factor->refresh();

        self::assertNull($factor->getCode());
    }

    /**
     * Test successful Eloquent verify dispatches MfaVerified event.
     *
     * @return void
     */
    public function testVerifySuccessDispatchesVerifiedEvent(): void
    {
        [$factor] = $this->seedEloquentVerifySuccessScenario();

        Event::fake();

        $this->manager()->verify('email', $factor, self::VALID_CODE);

        Event::assertDispatched(MfaVerified::class);
    }

    /**
     * Test successful Eloquent verify does not dispatch a failure event.
     *
     * @return void
     */
    public function testVerifySuccessDoesNotDispatchFailureEvent(): void
    {
        [$factor] = $this->seedEloquentVerifySuccessScenario();

        Event::fake();

        $this->manager()->verify('email', $factor, self::VALID_CODE);

        Event::assertNotDispatched(MfaVerificationFailed::class);
    }

    /**
     * Test verify success clears the per-identity manager cache.
     *
     * Pre-condition: the cache is warmed and the underlying row is deleted, so
     * a stale cache would still report `isSetup()` true. The post-verify
     * assertion observes the cache invalidation by proving `isSetup()` now
     * reflects the deleted state.
     *
     * @return void
     */
    public function testVerifySuccessClearsPerIdentityCache(): void
    {
        $manager = $this->seedWarmedCacheVerifyScenario();

        self::assertFalse($manager->isSetup());
    }

    /**
     * Test the warming setup remains true before verify is called.
     *
     * Documents the pre-condition the cache-clear assertion above relies on:
     * without the cache the underlying-row deletion would have already flipped
     * `isSetup()` to false.
     *
     * @return void
     */
    public function testCacheStaysWarmAfterUnderlyingRowDeletion(): void
    {
        $user = TestUser::query()->create([
            'email'       => 'v3-warm@example.com',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'driver'               => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);

        $manager = $this->manager();

        self::assertTrue($manager->isSetup());

        Factor::query()->where('authenticatable_id', $user->getKey())->delete();

        self::assertTrue($manager->isSetup(), 'cache still warm before verify');
    }

    /**
     * Stage the Eloquent-factor success scenario and return the persisted
     * factor for the assertions to observe.
     *
     * @return array{0: \SineMacula\Laravel\Mfa\Models\Factor}
     */
    private function seedEloquentVerifySuccessScenario(): array
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
            ->with(\Mockery::type(FactorContract::class), self::VALID_CODE)
            ->andReturnTrue();

        $this->stubDriver('email', $driver);

        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldReceive('markVerified')
            ->andReturn();

        $this->container()->instance(MfaVerificationStore::class, $store);

        return [$factor];
    }

    /**
     * Stage the warm-cache verify scenario: enrol a factor, warm the manager's
     * per-identity cache, delete the row, then run a successful verify so the
     * post-verify cache state is observable.
     *
     * @return \SineMacula\Laravel\Mfa\MfaManager
     */
    private function seedWarmedCacheVerifyScenario(): MfaManager
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
        $driver->shouldReceive('verify')->andReturnTrue();

        $this->stubDriver('totp', $driver);

        $manager = $this->manager();

        // Warm the setup cache.
        $manager->isSetup();

        // Remove the backing row so a stale cache would still report
        // `isSetup()` true after the verify.
        Factor::query()->where('authenticatable_id', $user->getKey())->delete();

        $manager->verify('totp', $factor, self::WRONG_CODE);

        return $manager;
    }
}
