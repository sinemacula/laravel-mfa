<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\TestUser;
use Tests\Unit\Concerns\InteractsWithMfaManagerState;

/**
 * Unit tests for `MfaManager` lifecycle mutations.
 *
 * Covers `markVerified()`, `forgetVerification()`, and `clearCache()`.
 * Split out from the broader state-test family so each subject stays
 * under the project's max-methods-per-class threshold.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MfaManagerLifecycleTest extends MfaManagerTestCase
{
    use InteractsWithMfaManagerState;

    /**
     * Without an identity `markVerified()` must not touch the
     * verification store.
     *
     * @return void
     */
    public function testMarkVerifiedIsNoopWhenNoIdentity(): void
    {
        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldNotReceive('markVerified');

        $this->container()->instance(MfaVerificationStore::class, $store);

        $this->manager()->markVerified();

        $this->addToAssertionCount(1);
    }

    /**
     * With an identity `markVerified()` should delegate to the bound
     * store's `markVerified()` method.
     *
     * @return void
     */
    public function testMarkVerifiedDelegatesToStore(): void
    {
        $user = TestUser::query()->create(['email' => 'p@example.com']);

        $this->actingAs($user);

        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldReceive('markVerified')
            ->once()
            ->with(\Mockery::type(Authenticatable::class));

        $this->container()->instance(MfaVerificationStore::class, $store);

        $this->manager()->markVerified();

        $this->addToAssertionCount(1);
    }

    /**
     * Without an identity `forgetVerification()` must not touch the
     * verification store.
     *
     * @return void
     */
    public function testForgetVerificationIsNoopWhenNoIdentity(): void
    {
        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldNotReceive('forget');

        $this->container()->instance(MfaVerificationStore::class, $store);

        $this->manager()->forgetVerification();

        $this->addToAssertionCount(1);
    }

    /**
     * With an identity `forgetVerification()` should delegate to the
     * bound store's `forget()` method.
     *
     * @return void
     */
    public function testForgetVerificationDelegatesToStore(): void
    {
        $user = TestUser::query()->create(['email' => 'q@example.com']);

        $this->actingAs($user);

        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldReceive('forget')
            ->once()
            ->with(\Mockery::type(Authenticatable::class));

        $this->container()->instance(MfaVerificationStore::class, $store);

        $this->manager()->forgetVerification();

        $this->addToAssertionCount(1);
    }

    /**
     * Calling `clearCache()` without an identity argument should
     * flush every cached entry across the manager.
     *
     * @return void
     */
    public function testClearCacheWithoutIdentityFlushesEverything(): void
    {
        $user = $this->makeUserWithFactor();

        $this->actingAs($user);

        $manager = $this->manager();

        self::assertTrue($manager->isSetup());

        Factor::query()->where('authenticatable_id', $user->getKey())->delete();

        // Still cached before flush.
        self::assertTrue($manager->isSetup());

        $manager->clearCache();

        self::assertFalse($manager->isSetup());
    }

    /**
     * Scoping `clearCache()` to a single identity must leave other
     * identities' cache entries intact.
     *
     * @return void
     */
    public function testClearCacheScopedToIdentityLeavesOthersAlone(): void
    {
        $userA = $this->makeUserWithFactor('user-a@example.com');
        $userB = $this->makeUserWithFactor('user-b@example.com');

        $manager = $this->manager();

        $this->actingAs($userA);
        self::assertTrue($manager->isSetup());

        $this->actingAs($userB);
        self::assertTrue($manager->isSetup());

        // Wipe the underlying data for both users, then scope-clear A.
        Factor::query()->delete();

        $manager->clearCache($userA);

        $this->actingAs($userA);
        self::assertFalse($manager->isSetup());

        // B's cache entry survives the scoped clear.
        $this->actingAs($userB);
        self::assertTrue($manager->isSetup());
    }
}
