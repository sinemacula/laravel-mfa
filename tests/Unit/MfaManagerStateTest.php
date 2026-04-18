<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Carbon\Carbon;
use Illuminate\Support\Facades\Auth;
use SineMacula\Laravel\Mfa\Contracts\MfaPolicy;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\NonScalarIdentifierUser;
use Tests\Fixtures\PlainUser;
use Tests\Fixtures\TestUser;
use Tests\Unit\Concerns\InteractsWithMfaManagerState;

/**
 * Unit tests for `MfaManager` lookup-style state queries.
 *
 * Covers `getDefaultDriver()`, `shouldUse()`, `isSetup()`, `hasEverVerified()`,
 * and `getFactors()`. The expiry-window and lifecycle-mutation surfaces live in
 * dedicated sibling files (`MfaManagerExpiryTest`, `MfaManagerLifecycleTest`)
 * so each subject stays under the project's max-methods-per-class threshold
 * without losing its cohesive grouping.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MfaManagerStateTest extends MfaManagerTestCase
{
    use InteractsWithMfaManagerState;

    /**
     * The shipped default driver should be `'totp'`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testGetDefaultDriverReturnsTotp(): void
    {
        $manager = $this->manager();

        self::assertSame('totp', $manager->getDefaultDriver());
    }

    /**
     * Without an identity in the guard, `shouldUse()` must return false
     * regardless of the bound policy.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testShouldUseReturnsFalseWhenNoIdentityResolved(): void
    {
        self::assertFalse($this->manager()->shouldUse());
    }

    /**
     * An identity that does not implement `MultiFactorAuthenticatable` must
     * short-circuit `shouldUse()` to false.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testShouldUseReturnsFalseWhenIdentityIsNotMfaAuthenticatable(): void
    {
        $plain = new PlainUser;

        $this->actingAs($plain);

        self::assertFalse($this->manager()->shouldUse());
    }

    /**
     * An identity opting in via `shouldUseMultiFactor()` should make
     * `shouldUse()` return true without consulting the policy.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testShouldUseReturnsTrueWhenIdentityOptsIn(): void
    {
        $user = TestUser::query()->create([
            'email'       => 'a@example.com',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        self::assertTrue($this->manager()->shouldUse());
    }

    /**
     * When the identity does not opt in but the bound `MfaPolicy` enforces MFA
     * externally, `shouldUse()` should still return true.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testShouldUseReturnsTrueWhenPolicyEnforces(): void
    {
        $user = TestUser::query()->create([
            'email'       => 'b@example.com',
            'mfa_enabled' => false,
        ]);

        $this->actingAs($user);

        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Mfa\Contracts\MfaPolicy $policy */
        $policy = \Mockery::mock(MfaPolicy::class);
        $policy->shouldReceive('shouldEnforce')
            ->once()
            ->andReturnTrue();

        $this->container()->instance(MfaPolicy::class, $policy);

        self::assertTrue($this->manager()->shouldUse());
    }

    /**
     * If neither the identity nor the policy enforces MFA, the manager must
     * report `shouldUse()` as false.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testShouldUseReturnsFalseWhenNeitherIdentityNorPolicyEnforce(): void
    {
        $user = TestUser::query()->create([
            'email'       => 'c@example.com',
            'mfa_enabled' => false,
        ]);

        $this->actingAs($user);

        self::assertFalse($this->manager()->shouldUse());
    }

    /**
     * Without an identity `isSetup()` must report false rather than throwing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testIsSetupReturnsFalseWhenNoIdentity(): void
    {
        self::assertFalse($this->manager()->isSetup());
    }

    /**
     * An identity with no factor rows in the database must report `isSetup()`
     * as false.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testIsSetupReturnsFalseWhenIdentityHasNoFactors(): void
    {
        $user = TestUser::query()->create([
            'email'       => 'd@example.com',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        self::assertFalse($this->manager()->isSetup());
    }

    /**
     * An identity with at least one persisted factor must report `isSetup()` as
     * true.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testIsSetupReturnsTrueWhenIdentityHasFactor(): void
    {
        $user = $this->makeUserWithFactor();

        $this->actingAs($user);

        self::assertTrue($this->manager()->isSetup());
    }

    /**
     * Repeated `isSetup()` calls within a single request must hit the runtime
     * cache rather than re-querying the database.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testIsSetupCachesResultBetweenCalls(): void
    {
        $user = $this->makeUserWithFactor();

        $this->actingAs($user);

        $manager = $this->manager();

        self::assertTrue($manager->isSetup());

        // Wipe the underlying data — the cached entry must survive.
        Factor::query()->where('authenticatable_id', $user->getKey())->delete();

        self::assertTrue($manager->isSetup());
    }

    /**
     * Without an identity `hasEverVerified()` must short-circuit to false.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testHasEverVerifiedReturnsFalseWhenNoIdentity(): void
    {
        self::assertFalse($this->manager()->hasEverVerified());
    }

    /**
     * When the bound store reports no prior verification timestamp,
     * `hasEverVerified()` must return false.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testHasEverVerifiedReturnsFalseWhenStoreReturnsNull(): void
    {
        $user = TestUser::query()->create(['email' => 'e@example.com']);

        $this->actingAs($user);

        $this->container()->instance(
            MfaVerificationStore::class,
            $this->nullStore(),
        );

        self::assertFalse($this->manager()->hasEverVerified());
    }

    /**
     * When the bound store reports a non-null verification timestamp,
     * `hasEverVerified()` must return true.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testHasEverVerifiedReturnsTrueWhenStoreReturnsTimestamp(): void
    {
        $user = TestUser::query()->create(['email' => 'f@example.com']);

        $this->actingAs($user);

        $this->container()->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->subMinute()),
        );

        self::assertTrue($this->manager()->hasEverVerified());
    }

    /**
     * Without an identity `getFactors()` must return null instead of an empty
     * collection.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testGetFactorsReturnsNullWhenNoIdentity(): void
    {
        self::assertNull($this->manager()->getFactors());
    }

    /**
     * With an identity `getFactors()` should return a collection of persisted
     * factor models.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testGetFactorsReturnsCollectionOfFactors(): void
    {
        $user = $this->makeUserWithFactor();

        $this->actingAs($user);

        $factors = $this->manager()->getFactors();

        self::assertNotNull($factors);
        self::assertCount(1, $factors);
        self::assertInstanceOf(Factor::class, $factors->first());
    }

    /**
     * `getFactors()` should cache its returned collection so repeated calls
     * within the same request do not re-query the database.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testGetFactorsCachesCollectionBetweenCalls(): void
    {
        $user = $this->makeUserWithFactor();

        $this->actingAs($user);

        $manager = $this->manager();

        $first = $manager->getFactors();

        // Mutate the underlying store; cached result stays stable.
        Factor::query()->where('authenticatable_id', $user->getKey())->delete();

        $second = $manager->getFactors();

        self::assertSame($first, $second);
    }

    /**
     * `isSetup()` must complete without throwing when the resolved identity's
     * auth identifier is non-scalar (neither string nor int). The empty-suffix
     * fallback inside the cache-prefix builder is exercised on the way in; the
     * actual composition is private to the manager and asserted indirectly
     * through the no-throw outcome here.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testIsSetupCompletesForNonScalarAuthIdentifierWithoutThrowing(): void
    {
        $identity = new NonScalarIdentifierUser;

        Auth::shouldReceive('user')->andReturn($identity);

        self::assertFalse($this->manager()->isSetup());
    }
}
