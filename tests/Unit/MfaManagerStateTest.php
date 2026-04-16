<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Carbon\Carbon;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Facades\Auth;
use Mockery;
use SineMacula\Laravel\Mfa\Contracts\MfaPolicy;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\NonScalarIdentifierUser;
use Tests\Fixtures\PlainUser;
use Tests\Fixtures\TestUser;

/**
 * Unit tests for `MfaManager` state-query and cache methods.
 *
 * Covers `getDefaultDriver()`, `shouldUse()`, `isSetup()`,
 * `hasEverVerified()`, `hasExpired()`, `markVerified()`,
 * `forgetVerification()`, `clearCache()`, and `getFactors()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MfaManagerStateTest extends MfaManagerTestCase
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

    public function testGetDefaultDriverReturnsTotp(): void
    {
        $manager = $this->manager();

        self::assertSame('totp', $manager->getDefaultDriver());
    }

    public function testShouldUseReturnsFalseWhenNoIdentityResolved(): void
    {
        $manager = $this->manager();

        self::assertFalse($manager->shouldUse());
    }

    public function testShouldUseReturnsFalseWhenIdentityIsNotMfaAuthenticatable(): void
    {
        $plain = PlainUser::query()->create(['email' => 'plain@example.com']);

        $this->actingAs($plain);

        self::assertFalse($this->manager()->shouldUse());
    }

    public function testShouldUseReturnsTrueWhenIdentityOptsIn(): void
    {
        $user = TestUser::query()->create([
            'email'       => 'a@example.com',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        self::assertTrue($this->manager()->shouldUse());
    }

    public function testShouldUseReturnsTrueWhenPolicyEnforces(): void
    {
        $user = TestUser::query()->create([
            'email'       => 'b@example.com',
            'mfa_enabled' => false,
        ]);

        $policy = \Mockery::mock(MfaPolicy::class);
        $policy->shouldReceive('shouldEnforce')
            ->once()
            ->with(\Mockery::type(Authenticatable::class))
            ->andReturnTrue();

        $this->app->instance(MfaPolicy::class, $policy);

        $this->actingAs($user);

        self::assertTrue($this->manager()->shouldUse());
    }

    public function testShouldUseReturnsFalseWhenNeitherIdentityNorPolicyEnforce(): void
    {
        $user = TestUser::query()->create([
            'email'       => 'c@example.com',
            'mfa_enabled' => false,
        ]);

        $this->actingAs($user);

        self::assertFalse($this->manager()->shouldUse());
    }

    public function testIsSetupReturnsFalseWhenNoIdentity(): void
    {
        self::assertFalse($this->manager()->isSetup());
    }

    public function testIsSetupReturnsFalseWhenIdentityHasNoFactors(): void
    {
        $user = TestUser::query()->create([
            'email'       => 'd@example.com',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        self::assertFalse($this->manager()->isSetup());
    }

    public function testIsSetupReturnsTrueWhenIdentityHasFactor(): void
    {
        $user = $this->makeUserWithFactor();

        $this->actingAs($user);

        self::assertTrue($this->manager()->isSetup());
    }

    public function testIsSetupCachesResultBetweenCalls(): void
    {
        $user = $this->makeUserWithFactor();

        $this->actingAs($user);

        $manager = $this->manager();

        self::assertTrue($manager->isSetup());

        // Delete the factor after the first lookup. The cached result
        // should remain truthy because the manager does not re-query
        // the database on subsequent calls within the same request.
        Factor::query()->where('authenticatable_id', $user->getKey())->delete();

        self::assertTrue($manager->isSetup());
    }

    public function testHasEverVerifiedReturnsFalseWhenNoIdentity(): void
    {
        self::assertFalse($this->manager()->hasEverVerified());
    }

    public function testHasEverVerifiedReturnsFalseWhenStoreReturnsNull(): void
    {
        $user = TestUser::query()->create(['email' => 'e@example.com']);

        $this->actingAs($user);

        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldReceive('lastVerifiedAt')
            ->once()
            ->andReturnNull();

        $this->app->instance(MfaVerificationStore::class, $store);

        self::assertFalse($this->manager()->hasEverVerified());
    }

    public function testHasEverVerifiedReturnsTrueWhenStoreReturnsTimestamp(): void
    {
        $user = TestUser::query()->create(['email' => 'f@example.com']);

        $this->actingAs($user);

        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldReceive('lastVerifiedAt')
            ->once()
            ->andReturn(Carbon::now());

        $this->app->instance(MfaVerificationStore::class, $store);

        self::assertTrue($this->manager()->hasEverVerified());
    }

    public function testHasExpiredReturnsTrueWhenNoIdentity(): void
    {
        self::assertTrue($this->manager()->hasExpired());
    }

    public function testHasExpiredReturnsTrueWhenNoPriorVerification(): void
    {
        $user = TestUser::query()->create(['email' => 'g@example.com']);

        $this->actingAs($user);

        $this->app->instance(
            MfaVerificationStore::class,
            $this->nullStore(),
        );

        self::assertTrue($this->manager()->hasExpired());
    }

    public function testHasExpiredUsesConfiguredDefaultExpiryWhenParameterOmitted(): void
    {
        $user = TestUser::query()->create(['email' => 'h@example.com']);

        $this->actingAs($user);

        /** @var Repository $config */
        $config = $this->app->make(Repository::class);
        $config->set('mfa.default_expiry', 60);

        $this->app->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->subMinutes(30)),
        );

        self::assertFalse($this->manager()->hasExpired());
    }

    public function testHasExpiredReturnsFalseForRecentVerificationWithExplicitExpiry(): void
    {
        $user = TestUser::query()->create(['email' => 'i@example.com']);

        $this->actingAs($user);

        $this->app->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->subMinutes(5)),
        );

        self::assertFalse($this->manager()->hasExpired(60));
    }

    public function testHasExpiredReturnsTrueWhenExplicitExpiryIsZero(): void
    {
        $user = TestUser::query()->create(['email' => 'j@example.com']);

        $this->actingAs($user);

        $this->app->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->subMinutes(1)),
        );

        self::assertTrue($this->manager()->hasExpired(0));
    }

    public function testHasExpiredReturnsTrueWhenExplicitExpiryIsNegative(): void
    {
        $user = TestUser::query()->create(['email' => 'k@example.com']);

        $this->actingAs($user);

        $this->app->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->subMinutes(1)),
        );

        self::assertTrue($this->manager()->hasExpired(-5));
    }

    public function testHasExpiredReturnsTrueForFutureDatedVerification(): void
    {
        $user = TestUser::query()->create(['email' => 'l@example.com']);

        $this->actingAs($user);

        // Clock-skew defence: a store that reports a verification in
        // the future should not be trusted as "still valid".
        $this->app->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->addMinutes(30)),
        );

        self::assertTrue($this->manager()->hasExpired(60));
    }

    public function testHasExpiredReturnsTrueWhenElapsedExceedsExpiry(): void
    {
        $user = TestUser::query()->create(['email' => 'm@example.com']);

        $this->actingAs($user);

        $this->app->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->subMinutes(120)),
        );

        self::assertTrue($this->manager()->hasExpired(60));
    }

    public function testHasExpiredDefaultsToFallbackExpiryWhenConfigIsNonNumeric(): void
    {
        $user = TestUser::query()->create(['email' => 'n@example.com']);

        $this->actingAs($user);

        /** @var Repository $config */
        $config = $this->app->make(Repository::class);
        $config->set('mfa.default_expiry', 'not-a-number');

        $this->app->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->subMinute()),
        );

        // A non-numeric config falls back to 0 via the manager's
        // `resolveDefaultExpiry()` defence, meaning any prior
        // verification is treated as expired.
        self::assertTrue($this->manager()->hasExpired());
    }

    public function testHasExpiredCoercesNumericStringConfigToInt(): void
    {
        $user = TestUser::query()->create(['email' => 'o@example.com']);

        $this->actingAs($user);

        /** @var Repository $config */
        $config = $this->app->make(Repository::class);
        $config->set('mfa.default_expiry', '60');

        $this->app->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->subMinutes(10)),
        );

        self::assertFalse($this->manager()->hasExpired());
    }

    public function testMarkVerifiedIsNoopWhenNoIdentity(): void
    {
        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldNotReceive('markVerified');

        $this->app->instance(MfaVerificationStore::class, $store);

        $this->manager()->markVerified();

        $this->addToAssertionCount(1);
    }

    public function testMarkVerifiedDelegatesToStore(): void
    {
        $user = TestUser::query()->create(['email' => 'p@example.com']);

        $this->actingAs($user);

        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldReceive('markVerified')
            ->once()
            ->with(\Mockery::type(Authenticatable::class));

        $this->app->instance(MfaVerificationStore::class, $store);

        $this->manager()->markVerified();

        $this->addToAssertionCount(1);
    }

    public function testForgetVerificationIsNoopWhenNoIdentity(): void
    {
        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldNotReceive('forget');

        $this->app->instance(MfaVerificationStore::class, $store);

        $this->manager()->forgetVerification();

        $this->addToAssertionCount(1);
    }

    public function testForgetVerificationDelegatesToStore(): void
    {
        $user = TestUser::query()->create(['email' => 'q@example.com']);

        $this->actingAs($user);

        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldReceive('forget')
            ->once()
            ->with(\Mockery::type(Authenticatable::class));

        $this->app->instance(MfaVerificationStore::class, $store);

        $this->manager()->forgetVerification();

        $this->addToAssertionCount(1);
    }

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

    public function testGetFactorsReturnsNullWhenNoIdentity(): void
    {
        self::assertNull($this->manager()->getFactors());
    }

    public function testGetFactorsReturnsCollectionOfFactors(): void
    {
        $user = $this->makeUserWithFactor();

        $this->actingAs($user);

        $factors = $this->manager()->getFactors();

        self::assertNotNull($factors);
        self::assertCount(1, $factors);
        self::assertInstanceOf(Factor::class, $factors->first());
    }

    public function testIsSetupHandlesNonScalarAuthIdentifierViaEmptySuffix(): void
    {
        $identity = new NonScalarIdentifierUser;

        Auth::shouldReceive('user')->andReturn($identity);

        // `isSetup()` forces the manager through `getCachePrefix()`,
        // which must accept an identity whose auth identifier is
        // neither a string nor an int by falling back to an empty
        // suffix rather than throwing.
        self::assertFalse($this->manager()->isSetup());
    }

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
     * Resolve the package's MFA manager instance from the container.
     *
     * @return \SineMacula\Laravel\Mfa\MfaManager
     */
    private function manager(): MfaManager
    {
        /** @var \SineMacula\Laravel\Mfa\MfaManager $manager */
        return $this->app->make('mfa');
    }

    /**
     * Create a test user with a single backing TOTP factor.
     *
     * @param  string  $email
     * @return \Tests\Fixtures\TestUser
     */
    private function makeUserWithFactor(string $email = 'user@example.com'): TestUser
    {
        /** @var TestUser $user */
        $user = TestUser::query()->create([
            'email'       => $email,
            'mfa_enabled' => true,
        ]);

        Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->getKey(),
            'driver'               => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);

        return $user;
    }

    /**
     * Build a store mock whose `lastVerifiedAt()` always returns the
     * supplied timestamp.
     *
     * @param  \Carbon\Carbon  $at
     * @return \SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore
     */
    private function fixedStore(Carbon $at): MfaVerificationStore
    {
        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldReceive('lastVerifiedAt')
            ->andReturn($at);

        /** @var MfaVerificationStore $store */
        return $store;
    }

    /**
     * Build a store mock whose `lastVerifiedAt()` always returns null.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore
     */
    private function nullStore(): MfaVerificationStore
    {
        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldReceive('lastVerifiedAt')
            ->andReturnNull();

        /** @var MfaVerificationStore $store */
        return $store;
    }
}
