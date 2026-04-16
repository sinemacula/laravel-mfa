<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Carbon\Carbon;
use Illuminate\Config\Repository;
use Illuminate\Contracts\Auth\Authenticatable;
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

    /**
     * The shipped default driver should be `'totp'`.
     *
     * @return void
     */
    public function testGetDefaultDriverReturnsTotp(): void
    {
        $manager = $this->manager();

        self::assertSame('totp', $manager->getDefaultDriver());
    }

    /**
     * Without a resolved identity `shouldUse()` must always return
     * false.
     *
     * @return void
     */
    public function testShouldUseReturnsFalseWhenNoIdentityResolved(): void
    {
        $manager = $this->manager();

        self::assertFalse($manager->shouldUse());
    }

    /**
     * An identity that does not implement
     * `MultiFactorAuthenticatable` must never opt into MFA
     * enforcement, regardless of policy state.
     *
     * @return void
     */
    public function testShouldUseReturnsFalseWhenIdentityIsNotMfaAuthenticatable(): void
    {
        $plain = PlainUser::query()->create(['email' => 'plain@example.com']);

        $this->actingAs($plain);

        self::assertFalse($this->manager()->shouldUse());
    }

    /**
     * An identity reporting `shouldUseMultiFactor() === true` should
     * activate enforcement.
     *
     * @return void
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
     * The bound `MfaPolicy` should be able to force enforcement even
     * when the identity itself does not opt in.
     *
     * @return void
     */
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

        $this->container()->instance(MfaPolicy::class, $policy);

        $this->actingAs($user);

        self::assertTrue($this->manager()->shouldUse());
    }

    /**
     * When neither the identity nor the policy demand MFA the manager
     * must report `shouldUse() === false`.
     *
     * @return void
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
     * Without a resolved identity `isSetup()` must return false.
     *
     * @return void
     */
    public function testIsSetupReturnsFalseWhenNoIdentity(): void
    {
        self::assertFalse($this->manager()->isSetup());
    }

    /**
     * An identity with no persisted factors should report as not
     * having MFA set up.
     *
     * @return void
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
     * An identity with at least one persisted factor should report as
     * having MFA set up.
     *
     * @return void
     */
    public function testIsSetupReturnsTrueWhenIdentityHasFactor(): void
    {
        $user = $this->makeUserWithFactor();

        $this->actingAs($user);

        self::assertTrue($this->manager()->isSetup());
    }

    /**
     * `isSetup()` should cache its result for the duration of the
     * request, so subsequent calls do not re-query the database.
     *
     * @return void
     */
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

    /**
     * Without a resolved identity `hasEverVerified()` must return
     * false.
     *
     * @return void
     */
    public function testHasEverVerifiedReturnsFalseWhenNoIdentity(): void
    {
        self::assertFalse($this->manager()->hasEverVerified());
    }

    /**
     * `hasEverVerified()` should report false when the verification
     * store has no record for the identity.
     *
     * @return void
     */
    public function testHasEverVerifiedReturnsFalseWhenStoreReturnsNull(): void
    {
        $user = TestUser::query()->create(['email' => 'e@example.com']);

        $this->actingAs($user);

        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldReceive('lastVerifiedAt')
            ->once()
            ->andReturnNull();

        $this->container()->instance(MfaVerificationStore::class, $store);

        self::assertFalse($this->manager()->hasEverVerified());
    }

    /**
     * `hasEverVerified()` should report true once the store can prove
     * the identity has been verified at any prior point.
     *
     * @return void
     */
    public function testHasEverVerifiedReturnsTrueWhenStoreReturnsTimestamp(): void
    {
        $user = TestUser::query()->create(['email' => 'f@example.com']);

        $this->actingAs($user);

        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldReceive('lastVerifiedAt')
            ->once()
            ->andReturn(Carbon::now());

        $this->container()->instance(MfaVerificationStore::class, $store);

        self::assertTrue($this->manager()->hasEverVerified());
    }

    /**
     * Without an identity verification is always treated as expired.
     *
     * @return void
     */
    public function testHasExpiredReturnsTrueWhenNoIdentity(): void
    {
        self::assertTrue($this->manager()->hasExpired());
    }

    /**
     * An identity with no prior verification record should be treated
     * as expired so the consumer is forced to verify.
     *
     * @return void
     */
    public function testHasExpiredReturnsTrueWhenNoPriorVerification(): void
    {
        $user = TestUser::query()->create(['email' => 'g@example.com']);

        $this->actingAs($user);

        $this->container()->instance(
            MfaVerificationStore::class,
            $this->nullStore(),
        );

        self::assertTrue($this->manager()->hasExpired());
    }

    /**
     * Omitting the explicit expiry argument should fall back to the
     * configured `mfa.default_expiry` value.
     *
     * @return void
     */
    public function testHasExpiredUsesConfiguredDefaultExpiryWhenParameterOmitted(): void
    {
        $user = TestUser::query()->create(['email' => 'h@example.com']);

        $this->actingAs($user);

        $config = app(Repository::class);
        $config->set('mfa.default_expiry', 60);

        $this->container()->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->subMinutes(30)),
        );

        self::assertFalse($this->manager()->hasExpired());
    }

    /**
     * A recent verification with an explicit expiry should be treated
     * as still valid.
     *
     * @return void
     */
    public function testHasExpiredReturnsFalseForRecentVerificationWithExplicitExpiry(): void
    {
        $user = TestUser::query()->create(['email' => 'i@example.com']);

        $this->actingAs($user);

        $this->container()->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->subMinutes(5)),
        );

        self::assertFalse($this->manager()->hasExpired(60));
    }

    /**
     * An explicit expiry of zero minutes should immediately expire any
     * prior verification.
     *
     * @return void
     */
    public function testHasExpiredReturnsTrueWhenExplicitExpiryIsZero(): void
    {
        $user = TestUser::query()->create(['email' => 'j@example.com']);

        $this->actingAs($user);

        $this->container()->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->subMinutes(1)),
        );

        self::assertTrue($this->manager()->hasExpired(0));
    }

    /**
     * A negative explicit expiry must be treated identically to zero.
     *
     * @return void
     */
    public function testHasExpiredReturnsTrueWhenExplicitExpiryIsNegative(): void
    {
        $user = TestUser::query()->create(['email' => 'k@example.com']);

        $this->actingAs($user);

        $this->container()->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->subMinutes(1)),
        );

        self::assertTrue($this->manager()->hasExpired(-5));
    }

    /**
     * A future-dated verification timestamp must be rejected as a
     * clock-skew defence and treated as expired.
     *
     * @return void
     */
    public function testHasExpiredReturnsTrueForFutureDatedVerification(): void
    {
        $user = TestUser::query()->create(['email' => 'l@example.com']);

        $this->actingAs($user);

        // Clock-skew defence: a store that reports a verification in
        // the future should not be trusted as "still valid".
        $this->container()->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->addMinutes(30)),
        );

        self::assertTrue($this->manager()->hasExpired(60));
    }

    /**
     * Once the elapsed minutes exceed the expiry budget the
     * verification should expire.
     *
     * @return void
     */
    public function testHasExpiredReturnsTrueWhenElapsedExceedsExpiry(): void
    {
        $user = TestUser::query()->create(['email' => 'm@example.com']);

        $this->actingAs($user);

        $this->container()->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->subMinutes(120)),
        );

        self::assertTrue($this->manager()->hasExpired(60));
    }

    /**
     * A non-numeric `mfa.default_expiry` config value should be
     * coerced to zero, expiring any prior verification.
     *
     * @return void
     */
    public function testHasExpiredDefaultsToFallbackExpiryWhenConfigIsNonNumeric(): void
    {
        $user = TestUser::query()->create(['email' => 'n@example.com']);

        $this->actingAs($user);

        $config = app(Repository::class);
        $config->set('mfa.default_expiry', 'not-a-number');

        $this->container()->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->subMinute()),
        );

        // A non-numeric config falls back to 0 via the manager's
        // `resolveDefaultExpiry()` defence, meaning any prior
        // verification is treated as expired.
        self::assertTrue($this->manager()->hasExpired());
    }

    /**
     * A numeric-string `mfa.default_expiry` config value should be
     * coerced to an int and respected.
     *
     * @return void
     */
    public function testHasExpiredCoercesNumericStringConfigToInt(): void
    {
        $user = TestUser::query()->create(['email' => 'o@example.com']);

        $this->actingAs($user);

        $config = app(Repository::class);
        $config->set('mfa.default_expiry', '60');

        $this->container()->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->subMinutes(10)),
        );

        self::assertFalse($this->manager()->hasExpired());
    }

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

    /**
     * Without an identity `getFactors()` must return null instead of
     * an empty collection.
     *
     * @return void
     */
    public function testGetFactorsReturnsNullWhenNoIdentity(): void
    {
        self::assertNull($this->manager()->getFactors());
    }

    /**
     * With an identity `getFactors()` should return a collection of
     * persisted factor models.
     *
     * @return void
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
     * The cache-prefix builder should accept an identity whose auth
     * identifier is neither a string nor an int by falling back to an
     * empty suffix rather than throwing.
     *
     * @return void
     */
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

    /**
     * `getFactors()` should cache its returned collection so repeated
     * calls within the same request do not re-query the database.
     *
     * @return void
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
     * Resolve the package's MFA manager instance from the container.
     *
     * @return \SineMacula\Laravel\Mfa\MfaManager
     */
    private function manager(): MfaManager
    {
        $manager = $this->container()->make('mfa');
        \PHPUnit\Framework\Assert::assertInstanceOf(MfaManager::class, $manager);

        return $manager;
    }

    /**
     * Create a test user with a single backing TOTP factor.
     *
     * @param  string  $email
     * @return \Tests\Fixtures\TestUser
     */
    private function makeUserWithFactor(string $email = 'user@example.com'): TestUser
    {
        /** @var \Tests\Fixtures\TestUser $user */
        $user = TestUser::query()->create([
            'email'       => $email,
            'mfa_enabled' => true,
        ]);

        Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
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
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore $store */
        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldReceive('lastVerifiedAt')
            ->andReturn($at);

        return $store;
    }

    /**
     * Build a store mock whose `lastVerifiedAt()` always returns null.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore
     */
    private function nullStore(): MfaVerificationStore
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore $store */
        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldReceive('lastVerifiedAt')
            ->andReturnNull();

        return $store;
    }
}
