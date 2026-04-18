<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\Events\MfaFactorDisabled;
use SineMacula\Laravel\Mfa\Events\MfaFactorEnrolled;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\TestUser;
use Tests\Unit\Concerns\InteractsWithMfaManagerState;

/**
 * Unit tests for `MfaManager` lifecycle mutations.
 *
 * Covers `markVerified()`, `forgetVerification()`, `clearCache()`, `enrol()`,
 * and `disable()`. Split out from the broader state-test family so each subject
 * stays under the project's max-methods-per-class threshold.
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
     * Without an identity `markVerified()` must not touch the verification
     * store.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testMarkVerifiedIsNoopWhenNoIdentity(): void
    {
        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldNotReceive('markVerified');

        $this->container()->instance(MfaVerificationStore::class, $store);

        $this->manager()->markVerified();

        $store->shouldNotHaveReceived('markVerified');
    }

    /**
     * With an identity `markVerified()` should delegate to the bound store's
     * `markVerified()` method.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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

        $store->shouldHaveReceived('markVerified')
            ->once()
            ->with(\Mockery::type(Authenticatable::class));
    }

    /**
     * Without an identity `forgetVerification()` must not touch the
     * verification store.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testForgetVerificationIsNoopWhenNoIdentity(): void
    {
        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldNotReceive('forget');

        $this->container()->instance(MfaVerificationStore::class, $store);

        $this->manager()->forgetVerification();

        $store->shouldNotHaveReceived('forget');
    }

    /**
     * With an identity `forgetVerification()` should delegate to the bound
     * store's `forget()` method.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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

        $store->shouldHaveReceived('forget')
            ->once()
            ->with(\Mockery::type(Authenticatable::class));
    }

    /**
     * Calling `clearCache()` without an identity argument should flush every
     * cached entry across the manager.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
     * Scoping `clearCache()` to a single identity must leave other identities'
     * cache entries intact.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
     * Without an identity `enrol()` must not persist the factor or dispatch the
     * lifecycle event.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEnrolIsNoopWhenNoIdentity(): void
    {
        Event::fake([MfaFactorEnrolled::class]);

        $factor = $this->makeUnpersistedTotpFactor();

        $this->manager()->enrol($factor);

        Event::assertNotDispatched(MfaFactorEnrolled::class);
        self::assertFalse($factor->exists);
    }

    /**
     * Test enrol persists the supplied factor row.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEnrolPersistsFactor(): void
    {
        $user    = $this->makeEnrolUser();
        $factor  = $this->makeUnpersistedTotpFactor($user);
        $manager = $this->manager();

        $manager->enrol($factor);

        self::assertTrue($factor->exists, 'enrol() must persist the factor row');
    }

    /**
     * Test enrol dispatches the MfaFactorEnrolled event.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEnrolDispatchesEnrolledEvent(): void
    {
        Event::fake([MfaFactorEnrolled::class]);

        $user    = $this->makeEnrolUser();
        $factor  = $this->makeUnpersistedTotpFactor($user);
        $manager = $this->manager();

        $manager->enrol($factor);

        Event::assertDispatched(
            MfaFactorEnrolled::class,
            static fn (MfaFactorEnrolled $event): bool => $event->identity === $user
                && $event->factor                                          === $factor
                && $event->driver                                          === 'totp',
        );
    }

    /**
     * Test enrol invalidates the identity's isSetup cache.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEnrolInvalidatesIsSetupCache(): void
    {
        $user    = $this->makeEnrolUser();
        $manager = $this->manager();

        // Warm the setup cache to "no factors" so the post-enrol invalidation
        // must force a fresh lookup.
        self::assertFalse($manager->isSetup());

        $manager->enrol($this->makeUnpersistedTotpFactor($user));

        self::assertTrue($manager->isSetup(), 'cache must be cleared after enrol');
    }

    /**
     * Without an identity `disable()` must not delete the factor or dispatch
     * the lifecycle event.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testDisableIsNoopWhenNoIdentity(): void
    {
        Event::fake([MfaFactorDisabled::class]);

        $user = TestUser::query()->create([
            'email'       => 'orphan-disable@example.test',
            'mfa_enabled' => true,
        ]);

        // Persist a factor but do NOT actingAs() — disable() should
        // short-circuit on the missing identity.
        $factor = $this->persistTotpFactorFor($user);

        $this->manager()->disable($factor);

        Event::assertNotDispatched(MfaFactorDisabled::class);
        self::assertNotNull(Factor::query()->find($factor->getKey()));
    }

    /**
     * Test disable deletes the underlying factor row.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testDisableDeletesFactorRow(): void
    {
        [$manager, $factor] = $this->enrolAndResolveFactor();

        $manager->disable($factor);

        self::assertNull(
            Factor::query()->find($factor->getKey()),
            'disable() must delete the factor row',
        );
    }

    /**
     * Test disable dispatches the MfaFactorDisabled event.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testDisableDispatchesDisabledEvent(): void
    {
        Event::fake([MfaFactorDisabled::class]);

        [$manager, $factor, $user] = $this->enrolAndResolveFactor();

        $manager->disable($factor);

        Event::assertDispatched(
            MfaFactorDisabled::class,
            static fn (MfaFactorDisabled $event): bool => $event->identity === $user
                && $event->driver                                          === 'totp',
        );
    }

    /**
     * Test disable invalidates the identity's isSetup cache.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testDisableInvalidatesIsSetupCache(): void
    {
        [$manager, $factor] = $this->enrolAndResolveFactor();

        // Warm the setup cache to "has factor" so the post-disable invalidation
        // must force a fresh lookup.
        self::assertTrue($manager->isSetup());

        $manager->disable($factor);

        self::assertFalse($manager->isSetup(), 'cache must be cleared after disable');
    }

    /**
     * Build a fresh TOTP `Factor` model that is NOT yet persisted — the
     * consumer-side shape that `enrol()` is intended to receive.
     *
     * @param  ?\Tests\Fixtures\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function makeUnpersistedTotpFactor(?TestUser $user = null): Factor
    {
        $factor         = new Factor;
        $factor->driver = 'totp';
        $factor->secret = 'JBSWY3DPEHPK3PXP';

        if ($user !== null) {
            $factor->authenticatable_type = $user::class;
            $factor->authenticatable_id   = (string) $user->id;
        }

        return $factor;
    }

    /**
     * Create an MFA-enabled user and authenticate as them, returning the user
     * for enrol-flow tests.
     *
     * @return \Tests\Fixtures\TestUser
     */
    private function makeEnrolUser(): TestUser
    {
        $user = TestUser::query()->create([
            'email'       => 'enrol@example.test',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        return $user;
    }

    /**
     * Persist a TOTP factor against the supplied identity and return the row.
     *
     * @param  \Tests\Fixtures\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function persistTotpFactorFor(TestUser $user): Factor
    {
        return Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'driver'               => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);
    }

    /**
     * Enrol an MFA-enabled user with a TOTP factor and return the manager,
     * resolved factor, and user triple for disable-flow tests.
     *
     * @formatter:off
     *
     * @return array{0: \SineMacula\Laravel\Mfa\MfaManager, 1: \SineMacula\Laravel\Mfa\Models\Factor, 2: \Tests\Fixtures\TestUser}
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function enrolAndResolveFactor(): array
    {
        $user = $this->makeUserWithFactor();

        $this->actingAs($user);

        $manager = $this->manager();

        /** @var \SineMacula\Laravel\Mfa\Models\Factor $factor */
        $factor = Factor::query()
            ->where('authenticatable_id', (string) $user->id)
            ->sole();

        return [$manager, $factor, $user];
    }
}
