<?php

declare(strict_types = 1);

namespace Tests\Unit\Concerns;

use Carbon\Carbon;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\TestUser;

/**
 * Shared scaffolding for the `MfaManager` state-test family.
 *
 * The state suite is split into three subjects (lookups / expiry / lifecycle)
 * to stay under the max-methods-per-class threshold. This trait centralises
 * the shared helpers — manager resolution, factor seeding, fake stores, and
 * Mockery teardown.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
trait InteractsWithMfaManagerState
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
     * Resolve the package's MFA manager instance from the container.
     *
     * @return \SineMacula\Laravel\Mfa\MfaManager
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function manager(): MfaManager
    {
        $manager = $this->container()->make('mfa');
        Assert::assertInstanceOf(MfaManager::class, $manager);

        return $manager;
    }

    /**
     * Create a test user with a single backing TOTP factor.
     *
     * @param  string  $email
     * @return \Tests\Fixtures\TestUser
     */
    protected function makeUserWithFactor(string $email = 'user@example.com'): TestUser
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
     * Build a store mock whose `lastVerifiedAt()` always returns the supplied
     * timestamp.
     *
     * @param  \Carbon\Carbon  $at
     * @return \SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore
     */
    protected function fixedStore(Carbon $at): MfaVerificationStore
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
    protected function nullStore(): MfaVerificationStore
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore $store */
        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldReceive('lastVerifiedAt')
            ->andReturnNull();

        return $store;
    }
}
