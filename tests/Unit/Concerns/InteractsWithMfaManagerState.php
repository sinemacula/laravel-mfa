<?php

declare(strict_types = 1);

namespace Tests\Unit\Concerns;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Identities\TestUser;

/**
 * Shared scaffolding for the `MfaManager` state-test family.
 *
 * The state suite is split into two subjects (lookups / lifecycle) to stay
 * under the max-methods-per-class threshold. This trait centralises the shared
 * helpers — manager resolution, factor seeding, and Mockery teardown.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
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
     * @return \Tests\Fixtures\Identities\TestUser
     */
    protected function makeUserWithFactor(string $email = 'user@example.com'): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->create([
            'email'       => $email,
            'mfa_enabled' => true,
        ]);

        Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);

        return $user;
    }
}
