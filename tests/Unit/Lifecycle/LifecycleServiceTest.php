<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Events\MfaFactorDisabled;
use SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleService;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Tests for `LifecycleService`: only the current identity's own factor is
 * disabled, its row deleted, its cached factors cleared and the removal
 * reported.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LifecycleService::class)]
final class LifecycleServiceTest extends TestCase
{
    /**
     * A guest disables nothing and nothing is reported.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAGuestDisablesNothing(): void
    {
        $owner  = TestUser::query()->create(['email' => 'owner@example.com']);
        $factor = $this->factorOf($owner);

        Event::fake([MfaFactorDisabled::class]);

        $this->service()->disable($factor);

        self::assertTrue(Factor::query()->whereKey($factor->getKey())->exists());
        Event::assertNotDispatched(MfaFactorDisabled::class);
    }

    /**
     * The identity's own factor is deleted and its removal reported.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheIdentitysFactorIsDeletedAndReported(): void
    {
        $user   = $this->signIn();
        $factor = $this->factorOf($user);

        Event::fake([MfaFactorDisabled::class]);

        $this->service()->disable($factor);

        self::assertFalse(Factor::query()->whereKey($factor->getKey())->exists());
        Event::assertDispatched(
            MfaFactorDisabled::class,
            static fn (MfaFactorDisabled $event): bool => $event->identity === $user
                && $event->factor                                          === $factor
                && $event->driver                                          === 'totp',
        );
    }

    /**
     * Another identity's factor is refused and kept.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnotherIdentitysFactorIsRefused(): void
    {
        $this->signIn();

        $other  = TestUser::query()->create(['email' => 'other@example.com']);
        $factor = $this->factorOf($other);

        Event::fake([MfaFactorDisabled::class]);

        try {
            $this->service()->disable($factor);
            self::fail('Disabling another identity\'s factor was expected to be refused.');
        } catch (FactorOwnershipMismatchException) {
            self::assertTrue(Factor::query()->whereKey($factor->getKey())->exists());
            Event::assertNotDispatched(MfaFactorDisabled::class);
        }
    }

    /**
     * A non-Eloquent factor of the identity is reported without a delete.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testANonEloquentFactorIsReported(): void
    {
        $user = $this->signIn();

        Event::fake([MfaFactorDisabled::class]);

        $this->service()->disable(new InMemoryFactor(type: 'sms', authenticatable: $user));

        Event::assertDispatched(MfaFactorDisabled::class, static fn (MfaFactorDisabled $event): bool => $event->driver === 'sms');
    }

    /**
     * Disabling clears the identity's cached factors.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testDisablingClearsTheIdentitysCachedFactors(): void
    {
        $user    = $this->signIn();
        $factor  = $this->factorOf($user);
        $factors = $this->container()->make(FactorService::class);

        self::assertTrue($factors->isSetup());

        $this->service()->disable($factor);

        self::assertFalse($factors->isSetup());
    }

    /**
     * Resolve the lifecycle service.
     *
     * @return \SineMacula\Laravel\Mfa\Lifecycle\LifecycleService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function service(): LifecycleService
    {
        return $this->container()->make(LifecycleService::class);
    }

    /**
     * Create a test user and authenticate as them.
     *
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function signIn(): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->create(['email' => 'disable@example.com']);

        $this->actingAs($user);

        return $user;
    }

    /**
     * Create a TOTP factor for the user.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function factorOf(TestUser $user): Factor
    {
        /** @var \SineMacula\Laravel\Mfa\Models\Factor */
        return Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);
    }
}
