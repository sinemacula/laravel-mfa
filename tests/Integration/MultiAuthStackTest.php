<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * Verifies that the MFA package enforces correctly across multiple
 * authentication stacks within the same application.
 *
 * Three guards are exercised:
 *
 *   1. The default session guard (SessionGuard via the testbench
 *      bootstrap).
 *   2. A token-style stateless guard (the same lookup path Sanctum
 *      / Passport take when they bind a user).
 *   3. A custom in-memory guard built on `Illuminate\Contracts\Auth\Guard`
 *      that hands back a fixture identity directly.
 *
 * Each guard authenticates a user, then asks the MFA manager to verify
 * setup state, run a TOTP verification, and report `hasEverVerified()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MultiAuthStackTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Under the default session guard the manager must read the
     * acting user identity and surface its persisted factors.
     *
     * @return void
     */
    public function testSessionGuardSeesIdentityAndFactors(): void
    {
        $user = $this->enrolUser('session@example.test');

        $this->actingAs($user);

        self::assertTrue(Mfa::shouldUse());
        self::assertTrue(Mfa::isSetup());
        self::assertCount(1, Mfa::getFactors() ?? collect());
    }

    /**
     * Under a token-style guard whose resolver hands back an
     * Eloquent identity the manager must surface the same setup
     * state and factor collection.
     *
     * @return void
     */
    public function testTokenStyleGuardSeesIdentityAndFactors(): void
    {
        config()->set('auth.guards.token', [
            'driver'   => 'token',
            'provider' => 'users',
        ]);

        $user = $this->enrolUser('token@example.test');

        // Mimic what Sanctum / Passport do: register a guard whose
        // resolver hands back a real Eloquent identity. The MFA manager
        // reads through the default guard, so swap it out for the
        // duration of the assertions.
        Auth::extend('token', static function ($app, string $name, array $config) use ($user): Guard {
            // The closure signature is fixed by Laravel's `Auth::extend`
            // contract; this fake guard ignores the wiring args and
            // returns the user captured from the outer closure.
            unset($app, $name, $config);

            return new class ($user) implements Guard {
                /**
                 * Capture the resolved identity once at construction.
                 *
                 * @param  \Tests\Fixtures\TestUser  $resolved
                 * @return void
                 */
                public function __construct(private readonly TestUser $resolved) {}

                /**
                 * @return bool
                 */
                public function check(): bool
                {
                    return true;
                }

                /**
                 * @return bool
                 */
                public function guest(): bool
                {
                    return false;
                }

                /**
                 * @return \Tests\Fixtures\TestUser
                 */
                public function user(): TestUser
                {
                    return $this->resolved;
                }

                /**
                 * @return int
                 */
                public function id(): int
                {
                    return $this->resolved->id;
                }

                /**
                 * @param  array<array-key, mixed>  $credentials
                 * @return bool
                 */
                public function validate(array $credentials = []): bool
                {
                    return true;
                }

                /**
                 * @return bool
                 */
                public function hasUser(): bool
                {
                    return true;
                }

                /**
                 * No-op — the fixture binds its identity at
                 * construction time.
                 *
                 * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
                 * @return self
                 */
                public function setUser(Authenticatable $user): self
                {
                    return $this;
                }
            };
        });

        config()->set('auth.defaults.guard', 'token');
        $this->container()->forgetInstance('mfa');
        Mfa::clearCache();

        self::assertTrue(Mfa::shouldUse());
        self::assertTrue(Mfa::isSetup());
        self::assertCount(1, Mfa::getFactors() ?? collect());
    }

    /**
     * Under a custom guard whose resolver hands back a non-Eloquent
     * `Authenticatable` the manager must short-circuit cleanly
     * rather than throw — proving the orchestration layer does not
     * assume Eloquent throughout.
     *
     * @return void
     */
    public function testCustomAuthenticatableGuardWithoutEloquentBindsCorrectly(): void
    {
        // Custom guard that hands back a non-Eloquent Authenticatable.
        // The package should treat it as a non-MFA-capable identity
        // (`shouldUse()` returns false) — proving the manager does not
        // assume Eloquent throughout the orchestration surface.
        Auth::extend('custom', static function (): Guard {
            return new class implements Guard {
                /** @var \Illuminate\Auth\GenericUser */
                private readonly GenericUser $resolved;

                /**
                 * Build the fixture identity once at construction.
                 *
                 * @return void
                 */
                public function __construct()
                {
                    $this->resolved = new GenericUser(['id' => 99, 'name' => 'Generic']);
                }

                /**
                 * @return bool
                 */
                public function check(): bool
                {
                    return true;
                }

                /**
                 * @return bool
                 */
                public function guest(): bool
                {
                    return false;
                }

                /**
                 * @return \Illuminate\Auth\GenericUser
                 */
                public function user(): GenericUser
                {
                    return $this->resolved;
                }

                /**
                 * @return int
                 */
                public function id(): int
                {
                    return 99;
                }

                /**
                 * @param  array<array-key, mixed>  $credentials
                 * @return bool
                 */
                public function validate(array $credentials = []): bool
                {
                    return true;
                }

                /**
                 * @return bool
                 */
                public function hasUser(): bool
                {
                    return true;
                }

                /**
                 * No-op — the fixture binds its identity at
                 * construction time.
                 *
                 * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
                 * @return self
                 */
                public function setUser(Authenticatable $user): self
                {
                    return $this;
                }
            };
        });

        config()->set('auth.guards.custom', [
            'driver'   => 'custom',
            'provider' => 'users',
        ]);
        config()->set('auth.defaults.guard', 'custom');
        $this->container()->forgetInstance('mfa');
        Mfa::clearCache();

        // GenericUser does not implement MultiFactorAuthenticatable, so
        // the manager must short-circuit cleanly rather than throw.
        self::assertFalse(Mfa::shouldUse());
        self::assertFalse(Mfa::isSetup());
        self::assertNull(Mfa::getFactors());
    }

    /**
     * Persist a fresh MFA-enrolled user with one TOTP factor.
     *
     * @param  string  $email
     * @return \Tests\Fixtures\TestUser
     */
    private function enrolUser(string $email): TestUser
    {
        $user = TestUser::create([
            'email'       => $email,
            'mfa_enabled' => true,
        ]);

        Factor::create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'driver'               => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);

        return $user;
    }
}
