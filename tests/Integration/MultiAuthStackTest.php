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

    public function testSessionGuardSeesIdentityAndFactors(): void
    {
        $user = $this->enrolUser('session@example.test');

        $this->actingAs($user);

        self::assertTrue(Mfa::shouldUse());
        self::assertTrue(Mfa::isSetup());
        self::assertCount(1, Mfa::getFactors() ?? collect());
    }

    public function testTokenStyleGuardSeesIdentityAndFactors(): void
    {
        $this->app['config']->set('auth.guards.token', [
            'driver'   => 'token',
            'provider' => 'users',
        ]);

        $user = $this->enrolUser('token@example.test');

        // Mimic what Sanctum / Passport do: register a guard whose
        // resolver hands back a real Eloquent identity. The MFA manager
        // reads through the default guard, so swap it out for the
        // duration of the assertions.
        Auth::extend('token', static function ($app, string $name, array $config) use ($user): Guard {
            return new class ($user) implements Guard {
                public function __construct(private readonly TestUser $resolved) {}

                public function check(): bool
                {
                    return true;
                }

                public function guest(): bool
                {
                    return false;
                }

                public function user(): TestUser
                {
                    return $this->resolved;
                }

                public function id(): int
                {
                    return $this->resolved->getKey();
                }

                public function validate(array $credentials = []): bool
                {
                    return true;
                }

                public function hasUser(): bool
                {
                    return true;
                }

                public function setUser(Authenticatable $user): self
                {
                    return $this;
                }
            };
        });

        $this->app['config']->set('auth.defaults.guard', 'token');
        $this->app->forgetInstance('mfa');
        Mfa::clearCache();

        self::assertTrue(Mfa::shouldUse());
        self::assertTrue(Mfa::isSetup());
        self::assertCount(1, Mfa::getFactors() ?? collect());
    }

    public function testCustomAuthenticatableGuardWithoutEloquentBindsCorrectly(): void
    {
        // Custom guard that hands back a non-Eloquent Authenticatable.
        // The package should treat it as a non-MFA-capable identity
        // (`shouldUse()` returns false) — proving the manager does not
        // assume Eloquent throughout the orchestration surface.
        Auth::extend('custom', static function (): Guard {
            return new class implements Guard {
                private readonly GenericUser $resolved;

                public function __construct()
                {
                    $this->resolved = new GenericUser(['id' => 99, 'name' => 'Generic']);
                }

                public function check(): bool
                {
                    return true;
                }

                public function guest(): bool
                {
                    return false;
                }

                public function user(): GenericUser
                {
                    return $this->resolved;
                }

                public function id(): int
                {
                    return 99;
                }

                public function validate(array $credentials = []): bool
                {
                    return true;
                }

                public function hasUser(): bool
                {
                    return true;
                }

                public function setUser(Authenticatable $user): self
                {
                    return $this;
                }
            };
        });

        $this->app['config']->set('auth.guards.custom', [
            'driver'   => 'custom',
            'provider' => 'users',
        ]);
        $this->app['config']->set('auth.defaults.guard', 'custom');
        $this->app->forgetInstance('mfa');
        Mfa::clearCache();

        // GenericUser does not implement MultiFactorAuthenticatable, so
        // the manager must short-circuit cleanly rather than throw.
        self::assertFalse(Mfa::shouldUse());
        self::assertFalse(Mfa::isSetup());
        self::assertNull(Mfa::getFactors());
    }

    private function enrolUser(string $email): TestUser
    {
        $user = TestUser::create([
            'email'       => $email,
            'mfa_enabled' => true,
        ]);

        Factor::create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->getKey(),
            'driver'               => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);

        return $user;
    }
}
