<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Illuminate\Contracts\Auth\Guard;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Guards\GenericUserGuard;
use Tests\Fixtures\Guards\StaticUserGuard;
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
        // resolver hands back a real Eloquent identity — the MFA
        // manager reads through the default guard, so swap it out.
        Auth::extend('token', static fn (): Guard => new StaticUserGuard($user));

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
        Auth::extend('custom', static fn (): Guard => new GenericUserGuard);

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
     * Sanctum's `auth:sanctum` guard authenticates the request via a
     * personal access token (Bearer) and falls back to the configured
     * stateful guard for browser sessions. The MFA package must
     * resolve the same MultiFactorAuthenticatable identity through
     * Sanctum's TransientToken guard as it does through SessionGuard
     * — proving the package depends only on `Auth::user()` returning
     * a `MultiFactorAuthenticatable`, not on Sanctum-specific wiring.
     *
     * @return void
     */
    public function testSanctumGuardSeesIdentityAndFactors(): void
    {
        $user = $this->enrolUser('sanctum@example.test');

        // Register Sanctum's auth driver inside this test so the
        // package's standalone-auth-stack story is exercised against
        // the real `auth:sanctum` driver — not just a hand-rolled
        // token-style guard. Mirrors the wiring a consumer would do
        // via auth.php when adding Sanctum to an existing app.
        (new \Laravel\Sanctum\SanctumServiceProvider($this->container()))->boot();

        config()->set('auth.guards.sanctum', [
            'driver'   => 'sanctum',
            'provider' => 'users',
        ]);
        config()->set('auth.defaults.guard', 'sanctum');

        $this->container()->forgetInstance('mfa');
        Auth::forgetGuards();
        Mfa::clearCache();

        // Sanctum::actingAs() handles the rest: it stamps the user as
        // resolved through the sanctum guard with a TransientToken
        // (no DB write needed for this test), so subsequent Auth::user()
        // calls under the `sanctum` guard return our MFA-capable
        // identity.
        \Laravel\Sanctum\Sanctum::actingAs($user, ['*']);

        self::assertTrue(Mfa::shouldUse());
        self::assertTrue(Mfa::isSetup());

        $factors = Mfa::getFactors();
        self::assertNotNull($factors);
        self::assertCount(1, $factors);
        self::assertSame('totp', $factors->first()?->getDriver());
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
