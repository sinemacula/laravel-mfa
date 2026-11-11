<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Illuminate\Contracts\Auth\Guard;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use Laravel\Sanctum\Sanctum;
use Laravel\Sanctum\SanctumServiceProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Guards\GenericUserGuard;
use Tests\Fixtures\Guards\StaticUserGuard;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * The manager reads the identity and factors the same way under session,
 * token-style, Sanctum and custom guards.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
final class MultiAuthStackTest extends TestCase
{
    use RefreshDatabase;

    /**
     * @return void
     */
    public function testSessionGuardSeesIdentityAndFactors(): void
    {
        $user = $this->enrollUser('session@example.test');

        $this->actingAs($user);

        self::assertFalse(Mfa::requirement(Callers::current())->isEmpty());
        self::assertCount(1, Mfa::factors(Callers::current()));
    }

    /**
     * @return void
     */
    public function testTokenStyleGuardSeesIdentityAndFactors(): void
    {
        config()->set('auth.guards.token', [
            'driver'   => 'token',
            'provider' => 'users',
        ]);

        $user = $this->enrollUser('token@example.test');

        // The manager reads the default guard, as with Sanctum and Passport.
        Auth::extend('token', static fn (): Guard => new StaticUserGuard($user));

        config()->set('auth.defaults.guard', 'token');
        $this->container()->forgetInstance('mfa');

        self::assertFalse(Mfa::requirement(Callers::current())->isEmpty());
        self::assertCount(1, Mfa::factors(Callers::current()));
    }

    /**
     * @return void
     */
    public function testCustomAuthenticatableGuardWithoutEloquentBindsCorrectly(): void
    {
        Auth::extend('custom', static fn (): Guard => new GenericUserGuard);

        config()->set('auth.guards.custom', [
            'driver'   => 'custom',
            'provider' => 'users',
        ]);
        config()->set('auth.defaults.guard', 'custom');
        $this->container()->forgetInstance('mfa');

        // GenericUser is not MultiFactorAuthenticatable: nothing is required.
        self::assertTrue(Mfa::requirement(Callers::current())->isEmpty());
        self::assertSame([], Mfa::factors(Callers::current()));
    }

    /**
     * @return void
     */
    public function testSanctumGuardSeesIdentityAndFactors(): void
    {
        $user = $this->enrollUser('sanctum@example.test');

        // The real `sanctum` driver, wired as a consumer's auth.php would.
        (new SanctumServiceProvider($this->container()))->boot();

        config()->set('auth.guards.sanctum', [
            'driver'   => 'sanctum',
            'provider' => 'users',
        ]);
        config()->set('auth.defaults.guard', 'sanctum');

        $this->container()->forgetInstance('mfa');
        Auth::forgetGuards();

        // Resolves the user with a TransientToken and no DB write.
        Sanctum::actingAs($user, ['*']);

        self::assertFalse(Mfa::requirement(Callers::current())->isEmpty());

        $factors = Mfa::factors(Callers::current());
        self::assertCount(1, $factors);
        self::assertSame('totp', $factors[0]->type);
    }

    /**
     * @param  string  $email
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function enrollUser(string $email): TestUser
    {
        $user = TestUser::create([
            'email'       => $email,
            'mfa_enabled' => true,
        ]);

        Factor::create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);

        return $user;
    }
}
