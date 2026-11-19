<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Laravel\Sanctum\Sanctum;
use Laravel\Sanctum\SanctumServiceProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\GuardHooks;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Drivers\HeaderApplicationResolver;
use Tests\Fixtures\Guards\GenericUserGuard;
use Tests\Fixtures\Guards\StaticUserGuard;
use Tests\Fixtures\Guards\TokenProofStore;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * The identity, factors, verification and gate under session, token-style,
 * Sanctum and custom guards.
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

    /** @var array<string, mixed> An application accepting TOTP after a password. */
    private const array APPLICATION = ['types' => ['totp'], 'first_factor' => ['method' => 'password', 'channel' => 'password']];

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
     * Sanctum's stateful requests sign in on `web` but are served under
     * `sanctum`, another application by default.
     *
     * @return void
     */
    public function testASanctumSpaSignInIsNotFoundUnderTheSanctumGuard(): void
    {
        $factor = $this->signInToTheSpa();

        $this->postJson('sanctum/verify', ['factor' => $factor->id, 'code' => AuthenticatorApp::code($factor)])->assertContent('not_found');
        $this->getJson('sanctum/gated')->assertUnauthorized();
    }

    /**
     * @return void
     */
    public function testASanctumSpaSignInVerifiesWhenBothGuardsServeOneApplication(): void
    {
        // Names `web` for every request, whatever the guard.
        $this->container()->instance(ApplicationResolver::class, new HeaderApplicationResolver);

        $factor = $this->signInToTheSpa();

        $this->getJson('sanctum/gated')->assertUnauthorized();
        $this->postJson('sanctum/verify', ['factor' => $factor->id, 'code' => AuthenticatorApp::code($factor)])->assertContent('verified');

        self::assertCount(1, Mfa::proofs(Callers::current('sanctum')));

        $this->getJson('sanctum/gated')->assertOk();
    }

    /**
     * Each token is its own sign-in, and no Laravel session is kept.
     *
     * @return void
     */
    public function testATokenGuardWithItsOwnStoreKeepsEachTokensSignIn(): void
    {
        $this->container()->instance(ProofStore::class, new TokenProofStore);

        $factor = $this->issueTokens('token-a', 'token-b');

        $this->withToken('token-a')->postJson('token/verify', ['factor' => $factor->id, 'code' => AuthenticatorApp::code($factor)])->assertContent('verified');
        $this->withToken('token-a')->getJson('token/gated')->assertOk();
        $this->withToken('token-b')->getJson('token/gated')->assertUnauthorized();

        $this->withToken('token-b')->postJson('token/verify', ['factor' => $factor->id, 'code' => AuthenticatorApp::code($factor, 1)])->assertContent('verified');
        $this->withToken('token-a')->postJson('token/logout')->assertOk();

        $this->withToken('token-a')->getJson('token/gated')->assertUnauthorized();
        $this->withToken('token-b')->getJson('token/gated')->assertOk();

        self::assertFalse($this->container()->make(Session::class)->has(SessionProofStore::SESSION_KEY));
    }

    /**
     * @return void
     */
    public function testATokenGuardOnTheSessionStoreVerifiesNothing(): void
    {
        $factor = $this->issueTokens('token-a');

        $this->withToken('token-a')->postJson('token/verify', ['factor' => $factor->id, 'code' => AuthenticatorApp::code($factor)])->assertContent('not_found');
        $this->withToken('token-a')->getJson('token/gated')->assertUnauthorized();
    }

    /**
     * A person with a TOTP factor signed in on `web`, under `auth:sanctum`
     * routes.
     *
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function signInToTheSpa(): Factor
    {
        (new SanctumServiceProvider($this->container()))->boot();

        config()->set('auth.guards.sanctum', ['driver' => 'sanctum', 'provider' => 'users']);
        config()->set('mfa.applications.web', self::APPLICATION);

        Auth::forgetGuards();

        $user   = TestUser::create(['email' => 'spa@example.test']);
        $factor = $this->confirmedTotp($user);

        Auth::guard('web')->login($user);

        $this->guardedRoutes('sanctum');

        return $factor;
    }

    /**
     * A person with a TOTP factor signed in on a token guard once per token, on
     * a request carrying it, with no Laravel session kept for the next request.
     *
     * @param  string  ...$tokens
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function issueTokens(string ...$tokens): Factor
    {
        $user   = TestUser::create(['email' => 'token@example.test']);
        $factor = $this->confirmedTotp($user);

        Auth::extend('token', static fn (): Guard => new StaticUserGuard($user));

        config()->set('auth.guards.token', ['driver' => 'token', 'provider' => 'users']);
        config()->set('mfa.applications.token', self::APPLICATION);

        foreach ($tokens as $token) {
            $this->container()->instance('request', Request::create('/', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]));

            GuardHooks::signedIn($user, SignInProofs::of($user)->onApplication('token')->inSession($token)->password());
        }

        $this->container()->make('session')->forgetDrivers();
        $this->container()->forgetInstance('session.store');

        $this->guardedRoutes('token');

        Route::post('token/logout', static function () use ($user): string {
            GuardHooks::signedOut($user, 'token');

            return 'signed out';
        })->middleware('auth:token');

        return $factor;
    }

    /**
     * Routes under the guard that verify a factor and gate at AAL2.
     *
     * @param  string  $guard
     * @return void
     */
    private function guardedRoutes(string $guard): void
    {
        Route::middleware('auth:' . $guard)->prefix($guard)->group(static function (): void {
            Route::post('verify', static function (Request $request): string {
                $submission = Submission::factor($request->string('factor')->value(), $request->string('code')->value());

                return Mfa::verify(CallerContext::fromRequest($request), $submission)->reason->value ?? 'verified';
            });

            Route::get('gated', static fn (): string => 'reached')->middleware('mfa:level=aal2');
        });
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function confirmedTotp(TestUser $user): Factor
    {
        /** @var \SineMacula\Laravel\Mfa\Models\Factor */
        return Factor::create([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'status'               => 'confirmed',
        ]);
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
