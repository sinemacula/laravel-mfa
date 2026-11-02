<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use Orchestra\Testbench\Foundation\Application as Testbench;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use Tests\Fixtures\Identities\TestUser;

/**
 * The application the whole-path benchmarks run on, built as the query budgets'
 * is rather than by hand, as the default seams need the session guard, the
 * session store and the auth stack, and a hand-built container would drift from
 * what the budgets run: the package's provider, in-memory SQLite with the
 * package's and the test identities' tables, an array session, and bcrypt at
 * its cheapest cost, so a recovery code's hashing does not swamp the rest.
 *
 * The clock is the process's own, frozen before the set-up and released after
 * the timing, so a code never crosses a time step and no window ends.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BenchApplication
{
    /** @var string The application the benchmarks verify on. */
    public const string APPLICATION = 'web';

    /** @var string The time the benchmarks run at. */
    private const string NOW = '2026-11-01 12:00:00';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Build and migrate the application, with the requirement mode given; the
     * default is the one the query budgets run in.
     *
     * @param  string  $requirement
     * @return \Illuminate\Contracts\Foundation\Application
     */
    public static function create(string $requirement = 'never'): Application
    {
        $root = dirname(__DIR__, 2);
        $app  = Testbench::create(options: ['extra' => ['providers' => [MfaServiceProvider::class], 'dont-discover' => ['*']]]);

        $app->make('config')->set([
            'app.key'                               => 'base64:' . base64_encode(str_repeat('b', 32)),
            'auth.defaults.guard'                   => 'web',
            'auth.guards.web'                       => ['driver' => 'session', 'provider' => 'users'],
            'auth.providers.users'                  => ['driver' => 'eloquent', 'model' => TestUser::class],
            'database.default'                      => 'bench',
            'database.connections.bench'            => ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => ''],
            'hashing.bcrypt.rounds'                 => 4,
            'session.driver'                        => 'array',
            'mfa.applications.' . self::APPLICATION => [
                'types'          => ['totp', 'email'],
                'requirement'    => $requirement,
                'recovery_codes' => ['enabled' => true],
                'first_factor'   => ['method' => 'password', 'channel' => 'password'],
            ],
        ]);

        $migrator = $app->make('migrator');

        $migrator->getRepository()->createRepository();
        $migrator->run([$root . '/database/migrations', $root . '/tests/Fixtures/migrations']);

        return $app;
    }

    /**
     * Freeze both clocks.
     *
     * @return void
     */
    public static function freezeClock(): void
    {
        Carbon::setTestNow(self::NOW);
        CarbonImmutable::setTestNow(self::NOW);
    }

    /**
     * Release both clocks.
     *
     * @return void
     */
    public static function releaseClock(): void
    {
        Carbon::setTestNow();
        CarbonImmutable::setTestNow();
    }

    /**
     * A new person, signed in through the guard from the address given, with a
     * sign-in of their own that the proof store knows.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  string  $email
     * @param  string  $ip
     * @param  string  $session
     * @return \Tests\Fixtures\Identities\TestUser
     */
    public static function signedInPerson(Application $app, string $email, string $ip, string $session): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->create(['email' => $email]);

        $app->make('auth')->guard('web')->setUser($user);
        $app->instance('request', Request::create('/', 'POST', server: ['REMOTE_ADDR' => $ip]));
        $app->make(ProofStore::class)->begin($user, self::APPLICATION, $session);

        return $user;
    }

    /**
     * A confirmed TOTP factor of the person's.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    public static function totpFactor(TestUser $user): Factor
    {
        return self::factorOf($user, AuthenticatorApp::FACTOR);
    }

    /**
     * A confirmed email factor of the person's, delivering to their address.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    public static function emailFactor(TestUser $user): Factor
    {
        return self::factorOf($user, ['type' => 'email', 'destination' => $user->email]);
    }

    /**
     * A confirmed factor of the person's with the attributes given.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private static function factorOf(TestUser $user, array $attributes): Factor
    {
        $owner = ProofOwner::of($user);

        /** @var \SineMacula\Laravel\Mfa\Models\Factor */
        return Factor::query()->create([
            'authenticatable_type' => $owner->type,
            'authenticatable_id'   => $owner->key,
            'status'               => 'confirmed',
            'confirmed_at'         => CarbonImmutable::now(),
            ...$attributes,
        ]);
    }
}
