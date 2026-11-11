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
 * Built like the query budgets' application, since the default seams need the
 * full auth stack; bcrypt is at its cheapest so hashing does not swamp the
 * rest.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BenchApplication
{
    /** @var string */
    public const string APPLICATION = 'web';

    /** @var string Frozen so no code crosses a time step. */
    private const string NOW = '2026-11-01 12:00:00';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The default requirement mode is the one the query budgets run in.
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
     * @return void
     */
    public static function freezeClock(): void
    {
        Carbon::setTestNow(self::NOW);
        CarbonImmutable::setTestNow(self::NOW);
    }

    /**
     * @return void
     */
    public static function releaseClock(): void
    {
        Carbon::setTestNow();
        CarbonImmutable::setTestNow();
    }

    /**
     * Signed in from the given address, with a sign-in the proof store knows.
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
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    public static function totpFactor(TestUser $user): Factor
    {
        return self::factorOf($user, AuthenticatorApp::FACTOR);
    }

    /**
     * Delivers to the person's address.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    public static function emailFactor(TestUser $user): Factor
    {
        return self::factorOf($user, ['type' => 'email', 'destination' => $user->email]);
    }

    /**
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
