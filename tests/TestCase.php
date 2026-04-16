<?php

declare(strict_types = 1);

namespace Tests;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase as BaseTestCase;
use SineMacula\Laravel\Mfa\MfaServiceProvider;

/**
 * Base TestCase for the `sinemacula/laravel-mfa` test suites.
 *
 * Boots an Orchestra TestBench application with the MFA service
 * provider registered, an in-memory SQLite connection, and the
 * shipped migration applied. Concrete tests subclass this directly
 * (via `use RefreshDatabase` when persistence is required) or the
 * thinner `Tests\UnitTestCase` for pure unit scenarios.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
abstract class TestCase extends BaseTestCase
{
    /**
     * Register the package's service provider with the test
     * application.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return list<class-string<\Illuminate\Support\ServiceProvider>>
     */
    protected function getPackageProviders(\Illuminate\Foundation\Application $app): array
    {
        return [
            MfaServiceProvider::class,
        ];
    }

    /**
     * Configure the application environment for the test suite.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function defineEnvironment(\Illuminate\Foundation\Application $app): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $app->make(Repository::class);

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);

        $config->set('auth.defaults.guard', 'web');
        $config->set('auth.guards.web', [
            'driver'   => 'session',
            'provider' => 'users',
        ]);
        $config->set('auth.providers.users', [
            'driver' => 'eloquent',
            'model'  => Fixtures\TestUser::class,
        ]);
    }

    /**
     * Load the package's migration + the test user migration for the
     * test application database.
     *
     * @return void
     */
    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
        $this->loadMigrationsFrom(__DIR__ . '/Fixtures/migrations');
    }
}
