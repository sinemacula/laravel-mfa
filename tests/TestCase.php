<?php

declare(strict_types = 1);

namespace Tests;

use Illuminate\Config\Repository;
use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase as BaseTestCase;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\MfaServiceProvider;

/**
 * Base TestCase for the `sinemacula/laravel-mfa` test suites.
 *
 * Boots an Orchestra TestBench application with the MFA service provider
 * registered, an in-memory SQLite connection, and the shipped migration
 * applied. Concrete tests subclass this directly (via `use RefreshDatabase`
 * when persistence is required) or the thinner `Tests\UnitTestCase` for pure
 * unit scenarios.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
abstract class TestCase extends BaseTestCase
{
    /**
     * Register the package's service provider with the test application.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return list<class-string<\Illuminate\Support\ServiceProvider>>
     */
    protected function getPackageProviders(mixed $app): array
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
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    protected function defineEnvironment(mixed $app): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(Repository::class);

        $config->set('app.key', 'base64:' . base64_encode(random_bytes(32)));

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', $this->resolveDatabaseConnection());

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
     * Resolve the test database connection.
     *
     * Defaults to in-memory SQLite so `composer test` needs no external
     * services. Honours `DB_CONNECTION` plus `DB_HOST` / `DB_PORT` /
     * `DB_DATABASE` / `DB_USERNAME` / `DB_PASSWORD` so the CI database matrix
     * runs against the provisioned engine.
     *
     * @return array<string, mixed>
     */
    protected function resolveDatabaseConnection(): array
    {
        $driver = getenv('DB_CONNECTION');

        if ($driver === false || $driver === '' || $driver === 'sqlite') {
            return [
                'driver'   => 'sqlite',
                'database' => ':memory:',
                'prefix'   => '',
            ];
        }

        return [
            'driver'   => $driver,
            'host'     => self::envOrDefault('DB_HOST', '127.0.0.1'),
            'port'     => self::envOrDefault('DB_PORT', $driver === 'pgsql' ? '5432' : '3306'),
            'database' => self::envOrDefault('DB_DATABASE', 'laravel_mfa_test'),
            'username' => self::envOrDefault('DB_USERNAME', $driver === 'pgsql' ? 'postgres' : 'root'),
            'password' => self::envOrDefault('DB_PASSWORD', ''),
            'prefix'   => '',
            'charset'  => $driver === 'pgsql' ? 'utf8' : 'utf8mb4',
        ];
    }

    /**
     * Load the package's migration + the test user migration for the test
     * application database.
     *
     * @return void
     */
    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
        $this->loadMigrationsFrom(__DIR__ . '/Fixtures/migrations');
    }

    /**
     * Return the bootstrapped application container as a non-null value,
     * narrowing the parent's nullable property for static analysis.
     *
     * @return \Illuminate\Foundation\Application
     */
    protected function container(): Application
    {
        Assert::assertNotNull($this->app);

        return $this->app;
    }

    /**
     * Return the value of the given env var if it is set and non-empty,
     * otherwise return the supplied default. Centralised so the connection
     * resolver does not repeat the `getenv` + falsy-check pattern at every key.
     *
     * @param  string  $key
     * @param  string  $default
     * @return string
     */
    private static function envOrDefault(string $key, string $default): string
    {
        $value = getenv($key);

        return $value === false || $value === '' ? $default : $value;
    }
}
