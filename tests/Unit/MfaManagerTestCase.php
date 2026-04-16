<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Config\Repository;
use Orchestra\Testbench\TestCase as BaseTestCase;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use Tests\Fixtures;

/**
 * Dedicated MfaManager test base class.
 *
 * Mirrors the `Tests\TestCase` bootstrap but declares its provider /
 * environment hooks with parameter signatures compatible with the
 * Orchestra TestBench base class under strict PHP 8.3 LSP checks, so
 * test files that depend on this base can load regardless of any
 * upstream signature drift on the shared Tests\TestCase.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
abstract class MfaManagerTestCase extends BaseTestCase
{
    /**
     * Register the package's service provider with the test
     * application.
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
     */
    protected function defineEnvironment(mixed $app): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(Repository::class);

        $config->set('app.key', 'base64:' . base64_encode(random_bytes(32)));

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
        $this->loadMigrationsFrom(__DIR__ . '/../../database/migrations');
        $this->loadMigrationsFrom(__DIR__ . '/../Fixtures/migrations');
    }

    /**
     * Return the bootstrapped application container as a non-null
     * value, narrowing the parent's nullable property for static
     * analysis.
     *
     * @return \Illuminate\Foundation\Application
     */
    protected function container(): \Illuminate\Foundation\Application
    {
        Assert::assertNotNull($this->app);

        return $this->app;
    }
}
