<?php

declare(strict_types = 1);

namespace Tests;

use Illuminate\Config\Repository;
use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase as BaseTestCase;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\MfaServiceProvider;

/**
 * Boots Testbench with the package provider, the `DB_CONNECTION` database
 * (in-memory SQLite when unset) and the migrations applied.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class TestCase extends BaseTestCase
{
    /** @var array<string, true> Worker databases this process has created. */
    private static array $workerDatabases = [];

    /** @var array<string, mixed> The settings the migrations ran against. */
    private array $migratedSettings = [];

    /**
     * Notes the storage connection and table names the package's tables were
     * created with.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $config = $this->app?->make(Repository::class);

        foreach ($this->migrationSettings() as $setting) {
            $this->migratedSettings[$setting] = $config?->get($setting);
        }
    }

    /**
     * Restores the table settings first so the rollback drops what the
     * migrations created, then collects cycles so the PDO closes before
     * parallel runs exhaust connections.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->app?->make(Repository::class)->set($this->migratedSettings);

        /** @var ?\Illuminate\Database\DatabaseManager $database */
        $database = $this->app?->make('db');

        parent::tearDown();

        foreach ($database?->getConnections() ?? [] as $connection) {
            $connection->disconnect();
        }

        gc_collect_cycles();
    }

    /**
     * @param  mixed  $app
     * @return list<class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return [
            MfaServiceProvider::class,
        ];
    }

    /**
     * @param  mixed  $app
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = app(Repository::class);

        $config->set('app.key', 'base64:' . base64_encode(random_bytes(32)));

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', $this->databaseConnection());

        $config->set('auth.defaults.guard', 'web');
        $config->set('auth.guards.web', [
            'driver'   => 'session',
            'provider' => 'users',
        ]);
        $config->set('auth.providers.users', [
            'driver' => 'eloquent',
            'model'  => Fixtures\Identities\TestUser::class,
        ]);
    }

    /**
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
        $this->loadMigrationsFrom(__DIR__ . '/Fixtures/migrations');
    }

    /**
     * Narrows the parent's nullable property for static analysis.
     *
     * @return \Illuminate\Foundation\Application
     */
    protected function container(): Application
    {
        Assert::assertNotNull($this->app);

        return $this->app;
    }

    /**
     * The storage connection and every table's name, as the migrations read
     * them.
     *
     * @return list<string>
     */
    private function migrationSettings(): array
    {
        return [
            'mfa.storage.connection',
            ...array_map(TableNames::setting(...), array_keys(TableNames::DEFAULTS)),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function databaseConnection(): array
    {
        $driver = getenv('DB_CONNECTION') ?: 'sqlite';

        if ($driver === 'sqlite') {
            return [
                'driver'   => 'sqlite',
                'database' => ':memory:',
                'prefix'   => '',
            ];
        }

        $connection = [
            'driver'    => $driver,
            'host'      => getenv('DB_HOST') ?: '127.0.0.1',
            'port'      => getenv('DB_PORT') ?: $this->defaultPort($driver),
            'database'  => getenv('DB_DATABASE') ?: 'laravel_mfa_test',
            'username'  => getenv('DB_USERNAME') ?: $this->defaultUsername($driver),
            'password'  => getenv('DB_PASSWORD') ?: '',
            'prefix'    => '',
            'charset'   => $driver === 'pgsql' ? 'utf8' : 'utf8mb4',
            'collation' => $driver === 'pgsql' ? null : 'utf8mb4_unicode_ci',
        ];

        $connection['database'] = $this->workerDatabase($connection);

        return $connection;
    }

    /**
     * One per paratest worker (`TEST_TOKEN`, `0` outside paratest), created
     * afresh on first use so workers and earlier runs never collide.
     *
     * @param  array{driver: string, host: string, port: string, database: string, username: string, password: string}  $connection
     * @return string
     */
    private function workerDatabase(array $connection): string
    {
        $token    = getenv('TEST_TOKEN');
        $database = $connection['database'] . '_' . ($token === false || $token === '' ? '0' : $token);

        if (isset(self::$workerDatabases[$database])) {
            return $database;
        }

        $dsn = sprintf('%s:host=%s;port=%s;dbname=%s', $connection['driver'], $connection['host'], $connection['port'], $connection['database']);
        $pdo = new \PDO($dsn, $connection['username'], $connection['password']);

        $quoted = $connection['driver'] === 'pgsql' ? '"' . $database . '"' : '`' . $database . '`';

        $pdo->exec('DROP DATABASE IF EXISTS ' . $quoted . ($connection['driver'] === 'pgsql' ? ' WITH (FORCE)' : ''));
        $pdo->exec('CREATE DATABASE ' . $quoted);

        self::$workerDatabases[$database] = true;

        return $database;
    }

    /**
     * @param  string  $driver
     * @return string
     */
    private function defaultPort(string $driver): string
    {
        return $driver === 'pgsql' ? '5432' : '3306';
    }

    /**
     * @param  string  $driver
     * @return string
     */
    private function defaultUsername(string $driver): string
    {
        return $driver === 'pgsql' ? 'postgres' : 'root';
    }
}
