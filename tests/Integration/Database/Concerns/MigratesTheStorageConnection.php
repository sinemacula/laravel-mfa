<?php

declare(strict_types = 1);

namespace Tests\Integration\Database\Concerns;

/**
 * Creates the package's tables on a storage connection other than the default
 * one, for a test that configures one.
 *
 * The migrator records what it ran on the default connection, so on a database
 * that outlives a test (MySQL and PostgreSQL in CI) it would find the package's
 * migrations already run by an earlier test and create nothing on the storage
 * connection, and a rollback would drop the tables from wherever the setting
 * then pointed. The package's migrations are therefore run here directly,
 * against the storage connection each test configures, outside the migrator;
 * the migrator runs only the test identities' migrations on the default
 * connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait MigratesTheStorageConnection
{
    /**
     * Load only the test identities' migrations through the migrator.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../../../Fixtures/migrations');
    }

    /**
     * Run the package's migrations against the configured storage connection.
     *
     * @return void
     */
    protected function migrateTheStorageConnection(): void
    {
        $files = glob(__DIR__ . '/../../../../database/migrations/*.php') ?: [];

        sort($files);

        foreach ($files as $file) {
            $migration = require $file;

            assert(is_object($migration) && method_exists($migration, 'up'));

            $migration->up();
        }
    }
}
