<?php

declare(strict_types = 1);

namespace Tests\Integration\Database\Concerns;

/**
 * Runs the package's migrations directly on the storage connection, as the
 * migrator's record on the default connection outlives a test on a server.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait MigratesTheStorageConnection
{
    /**
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../../../Fixtures/migrations');
    }

    /**
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
