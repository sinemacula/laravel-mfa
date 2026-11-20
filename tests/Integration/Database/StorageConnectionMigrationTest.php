<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Config\Repository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\TableNames;
use Tests\Integration\Database\Concerns\MigratesTheStorageConnection;
use Tests\TestCase;

/**
 * The migrator runs on the default connection while the package's tables land
 * on the `secondary` storage connection, and rolling back drops them there.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StorageConnection::class)]
final class StorageConnectionMigrationTest extends TestCase
{
    use MigratesTheStorageConnection;

    /**
     * @return void
     */
    public function testMigrateAndRollbackFollowTheStorageConnection(): void
    {
        $tables  = array_values(TableNames::DEFAULTS);
        $options = ['--path' => realpath(__DIR__ . '/../../../database/migrations'), '--realpath' => true];

        self::assertSame(0, Artisan::call('migrate', $options));

        try {
            foreach ($tables as $table) {
                self::assertTrue(Schema::connection('secondary')->hasTable($table), $table);
                self::assertFalse(Schema::connection('testing')->hasTable($table), $table);
            }

            self::assertFalse(Schema::connection('secondary')->hasTable('migrations'));
            self::assertSame(7, DB::connection('testing')->table('migrations')->where('migration', 'like', '%_create_mfa_%')->count());
        } finally {
            self::assertSame(0, Artisan::call('migrate:rollback', $options));
        }

        foreach ($tables as $table) {
            self::assertFalse(Schema::connection('secondary')->hasTable($table), $table);
        }

        self::assertSame(0, DB::connection('testing')->table('migrations')->where('migration', 'like', '%_create_mfa_%')->count());
    }

    /**
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(Repository::class);

        $config->set('database.connections.secondary', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);

        $config->set('mfa.storage.connection', 'secondary');
    }
}
