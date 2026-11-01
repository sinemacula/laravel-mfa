<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;
use Tests\Fixtures\Exceptions\MidRotationFailureException;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Integration\Database\Concerns\MigratesTheStorageConnection;
use Tests\TestCase;

/**
 * The factor state lock is taken on the storage connection and released when
 * its transaction rolls back.
 *
 * The package's tables live in a SQLite file reached through two connections:
 * `storage`, the configured storage connection, and `observer`, standing in for
 * a concurrent request with no wait for locks. While a factor state transaction
 * holds the identity's lock, the observer cannot take it (SQLite holds the
 * write lock of the whole file, MySQL and PostgreSQL the row's); once the
 * transaction rolls back, it can, and nothing the transaction wrote remains.
 * The default connection is never used for the lock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorStateTransaction::class)]
final class FactorStateLockTest extends TestCase
{
    use MigratesTheStorageConnection;

    /** @var string The key of the identity whose factor state is locked. */
    private const string IDENTITY_KEY = 'person-1';

    /** @var string The SQLite file the package's tables live in. */
    private string $database = '';

    /**
     * Create the package's tables on the storage connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->migrateTheStorageConnection();
    }

    /**
     * Remove the SQLite file once the application is gone.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();

        if ($this->database === '' || !is_file($this->database)) {
            return;
        }

        unlink($this->database);
    }

    /**
     * While the transaction runs, it holds the identity's lock on the storage
     * connection, and the default connection holds no transaction.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLockIsHeldOnTheStorageConnection(): void
    {
        $identity = new NonEloquentIdentity(self::IDENTITY_KEY);

        FactorStateTransaction::forIdentity($identity, new Factor, function (): void {

            self::assertSame(1, DB::connection('storage')->transactionLevel());
            self::assertSame(0, DB::connection()->transactionLevel());
            self::assertSame(1, DB::connection('storage')->table('mfa_identity_states')->count());

            $this->assertObserverIsLockedOut();
        });

        $this->lockAsObserver();

        self::assertSame(1, DB::connection('observer')->table('mfa_identity_states')->count());
    }

    /**
     * A rollback releases the lock and leaves nothing the transaction wrote.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARollbackReleasesTheLock(): void
    {
        $identity = new NonEloquentIdentity(self::IDENTITY_KEY);

        $thrown = null;

        try {
            FactorStateTransaction::forIdentity($identity, new Factor, function (): void {

                Factor::query()->create([
                    'authenticatable_type' => NonEloquentIdentity::class,
                    'authenticatable_id'   => self::IDENTITY_KEY,
                    'type'                 => 'totp',
                ]);

                $this->assertObserverIsLockedOut();

                throw new MidRotationFailureException('rolled back');
            });
        } catch (MidRotationFailureException $exception) {
            $thrown = $exception;
        }

        self::assertSame('rolled back', $thrown->getMessage());

        self::assertSame(0, DB::connection('storage')->transactionLevel());

        $this->lockAsObserver();

        self::assertSame(1, DB::connection('observer')->table('mfa_identity_states')->count());
        self::assertSame(0, DB::connection('observer')->table('mfa_factors')->count());
    }

    /**
     * Point the package's tables at a fresh SQLite file reached through two
     * connections, neither of which waits for a lock.
     *
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

        $this->database = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'mfa-lock-' . Str::lower((string) Str::ulid()) . '.sqlite';

        touch($this->database);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(Repository::class);

        foreach (['storage', 'observer'] as $name) {
            $config->set('database.connections.' . $name, [
                'driver'       => 'sqlite',
                'database'     => $this->database,
                'prefix'       => '',
                'busy_timeout' => 0,
            ]);
        }

        $config->set('mfa.storage.connection', 'storage');
    }

    /**
     * Take the test identity's lock as a concurrent request would, outside any
     * transaction of the observer's own.
     *
     * @return void
     */
    private function lockAsObserver(): void
    {
        $now = CarbonImmutable::now();

        DB::connection('observer')->table('mfa_identity_states')->upsert([[
            'id'                   => Str::lower((string) Str::ulid()),
            'authenticatable_type' => NonEloquentIdentity::class,
            'authenticatable_id'   => self::IDENTITY_KEY,
            'created_at'           => $now,
            'updated_at'           => $now,
        ]], ['authenticatable_type', 'authenticatable_id'], ['updated_at']);
    }

    /**
     * Assert the observer cannot take the test identity's lock while it is
     * held.
     *
     * @return void
     */
    private function assertObserverIsLockedOut(): void
    {
        try {
            $this->lockAsObserver();

            self::fail('The observer must not take the lock while the transaction holds it.');
        } catch (\Throwable $exception) {
            self::assertInstanceOf(QueryException::class, $exception);
            self::assertStringContainsString('database is locked', $exception->getMessage());
        }

        // The refused statement keeps the observer's read lock on the file
        // until it is finalised, and the exception's trace keeps it alive, so
        // both are let go before anything else touches the file.
        unset($exception);

        DB::purge('observer');

        gc_collect_cycles();
    }
}
