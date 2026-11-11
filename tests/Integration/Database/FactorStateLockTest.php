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
 * The factor state lock is taken on the storage connection; `observer` plays a
 * concurrent request on the same SQLite file that never waits for a lock.
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

    /** @var string Identity whose factor state is locked. */
    private const string IDENTITY_KEY = 'person-1';

    /** @var string SQLite file holding the package's tables. */
    private string $database = '';

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->migrateTheStorageConnection();
    }

    /**
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

        // The refused statement, kept alive by the trace, holds a read lock.
        unset($exception);

        DB::purge('observer');

        gc_collect_cycles();
    }
}
