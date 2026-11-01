<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Config\Repository;
use Illuminate\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Events\MfaFactorEnrolled;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\RecoveryCodes\BackupCodeDriver;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use Tests\Fixtures\Exceptions\MidRotationFailureException;
use Tests\Fixtures\Identities\TestUser;
use Tests\Integration\Database\Concerns\MigratesTheStorageConnection;
use Tests\TestCase;

/**
 * Backup-code rotation on a storage connection other than the default one.
 *
 * With `mfa.storage.connection` naming a `secondary` connection, the shipped
 * migrations create the package's tables there, the shipped factor model reads
 * and writes them there, and the rotation's transaction and the identity's lock
 * are taken there, so a failure partway through rolls back on the connection
 * the rows live on; a code is consumed there too. The identity itself stays on
 * the default connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecoveryCodeService::class)]
final class StorageConnectionRotationTest extends TestCase
{
    use MigratesTheStorageConnection;

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
     * The rotation writes the codes and the identity's state row on the storage
     * connection, and none of them reaches the default one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRotationWritesToTheStorageConnection(): void
    {
        $user = $this->loginUser();

        $codes = Mfa::issueBackupCodes();

        self::assertCount(10, $codes);
        self::assertSame('secondary', (new Factor)->getConnectionName());
        self::assertSame(10, $this->countBackupCodes((string) $user->id));
        self::assertSame(1, DB::connection('secondary')->table('mfa_identity_states')->count());

        self::assertSame(0, $this->countOnTheDefaultConnection('mfa_factors', (string) $user->id));
        self::assertSame(0, $this->countOnTheDefaultConnection('mfa_identity_states', (string) $user->id));
    }

    /**
     * A backup code issued on the storage connection is consumed there, once,
     * in the owner's factor state transaction.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testConsumptionRunsOnTheStorageConnection(): void
    {
        $user  = $this->loginUser();
        $codes = Mfa::issueBackupCodes();
        $hash  = (new BackupCodeDriver)->hash($codes[0]);

        /** @var \SineMacula\Laravel\Mfa\Models\Factor $factor */
        $factor = $user->factors()->get()->firstOrFail(static fn (Factor $candidate): bool => $candidate->getSecret() === $hash);

        self::assertSame('secondary', $factor->getConnectionName());
        self::assertTrue(Mfa::verify(BackupCodeDriver::NAME, $factor, $codes[0]));

        $factor->refresh();

        self::assertNull($factor->getSecret());
        self::assertFalse(Mfa::verify(BackupCodeDriver::NAME, $factor, $codes[0]));
        self::assertSame(0, DB::connection('secondary')->transactionLevel());
        self::assertSame(1, DB::connection('secondary')->table('mfa_identity_states')->count());
    }

    /**
     * A failure partway through the rotation rolls back every write on the
     * storage connection: the prior code survives and no partial batch remains.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRotationRollsBackOnTheStorageConnection(): void
    {
        $user = $this->loginUser();

        $prior = Factor::query()->create([
            'authenticatable_type' => $user->getMorphClass(),
            'authenticatable_id'   => (string) $user->id,
            'type'                 => BackupCodeDriver::NAME,
            'secret'               => 'prior-hash',
        ]);

        /** @var \Illuminate\Events\Dispatcher $events */
        $events = $this->container()->make(Dispatcher::class);

        $seen = 0;
        $events->listen(MfaFactorEnrolled::class, static function () use (&$seen): void {
            $seen++;

            if ($seen === 3) {
                throw new MidRotationFailureException('mid-rotation failure');
            }
        });

        try {
            Mfa::issueBackupCodes();
            self::fail('Expected the mid-rotation listener to throw.');
        } catch (MidRotationFailureException $exception) {
            self::assertSame('mid-rotation failure', $exception->getMessage());
        }

        $remaining = Factor::query()
            ->where('authenticatable_id', (string) $user->id)
            ->where('type', BackupCodeDriver::NAME)
            ->pluck('id')
            ->all();

        self::assertSame([$prior->getKey()], $remaining);
        self::assertSame(0, DB::connection('secondary')->transactionLevel());
    }

    /**
     * Put the package's tables on a secondary in-memory SQLite connection.
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

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(Repository::class);

        $config->set('database.connections.secondary', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);

        $config->set('mfa.storage.connection', 'secondary');
    }

    /**
     * Authenticate as a fresh MFA-enabled `TestUser`.
     *
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function loginUser(): TestUser
    {
        $user = TestUser::query()->create([
            'email'       => 'rotation@example.test',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        return $user;
    }

    /**
     * Count the user's rows in a package table on the default connection: none
     * when the table is not there, as on a database only this test uses; a
     * database other tests share may hold the table, but not these rows.
     *
     * @param  string  $table
     * @param  string  $identifier
     * @return int
     */
    private function countOnTheDefaultConnection(string $table, string $identifier): int
    {
        if (!Schema::connection('testing')->hasTable($table)) {
            return 0;
        }

        return DB::connection('testing')->table($table)
            ->where('authenticatable_type', (new TestUser)->getMorphClass())
            ->where('authenticatable_id', $identifier)
            ->count();
    }

    /**
     * Count the user's backup-code rows on the storage connection.
     *
     * @param  string  $identifier
     * @return int
     */
    private function countBackupCodes(string $identifier): int
    {
        return DB::connection('secondary')->table('mfa_factors')
            ->where('authenticatable_id', $identifier)
            ->where('type', BackupCodeDriver::NAME)
            ->count();
    }
}
