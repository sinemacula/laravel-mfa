<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Config\Repository;
use Illuminate\Database\Connection;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Exceptions\MidRotationFailureException;
use Tests\Fixtures\Hardening\Concerns\FlowCatalogue;
use Tests\Integration\Database\Concerns\MigratesTheStorageConnection;
use Tests\TestCase;

/**
 * Nothing in any flow reads the package's state from a replica. The storage
 * connection's read PDO is a closure that throws, with the identities on
 * another connection, so an unrouted read anywhere ends the flow: there is no
 * enclosing transaction, sticky reads are off and no writer pin covers the
 * connection, which a control query shows by reaching the poison.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(WriteConnection::class)]
final class PoisonedReaderTest extends TestCase
{
    use FlowCatalogue, MigratesTheStorageConnection;

    /** @var string The SQLite file the package's tables are on. */
    private string $writer = '';

    /**
     * Create the package's tables and arrange the flows.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->migrateTheStorageConnection();
        $this->arrangeVerification();
        $this->resetFlows();
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

        if ($this->writer === '' || !is_file($this->writer)) {
            return;
        }

        unlink($this->writer);
    }

    /**
     * The flow reaches its branch without touching the poisoned reader.
     *
     * @param  string  $flow
     * @return void
     */
    #[DataProvider('flowNames')]
    public function testTheFlowReadsOnlyFromTheWriter(string $flow): void
    {
        $act = $this->flows()[$flow]();

        $this->poisonTheReader();

        try {
            self::assertTrue($act(), 'The flow must reach its branch.');
        } finally {
            $this->storage()->setReadPdo($this->storage()->getPdo());
        }
    }

    /**
     * The control: a plain read on the storage connection does reach the
     * poison, so the flows above show something.
     *
     * @return void
     */
    public function testAPlainReadReachesThePoison(): void
    {
        $this->poisonTheReader();

        self::assertSame(0, $this->storage()->transactionLevel());

        $this->expectExceptionMessage('A read reached the replica.');

        Factor::query()->count();
    }

    /**
     * Put the package's tables on a connection that splits its reads and
     * writes, with sticky reads off, and leave the identities on the default.
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

        $this->writer = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'mfa-poison-' . Str::lower((string) Str::ulid()) . '.sqlite';

        touch($this->writer);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(Repository::class);

        $config->set('app.debug', false);
        $config->set('logging.default', 'null');
        $config->set('database.connections.split', [
            'driver' => 'sqlite',
            'read'   => ['database' => $this->writer],
            'write'  => ['database' => $this->writer],
            'sticky' => false,
            'prefix' => '',
        ]);
        $config->set('mfa.storage.connection', 'split');
    }

    /**
     * Make every read that reaches the storage connection's read PDO throw.
     *
     * @return void
     */
    private function poisonTheReader(): void
    {
        $this->storage()->setReadPdo(self::refuseTheRead(...));
    }

    /**
     * What a read that reached the replica runs into.
     *
     * @return never
     *
     * @throws \Tests\Fixtures\Exceptions\MidRotationFailureException
     */
    private static function refuseTheRead(): never
    {
        throw new MidRotationFailureException('A read reached the replica.');
    }

    /**
     * The storage connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function storage(): Connection
    {
        $connection = DB::connection('split');

        self::assertInstanceOf(Connection::class, $connection);

        return $connection;
    }
}
