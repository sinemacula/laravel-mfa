<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Illuminate\Database\Connection;
use Illuminate\Database\Events\TransactionCommitting;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Database\AfterStorageCommit;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\StorageTransaction;
use Tests\Fixtures\Database\TransactionsManagerUnawareOfFailedCommits;
use Tests\Fixtures\Exceptions\CommitFailedException;
use Tests\TestCase;

/**
 * Laravel 12's transactions manager keeps a failed commit's callbacks unless
 * told to forget them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StorageTransaction::class)]
#[CoversClass(AfterStorageCommit::class)]
final class StorageTransactionTest extends TestCase
{
    /** @var int How many times the work has run. */
    private int $runs = 0;

    /**
     * Use the manager a failed commit is not reported to.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $manager = new TransactionsManagerUnawareOfFailedCommits;

        $this->container()->instance('db.transactions', $manager);
        $this->connection()->setTransactionManager($manager);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testRunsTheCallbackInATransactionAndReturnsWhatItReturns(): void
    {
        $returned = StorageTransaction::run(function (): int {

            AfterStorageCommit::run($this->container(), $this->work(...));

            self::assertSame(0, $this->runs);

            return $this->connection()->transactionLevel();
        });

        self::assertSame(1, $returned);
        self::assertSame(1, $this->runs);
        self::assertSame(0, $this->connection()->transactionLevel());
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testOpensTheTransactionOnTheStorageConnection(): void
    {
        $this->useAnotherStorageConnection();

        $levels = StorageTransaction::run(fn (): array => [DB::connection('other')->transactionLevel(), $this->connection()->transactionLevel()]);

        self::assertSame([1, 0], $levels);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheWorkOfAFailedCommitNeverRunsOnTheNextCommit(): void
    {
        $this->failTheNextCommit();

        $this->assertTheCommitFails();

        $this->connection()->transaction(static fn (): null => null);

        self::assertSame(0, $this->runs);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testWorkAfterAFailedCommitRunsAtOnce(): void
    {
        $this->failTheNextCommit();

        $this->assertTheCommitFails();

        AfterStorageCommit::run($this->container(), $this->work(...));

        self::assertSame(1, $this->runs);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureInTheCallbackReachesTheCaller(): void
    {
        $thrown = new CommitFailedException('The callback failed.');
        $caught = null;

        try {
            StorageTransaction::run(static function () use ($thrown): void {
                throw $thrown;
            });
        } catch (CommitFailedException $failure) {
            $caught = $failure;
        }

        self::assertSame($thrown, $caught);
        self::assertSame(0, $this->connection()->transactionLevel());
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithNoManagerWorkRunsAtOnceAndAFailureReachesTheCaller(): void
    {
        $this->container()->instance('db.transactions', new \stdClass);

        AfterStorageCommit::run($this->container(), $this->work(...));

        self::assertSame(1, $this->runs);

        $this->expectException(CommitFailedException::class);

        StorageTransaction::run(static function (): void {
            throw new CommitFailedException('The callback failed.');
        });
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureInsideAnOuterTransactionLeavesItsWorkWaiting(): void
    {
        $connection = $this->connection();

        $connection->beginTransaction();

        AfterStorageCommit::run($this->container(), $this->work(...));

        try {
            StorageTransaction::run(static function (): void {
                throw new CommitFailedException('The savepoint failed.');
            });
        } catch (CommitFailedException) {
            self::assertSame(1, $connection->transactionLevel());
            self::assertTrue($connection->getPdo()->inTransaction());
        }

        $connection->commit();

        self::assertSame(1, $this->runs);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedCommitLeavesTheConnectionUsable(): void
    {
        $connection = $this->connection();

        $connection->statement('create table storage_transaction_rows (id integer)');

        $this->failTheNextCommit();

        try {
            StorageTransaction::run(static function () use ($connection): void {
                $connection->table('storage_transaction_rows')->insert(['id' => 1]);
            });
        } catch (CommitFailedException) {
            self::assertSame(0, $connection->table('storage_transaction_rows')->count());
        }

        StorageTransaction::run(static function () use ($connection): void {
            $connection->table('storage_transaction_rows')->insert(['id' => 2]);
        });

        self::assertSame(2, $connection->table('storage_transaction_rows')->value('id'));
        self::assertFalse($connection->getPdo()->inTransaction());

        $connection->statement('drop table storage_transaction_rows');
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedRollBackDropsTheConnectionAndKeepsTheFailure(): void
    {
        $connection = $this->connection();
        $original   = $connection->getPdo();
        $pdo        = \Mockery::mock(\PDO::class);

        $pdo->shouldReceive('beginTransaction')->andReturnTrue();
        $pdo->shouldReceive('exec')->andReturn(0);
        $pdo->shouldReceive('inTransaction')->andReturnTrue();
        $pdo->shouldReceive('rollBack')->once()->andThrow(new \PDOException('The connection has gone.'));

        $connection->setPdo($pdo);

        $this->failTheNextCommit();

        try {
            StorageTransaction::run(static fn (): null => null);

            self::fail('The commit failure must reach the caller.');
        } catch (CommitFailedException) {
            self::assertNull($connection->getRawPdo());
        } finally {
            $connection->setPdo($original);
        }
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureForgetsNothingOfAnotherConnection(): void
    {
        $this->useAnotherStorageConnection();

        $connection = $this->connection();

        $connection->beginTransaction();
        $connection->afterCommit($this->work(...));

        $this->failTheNextCommit();

        $this->assertTheCommitFails();

        $connection->commit();

        self::assertSame(1, $this->runs);
    }

    /**
     * The failure reaches the caller and no transaction is left open on the
     * PDO.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function assertTheCommitFails(): void
    {
        try {
            StorageTransaction::run(function (): void {
                AfterStorageCommit::run($this->container(), $this->work(...));
            });
        } catch (CommitFailedException) {
            self::assertFalse(DB::connection(StorageConnection::name())->getPdo()->inTransaction());

            return;
        }

        self::fail('The commit failure must reach the caller.');
    }

    /**
     * Laravel's `transaction()` commits on the PDO directly, so the listener
     * throws just before.
     *
     * @return void
     */
    private function failTheNextCommit(): void
    {
        $fail = true;

        Event::listen(TransactionCommitting::class, static function () use (&$fail): void {

            if ($fail) {

                $fail = false;

                throw new CommitFailedException('The database refused the commit.');
            }
        });
    }

    /**
     * @return void
     */
    private function useAnotherStorageConnection(): void
    {
        config()->set('database.connections.other', config('database.connections.testing'));
        config()->set('mfa.storage.connection', 'other');
    }

    /**
     * The default connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function connection(): Connection
    {
        $connection = DB::connection();

        self::assertInstanceOf(Connection::class, $connection);

        return $connection;
    }

    /**
     * @return void
     */
    private function work(): void
    {
        $this->runs++;
    }
}
