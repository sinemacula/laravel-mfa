<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Container\Container;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Mfa\Secrets\QueryExceptionMask;

/**
 * Every transaction the package opens on the storage connection, so that work
 * waiting for its commit (`AfterStorageCommit`) ends with it when the commit
 * fails, on every Laravel version the package supports, rather than running on
 * the connection's next commit, and so that a failed query leaves it with
 * nothing it was given (see `Secrets\QueryExceptionMask`). A transaction runs
 * once: a deadlock is a server error for the caller to retry, since running it
 * again here would run a driver again and could deliver a second code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StorageTransaction
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Run the callback in a transaction on the storage connection.
     *
     * @template TReturn
     *
     * @param  \Closure(): TReturn  $callback
     * @return TReturn
     *
     * @throws \Throwable
     */
    public static function run(\Closure $callback): mixed
    {
        $connection = DB::connection(StorageConnection::name());
        $outermost  = $connection->transactionLevel() === 0;

        try {
            return $connection->transaction($callback);
        } catch (\Throwable $failure) {
            AfterStorageCommit::forgetFailedCommit(Container::getInstance());

            if ($outermost) {
                self::endOrphanedTransaction($connection);
            }

            QueryExceptionMask::maskChain($failure);

            throw $failure;
        }
    }

    /**
     * End the transaction a failed commit left open on the PDO. Laravel has
     * already counted it as closed, so on a connection a long-running process
     * reuses, the next request would otherwise read what never committed and
     * fail to begin a transaction of its own. Only the transaction this class
     * opened is ever ended, never one the application holds, and whatever goes
     * wrong here gives way to the failure the caller is about to receive: a
     * connection that cannot be rolled back is dropped, to be opened afresh.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return void
     */
    private static function endOrphanedTransaction(Connection $connection): void
    {
        try {
            $pdo = $connection->getPdo();

            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
        } catch (\Throwable) {
            $connection->disconnect();
        }
    }
}
