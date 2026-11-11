<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Container\Container;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Mfa\Secrets\QueryExceptionMask;

/**
 * Every transaction the package opens. On failure it drops after-commit work
 * and masks query values. It never retries a deadlock, which could deliver a
 * second code.
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
     * End the transaction a failed commit left open on the PDO, which Laravel
     * counts as closed, so a long-running process does not reuse it.
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
