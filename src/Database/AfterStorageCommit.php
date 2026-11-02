<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Support\Facades\DB;

/**
 * Runs work that reports or follows a change to the package's tables once that
 * change has committed on the storage connection: at once when no transaction
 * is open there, when the open transaction commits otherwise, and never when it
 * rolls back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AfterStorageCommit
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Run the callback once the storage connection's open transaction, if any,
     * commits.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Closure(): mixed  $callback
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public static function run(Container $container, \Closure $callback): void
    {
        $pending = self::pendingTransaction($container);

        if ($pending === null) {

            $callback();

            return;
        }

        $pending->addCallback($callback);
    }

    /**
     * Forget the work a transaction left when its outermost commit failed, with
     * no transaction still open on the storage connection. Laravel 12 keeps
     * that work when a commit fails and runs it on the connection's next
     * commit, so what was waiting for a change that never committed would
     * happen anyway. With nothing open, nothing it forgets can still commit.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public static function forgetFailedCommit(Container $container): void
    {
        if (DB::connection(StorageConnection::name())->transactionLevel() !== 0) {
            return;
        }

        self::manager($container)?->rollback(StorageConnection::resolvedName(), 0);
    }

    /**
     * The innermost transaction open on the storage connection whose commit
     * runs callbacks, or `null` when there is none.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return ?\Illuminate\Database\DatabaseTransactionRecord
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private static function pendingTransaction(Container $container): ?DatabaseTransactionRecord
    {
        $connection = StorageConnection::resolvedName();

        return self::manager($container)
            ?->callbackApplicableTransactions()
            ->last(static fn (DatabaseTransactionRecord $transaction): bool => $transaction->connection === $connection);
    }

    /**
     * The transactions manager, read when it is needed since the testing traits
     * swap their own in, or `null` when there is none.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return ?\Illuminate\Database\DatabaseTransactionsManager
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function manager(Container $container): ?DatabaseTransactionsManager
    {
        $manager = $container->bound('db.transactions') ? $container->make('db.transactions') : null;

        return $manager instanceof DatabaseTransactionsManager ? $manager : null;
    }
}
