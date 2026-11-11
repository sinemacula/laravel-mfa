<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Support\Facades\DB;

/**
 * Runs work once the storage connection's open transaction commits, at once
 * when none is open, and never on rollback.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class AfterStorageCommit
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
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
     * Forget work left by a failed outermost commit, which Laravel 12 would
     * otherwise run on the connection's next commit.
     *
     * @internal
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
     * Read when needed, since the testing traits swap their own in.
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
