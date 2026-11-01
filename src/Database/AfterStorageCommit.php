<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;

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
        $manager = $container->bound('db.transactions') ? $container->make('db.transactions') : null;

        if (!$manager instanceof DatabaseTransactionsManager) {
            return null;
        }

        $connection = StorageConnection::resolvedName();

        return $manager->callbackApplicableTransactions()->last(static fn (DatabaseTransactionRecord $transaction): bool => $transaction->connection === $connection);
    }
}
