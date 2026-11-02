<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Container\Container;
use Illuminate\Support\Facades\DB;

/**
 * Every transaction the package opens on the storage connection, so that work
 * waiting for its commit (`AfterStorageCommit`) ends with it when the commit
 * fails, on every Laravel version the package supports, rather than running on
 * the connection's next commit.
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
        try {
            return DB::connection(StorageConnection::name())->transaction($callback);
        } catch (\Throwable $failure) {
            AfterStorageCommit::forgetFailedCommit(Container::getInstance());

            throw $failure;
        }
    }
}
