<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Support\Facades\DB;

/**
 * Refuses work that must run inside a caller's transaction on the storage
 * connection when none is open: a lock taken outside one is released at once,
 * so the change it guards could be overrun.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class OpenTransaction
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Throw a `LogicException` with the message when no transaction is open on
     * the storage connection.
     *
     * @param  string  $message
     * @return void
     *
     * @throws \LogicException
     */
    public static function assertOpen(string $message): void
    {
        if (DB::connection(StorageConnection::name())->transactionLevel() === 0) {
            throw new \LogicException($message);
        }
    }
}
