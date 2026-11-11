<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Support\Facades\DB;

/**
 * Refuses work outside a transaction on the storage connection, where a lock
 * would be released at once.
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
