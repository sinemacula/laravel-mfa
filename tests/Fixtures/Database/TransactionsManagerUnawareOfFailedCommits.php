<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Database;

use Illuminate\Database\DatabaseTransactionsManager;

/**
 * A transactions manager a failed commit is never reported to, as Laravel 12's
 * is, so that what follows from that can be tested on every supported version:
 * the work of the transaction stays pending, and runs on the next commit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TransactionsManagerUnawareOfFailedCommits extends DatabaseTransactionsManager
{
    /**
     * Roll back, unless it is the connection reporting a failed commit.
     *
     * @param  string  $connection
     * @param  int  $newTransactionLevel
     * @return void
     */
    #[\Override]
    public function rollback(mixed $connection, mixed $newTransactionLevel): void
    {
        if (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 2)[1]['function'] === 'handleCommitTransactionException') {
            return;
        }

        parent::rollback($connection, $newTransactionLevel);
    }
}
