<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Database;

use Illuminate\Database\DatabaseTransactionsManager;

/**
 * Never hears of a failed commit, as on Laravel 12, so the pending work running
 * on the next commit can be tested on every version.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TransactionsManagerUnawareOfFailedCommits extends DatabaseTransactionsManager
{
    /**
     * Ignores the rollback the connection reports for a failed commit.
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
