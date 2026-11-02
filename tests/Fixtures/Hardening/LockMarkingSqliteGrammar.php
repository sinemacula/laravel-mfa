<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Hardening;

use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\Grammars\SQLiteGrammar;

/**
 * SQLite takes no row locks, so its grammar leaves a locking read's clause out.
 * This one writes it as a comment, so the order of a flow's locking reads can
 * be read from its statements on SQLite as it can on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LockMarkingSqliteGrammar extends SQLiteGrammar
{
    /**
     * The locking clause, as a comment SQLite ignores.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  bool|string  $value
     * @return string
     */
    #[\Override]
    protected function compileLock(Builder $query, $value): string
    {
        return '/* for update */';
    }
}
