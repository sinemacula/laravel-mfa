<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Hardening;

use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\Grammars\SQLiteGrammar;

/**
 * Writes the locking clause SQLite omits as a comment, so the order of a flow's
 * locking reads shows in its statements.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LockMarkingSqliteGrammar extends SQLiteGrammar
{
    /**
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
