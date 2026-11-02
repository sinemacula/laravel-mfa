<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Database\Query\Builder;

/**
 * Deletes what a query finds in limited statements, so pruning a large table
 * neither holds locks for long nor builds one enormous transaction. Each
 * statement carries the query's own conditions, so a row that stopped matching
 * in the meantime stays. It runs on the query builder, so no model event fires.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BoundedDelete
{
    /** @var int The most rows one statement deletes. */
    public const int LIMIT = 1000;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Delete what the query finds, and return how many rows went.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @return int
     *
     * @imperative
     */
    public static function run(Builder $query): int
    {
        $total = 0;

        $query->limit(self::LIMIT);

        do {
            $deleted = $query->delete();
            $total += $deleted;
        } while ($deleted === self::LIMIT);

        return $total;
    }
}
